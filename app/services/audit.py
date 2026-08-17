import json
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from app.database import get_db_context
from app.models import AuditLog, User
from app.config import settings


GENESIS_HASH = settings.GENESIS_HASH


def canonicalize_audit_record(
    user_id: Optional[int],
    action: str,
    entity_type: Optional[str],
    entity_id: Optional[int],
    details: Optional[str],
    timestamp: datetime,
    previous_hash: str
) -> str:
    record = {
        "user_id": user_id,
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "details": details,
        "timestamp": timestamp.isoformat(),
        "previous_hash": previous_hash,
    }
    return json.dumps(record, separators=(",", ":"), sort_keys=True)


def compute_hash(canonical_data: str) -> str:
    return hashlib.sha256(canonical_data.encode()).hexdigest()


def get_latest_audit_hash(db) -> str:
    latest = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    if latest:
        return latest.current_hash
    return GENESIS_HASH


def record_audit(
    user_id: Optional[int],
    action: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
    db: Optional[Any] = None
) -> AuditLog:
    timestamp = datetime.now(timezone.utc).replace(tzinfo=None)

    details_json = json.dumps(details, separators=(",", ":"), sort_keys=True) if details else None

    if db is None:
        with get_db_context() as _db:
            return _insert_audit(_db, user_id, action, entity_type, entity_id, details_json, timestamp)

    return _insert_audit(db, user_id, action, entity_type, entity_id, details_json, timestamp)


def _insert_audit(db, user_id, action, entity_type, entity_id, details_json, timestamp) -> AuditLog:
    previous_hash = get_latest_audit_hash(db)

    canonical = canonicalize_audit_record(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details_json,
        timestamp=timestamp,
        previous_hash=previous_hash
    )
    current_hash = compute_hash(canonical)

    audit = AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details_json,
        timestamp=timestamp,
        previous_hash=previous_hash,
        current_hash=current_hash,
    )
    db.add(audit)
    db.flush()
    return audit


def verify_audit_chain() -> dict:
    with get_db_context() as db:
        audits = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
        
        if not audits:
            return {
                "valid": True,
                "total_records": 0,
                "first_corruption_index": None,
                "message": "Audit chain is empty (valid)"
            }
        
        previous_hash = GENESIS_HASH
        
        for i, audit in enumerate(audits):
            canonical = canonicalize_audit_record(
                user_id=audit.user_id,
                action=audit.action,
                entity_type=audit.entity_type,
                entity_id=audit.entity_id,
                details=audit.details,
                timestamp=audit.timestamp,
                previous_hash=previous_hash
            )
            computed_hash = compute_hash(canonical)
            
            if audit.previous_hash != previous_hash:
                return {
                    "valid": False,
                    "total_records": len(audits),
                    "first_corruption_index": i,
                    "message": f"Broken chain at record {audit.id}: previous_hash mismatch"
                }
            
            if audit.current_hash != computed_hash:
                return {
                    "valid": False,
                    "total_records": len(audits),
                    "first_corruption_index": i,
                    "message": f"Tampering detected at record {audit.id}: current_hash mismatch"
                }
            
            previous_hash = audit.current_hash
        
        return {
            "valid": True,
            "total_records": len(audits),
            "first_corruption_index": None,
            "message": "Audit chain is valid"
        }


def get_audit_logs(
    skip: int = 0,
    limit: int = 100,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None,
    log_id: Optional[int] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
):
    with get_db_context() as db:
        query = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
        
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if username:
            user_ids = db.query(User.id).filter(User.username.ilike(f"%{username}%"))
            query = query.filter(AuditLog.user_id.in_(user_ids))
        if action:
            query = query.filter(AuditLog.action.ilike(f"%{action}%"))
        if entity_type:
            query = query.filter(AuditLog.entity_type.ilike(f"%{entity_type}%"))
        if entity_id:
            query = query.filter(AuditLog.entity_id == entity_id)
        if log_id:
            query = query.filter(AuditLog.id == log_id)
        if start_time:
            query = query.filter(AuditLog.timestamp >= start_time)
        if end_time:
            query = query.filter(AuditLog.timestamp < end_time + timedelta(days=1))
        
        total = query.count()
        logs = query.offset(skip).limit(limit).all()
        
        return logs, total
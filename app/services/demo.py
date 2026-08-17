import hashlib
from fastapi import HTTPException, status
from app.config import settings
from app.database import get_db_context
from app.models import User, Case, Evidence, AuditLog, DemoState, UserDevice
from app.services.audit import record_audit
from app.services.evidence import generate_storage_filename, compute_sha256_bytes
from app.storage import storage

TAMPER_SUFFIX = b"\n[EVIDENTIA-DEMO-TAMPER]"


def _require_demo_mode():
    if not settings.DEMO_MODE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Demo mode is disabled")


def tamper_evidence(evidence_id: int, user_id: int) -> Evidence:
    _require_demo_mode()
    backup_key = f"evidence_orig:{evidence_id}"
    with get_db_context() as db:
        evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
        if not evidence:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
        if db.query(DemoState).filter(DemoState.key == backup_key).first():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Evidence is already tampered. Restore it first.")

        original = storage.get(evidence.stored_filename)
        db.add(DemoState(key=backup_key, value_blob=original))
        record_audit(
            user_id=user_id,
            action="DEMO_EVIDENCE_TAMPERED",
            entity_type="Evidence",
            entity_id=evidence.id,
            details={"filename": evidence.filename, "original_size": len(original)},
            db=db,
        )
        db.commit()

    storage.put(evidence.stored_filename, original + TAMPER_SUFFIX)
    return evidence


def restore_evidence(evidence_id: int, user_id: int) -> Evidence:
    _require_demo_mode()
    backup_key = f"evidence_orig:{evidence_id}"
    with get_db_context() as db:
        evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
        if not evidence:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
        backup = db.query(DemoState).filter(DemoState.key == backup_key).first()
        if not backup or backup.value_blob is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Evidence is not tampered. Simulate tampering first.")

        original = bytes(backup.value_blob)
        db.delete(backup)
        record_audit(
            user_id=user_id,
            action="DEMO_EVIDENCE_RESTORED",
            entity_type="Evidence",
            entity_id=evidence.id,
            details={"filename": evidence.filename, "restored_size": len(original)},
            db=db,
        )
        db.commit()

    storage.put(evidence.stored_filename, original)
    return evidence


def tamper_audit_chain(user_id: int) -> AuditLog:
    _require_demo_mode()
    with get_db_context() as db:
        oldest = db.query(AuditLog).order_by(AuditLog.id.asc()).first()
        if not oldest:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No audit records to tamper")
        backup_key = f"audit_orig:{oldest.id}"
        if db.query(DemoState).filter(DemoState.key == backup_key).first():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Audit chain is already tampered. Restore it first.")

        db.add(DemoState(key=backup_key, value=oldest.details))
        oldest.details = '{"tampered": true, "note": "EVIDENTIA DEMO - simulated manual database edit"}'
        record_audit(
            user_id=user_id,
            action="DEMO_AUDIT_TAMPERED",
            entity_type="AuditLog",
            entity_id=oldest.id,
            details={"record_id": oldest.id},
            db=db,
        )
        db.commit()
        return oldest


def restore_audit_chain(user_id: int) -> AuditLog:
    _require_demo_mode()
    with get_db_context() as db:
        backup = db.query(DemoState).filter(DemoState.key.like("audit_orig:%")).first()
        if not backup:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Audit chain is not tampered. Simulate tampering first.")

        record_id = int(backup.key.split(":", 1)[1])
        record = db.query(AuditLog).filter(AuditLog.id == record_id).first()
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tampered audit record no longer exists")
        record.details = backup.value
        db.delete(backup)
        record_audit(
            user_id=user_id,
            action="DEMO_AUDIT_RESTORED",
            entity_type="AuditLog",
            entity_id=record.id,
            details={"record_id": record.id},
            db=db,
        )
        db.commit()
        return record


def unlock_user(target_user_id: int, actor_id: int) -> User:
    _require_demo_mode()
    with get_db_context() as db:
        user = db.query(User).filter(User.id == target_user_id).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        user.failed_attempts = 0
        user.locked_until = None
        record_audit(
            user_id=actor_id,
            action="DEMO_USER_UNLOCKED",
            entity_type="User",
            entity_id=user.id,
            details={"username": user.username},
            db=db,
        )
        db.commit()
        return user


def reset_demo_data(actor_id: int) -> dict:
    _require_demo_mode()
    content = (
        b"INTERVIEW TRANSCRIPT (DEMO DATA)\n"
        b"Case: Theft at Warehouse 7\n"
        b"Officer: demo_officer\n"
        b"\n"
        b"Q: What did you observe at 21:40?\n"
        b"A: The suspect removed three boxes from the loading dock.\n"
        b"\n"
        b"-- end of transcript --\n"
    )
    sha256_hash = compute_sha256_bytes(content)
    key = generate_storage_filename("demo_transcript.txt")

    with get_db_context() as db:
        for evidence in db.query(Evidence).all():
            storage.delete(evidence.stored_filename)

        db.query(Evidence).delete()
        db.query(Case).delete()
        db.query(UserDevice).delete()
        db.query(AuditLog).delete()
        db.query(DemoState).delete()
        db.query(User).filter(User.id != actor_id).delete()

        storage.put(key, content)

        actor = db.query(User).filter(User.id == actor_id).first()
        if not actor:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Actor not found")

        record_audit(actor.id, "AUTH_LOGIN_SUCCESS", "User", actor.id, {"username": actor.username}, db=db)

        case = Case(
            case_number=f"CASE-{actor.id:04d}-0001",
            title="Demo Case: Theft at Warehouse 7",
            description="Seeded automatically by Evidentia Demo Mode.",
            created_by=actor.id,
        )
        db.add(case)
        db.flush()
        record_audit(
            actor.id, "CASE_CREATED", "Case", case.id,
            {"case_number": case.case_number, "title": case.title}, db=db,
        )

        evidence = Evidence(
            case_id=case.id,
            filename="demo_transcript.txt",
            stored_filename=key,
            file_path=key,
            sha256_hash=sha256_hash,
            file_size=len(content),
            mime_type="text/plain",
            uploaded_by=actor.id,
        )
        db.add(evidence)
        db.flush()
        record_audit(
            actor.id, "EVIDENCE_UPLOADED", "Evidence", evidence.id,
            {"case_id": case.id, "filename": evidence.filename, "sha256_hash": sha256_hash, "file_size": len(content)}, db=db,
        )
        record_audit(
            actor.id, "EVIDENCE_INTEGRITY_VERIFIED", "Evidence", evidence.id,
            {"match": True, "original_hash": sha256_hash, "computed_hash": sha256_hash}, db=db,
        )

        record_audit(
            actor_id, "DEMO_DATA_RESET", None, None,
            {"username": actor.username, "case_id": case.id, "evidence_id": evidence.id}, db=db,
        )
        db.commit()

    return {
        "username": actor.username,
        "case_id": case.id,
        "evidence_id": evidence.id,
        "sha256_hash": sha256_hash,
    }
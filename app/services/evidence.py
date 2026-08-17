import hashlib
import uuid
from pathlib import Path
from typing import Optional, Tuple
from app.config import settings
from app.database import get_db_context
from app.models import Evidence, Case
from app.storage import storage
from app.services.audit import record_audit
from fastapi import UploadFile, HTTPException, status


def compute_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_file(file: UploadFile) -> Tuple[bool, str]:
    content_type = file.content_type or "application/octet-stream"
    if content_type not in settings.ALLOWED_MIME_TYPES:
        return False, f"File type {content_type} not allowed"
    return True, ""


def generate_storage_filename(original_filename: str) -> str:
    ext = Path(original_filename).suffix.lower()
    if ext not in [".pdf", ".jpg", ".jpeg", ".png", ".gif", ".txt", ".doc", ".docx"]:
        ext = ".bin"
    return f"{uuid.uuid4().hex}{ext}"


def create_evidence_record(
    db,
    case_id: int,
    filename: str,
    stored_filename: str,
    sha256_hash: str,
    file_size: int,
    mime_type: str,
    uploaded_by: int
) -> Evidence:
    evidence = Evidence(
        case_id=case_id,
        filename=filename,
        stored_filename=stored_filename,
        file_path=stored_filename,
        sha256_hash=sha256_hash,
        file_size=file_size,
        mime_type=mime_type,
        uploaded_by=uploaded_by,
    )
    db.add(evidence)
    db.flush()
    return evidence


async def upload_evidence(
    case_id: int,
    file: UploadFile,
    user_id: int
) -> Evidence:
    valid, error = validate_file(file)
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    with get_db_context() as db:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    stored_filename = generate_storage_filename(file.filename)
    data = await file.read()
    file_size = len(data)

    if file_size > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds {settings.MAX_FILE_SIZE_MB}MB limit"
        )

    sha256_hash = compute_sha256_bytes(data)
    storage.put(stored_filename, data)

    with get_db_context() as db:
        evidence = create_evidence_record(
            db=db,
            case_id=case_id,
            filename=file.filename,
            stored_filename=stored_filename,
            sha256_hash=sha256_hash,
            file_size=file_size,
            mime_type=file.content_type or "application/octet-stream",
            uploaded_by=user_id,
        )

        record_audit(
            user_id=user_id,
            action="EVIDENCE_UPLOADED",
            entity_type="Evidence",
            entity_id=evidence.id,
            details={
                "case_id": case_id,
                "filename": file.filename,
                "sha256_hash": sha256_hash,
                "file_size": file_size,
            },
            db=db
        )

        db.commit()
        db.refresh(evidence)
        return evidence


def verify_evidence_integrity(evidence_id: int) -> dict:
    with get_db_context() as db:
        evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
        if not evidence:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

        key = evidence.stored_filename
        if not storage.exists(key):
            return {
                "evidence_id": evidence_id,
                "match": False,
                "original_hash": evidence.sha256_hash,
                "computed_hash": "",
                "message": "Evidence file not found in storage"
            }

        computed_hash = storage.hash_sha256(key)
        match = computed_hash == evidence.sha256_hash

        return {
            "evidence_id": evidence_id,
            "match": match,
            "original_hash": evidence.sha256_hash,
            "computed_hash": computed_hash,
            "message": "Integrity Verified" if match else "Integrity Compromised"
        }


def get_evidence_for_download(evidence_id: int, user_id: int, user_role: str) -> Evidence:
    with get_db_context() as db:
        evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
        if not evidence:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

        if user_role != "admin":
            case = db.query(Case).filter(Case.id == evidence.case_id).first()
            if not case or case.created_by != user_id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this evidence")

        if not storage.exists(evidence.stored_filename):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence file not found in storage")

        return evidence


def get_evidence_download_url(evidence: Evidence, expires_seconds: int = 300) -> Optional[str]:
    return storage.presigned_get_url(evidence.stored_filename, expires_seconds)


def delete_evidence(evidence_id: int, user_id: int, user_role: str) -> bool:
    with get_db_context() as db:
        evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
        if not evidence:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

        if user_role != "admin":
            case = db.query(Case).filter(Case.id == evidence.case_id).first()
            if not case or case.created_by != user_id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete this evidence")

        key = evidence.stored_filename
        storage.delete(key)

        record_audit(
            user_id=user_id,
            action="EVIDENCE_DELETED",
            entity_type="Evidence",
            entity_id=evidence.id,
            details={
                "filename": evidence.filename,
                "sha256_hash": evidence.sha256_hash,
            },
            db=db
        )

        db.delete(evidence)
        db.commit()
        return True
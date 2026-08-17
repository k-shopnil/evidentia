import hashlib
import secrets
from datetime import timedelta

from sqlalchemy.orm import Session

from app.security.password import hash_password
from app.database import get_db_context
from app.models import User, PasswordResetToken
from app.services.audit import record_audit
from app.services.email import send_password_reset_email
from app.security.auth import utcnow

TOKEN_TTL_MINUTES = 60


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def request_password_reset(email: str, base_url: str) -> bool:
    now = utcnow()
    with get_db_context() as db:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            record_audit(
                user_id=None,
                action="PASSWORD_RESET_REQUESTED",
                details={"email": email, "exists": False},
                db=db,
            )
            return False

        raw_token = secrets.token_urlsafe(32)
        db.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=_hash_token(raw_token),
                expires_at=now + timedelta(minutes=TOKEN_TTL_MINUTES),
            )
        )
        record_audit(
            user_id=user.id,
            action="PASSWORD_RESET_REQUESTED",
            details={"email": email, "exists": True},
            db=db,
        )
        db.commit()

        reset_url = f"{base_url}/reset-password?token={raw_token}"
        delivered = send_password_reset_email(
            user.email,
            user.username,
            reset_url,
            now.isoformat(),
            TOKEN_TTL_MINUTES,
        )
        if not delivered:
            with get_db_context() as db:
                record_audit(
                    user_id=user.id,
                    action="PASSWORD_RESET_EMAIL_FAILED",
                    details={"reason": "smtp_not_configured"},
                    db=db,
                )
        return True


def _get_valid_token(db: Session, raw_token: str):
    token_hash = _hash_token(raw_token)
    row = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.token_hash == token_hash)
        .order_by(PasswordResetToken.id.desc())
        .first()
    )
    if not row:
        return None
    if row.used_at is not None:
        return None
    now = utcnow()
    if row.expires_at < now:
        return None
    return row


def complete_password_reset(raw_token: str, new_password: str) -> bool:
    with get_db_context() as db:
        row = _get_valid_token(db, raw_token)
        user = db.query(User).filter(User.id == row.user_id).first() if row else None

        if not row or not user:
            record_audit(
                user_id=None,
                action="PASSWORD_RESET_INVALID_TOKEN",
                details={"reason": "invalid_or_expired"},
                db=db,
            )
            return False

        user.password_hash = hash_password(new_password)
        row.used_at = utcnow()
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.id != row.id,
            PasswordResetToken.used_at.is_(None),
        ).update({"expires_at": utcnow()})

        record_audit(
            user_id=user.id,
            action="PASSWORD_RESET_COMPLETED",
            details={"username": user.username},
            db=db,
        )
    return True


def reset_token_is_valid(raw_token: str) -> bool:
    with get_db_context() as db:
        row = _get_valid_token(db, raw_token)
        return row is not None
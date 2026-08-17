from itsdangerous import TimedSerializer, BadSignature, SignatureExpired
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from fastapi import Request
from app.config import settings
from app.database import get_db_context
from app.models import User
from app.security.password import verify_password
from app.security.totp import verify_totp


class SessionManager:
    def __init__(self, secret_key: str = None, salt: str = "session", max_age: int = None):
        self.secret_key = secret_key or settings.SECRET_KEY
        self.salt = salt
        self.max_age = max_age or settings.SESSION_MAX_AGE
        self.serializer = TimedSerializer(self.secret_key, salt=self.salt)

    def create_session(self, data: Dict[str, Any]) -> str:
        return self.serializer.dumps(data)

    def decode_session(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            return self.serializer.loads(token, max_age=self.max_age)
        except (BadSignature, SignatureExpired, Exception):
            return None

    def get_session_data(self, request) -> Optional[Dict[str, Any]]:
        cookie_name = settings.SESSION_COOKIE_NAME
        session_cookie = request.cookies.get(cookie_name)
        if not session_cookie:
            return None
        return self.decode_session(session_cookie)

    def set_session_cookie(self, response, data: Dict[str, Any]):
        token = self.create_session(data)
        response.set_cookie(
            key=settings.SESSION_COOKIE_NAME,
            value=token,
            max_age=self.max_age,
            httponly=settings.SESSION_COOKIE_HTTPONLY,
            secure=settings.SESSION_COOKIE_SECURE,
            samesite=settings.SESSION_COOKIE_SAMESITE,
            path="/",
        )

    def clear_session_cookie(self, response):
        response.delete_cookie(
            key=settings.SESSION_COOKIE_NAME,
            path="/",
            httponly=settings.SESSION_COOKIE_HTTPONLY,
            secure=settings.SESSION_COOKIE_SECURE,
            samesite=settings.SESSION_COOKIE_SAMESITE,
        )


session_manager = SessionManager()


AUTH_STATE_UNAUTHENTICATED = "unauthenticated"
AUTH_STATE_PASSWORD_VERIFIED = "password_verified"
AUTH_STATE_2FA_REQUIRED = "2fa_required"
AUTH_STATE_AUTHENTICATED = "authenticated"


def get_current_user(request: Request) -> Optional[User]:
    session_data = session_manager.get_session_data(request)
    if not session_data:
        return None
    
    if session_data.get("auth_state") != AUTH_STATE_AUTHENTICATED:
        return None
    
    user_id = session_data.get("user_id")
    if not user_id:
        return None
    
    with get_db_context() as db:
        user = db.query(User).filter(User.id == user_id).first()
        return user


def require_authentication(request: Request) -> User:
    user = get_current_user(request)
    if not user:
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    return user


def require_admin(request: Request) -> User:
    user = require_authentication(request)
    if user.role.value != "admin":
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return user


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def verify_credentials(username: str, password: str) -> Optional[User]:
    with get_db_context() as db:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return None
        
        if user.locked_until and user.locked_until > utcnow():
            return None
        
        if not verify_password(password, user.password_hash):
            return None
        
        return user


def increment_failed_attempts(user_id: int):
    with get_db_context() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return
        user.failed_attempts += 1
        from app.config import settings
        if user.failed_attempts >= settings.LOCKOUT_MAX_ATTEMPTS:
            from datetime import timedelta
            user.locked_until = utcnow() + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
        db.commit()


def reset_failed_attempts(user_id: int):
    with get_db_context() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return
        user.failed_attempts = 0
        user.locked_until = None
        db.commit()


def verify_2fa(user: User, code: str) -> bool:
    if not user.totp_enabled or not user.totp_secret:
        return False
    return verify_totp(user.totp_secret, code)
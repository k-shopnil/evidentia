import secrets
import hashlib
import hmac
from itsdangerous import TimedSerializer, BadSignature, SignatureExpired
from app.config import settings


class CSRFProtection:
    def __init__(self, secret_key: str = None, salt: str = "csrf-token", max_age: int = 3600):
        self.secret_key = secret_key or settings.SECRET_KEY
        self.salt = salt
        self.max_age = max_age
        self.serializer = TimedSerializer(self.secret_key, salt=self.salt)

    def generate_token(self, session_id: str) -> str:
        data = {"session_id": session_id, "nonce": secrets.token_hex(16)}
        return self.serializer.dumps(data)

    def validate_token(self, token: str, session_id: str) -> bool:
        try:
            data = self.serializer.loads(token, max_age=self.max_age)
            return data.get("session_id") == session_id
        except (BadSignature, SignatureExpired, Exception):
            return False

    def generate_form_token(self) -> str:
        return secrets.token_hex(32)


csrf = CSRFProtection()


def get_csrf_token(session_id: str) -> str:
    return csrf.generate_token(session_id)


def validate_csrf_token(token: str, session_id: str) -> bool:
    return csrf.validate_token(token, session_id)
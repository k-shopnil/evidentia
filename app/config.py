import os
from pathlib import Path
from typing import List
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    APP_NAME: str = os.getenv("APP_NAME", "Evidentia")
    DEBUG: bool = os.getenv("DEBUG", "true").lower() == "true"

    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./evidentia.db")

    SESSION_COOKIE_NAME: str = os.getenv("SESSION_COOKIE_NAME", "evidentia_session")
    SESSION_COOKIE_SECURE: bool = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    SESSION_COOKIE_HTTPONLY: bool = os.getenv("SESSION_COOKIE_HTTPONLY", "true").lower() == "true"
    SESSION_COOKIE_SAMESITE: str = os.getenv("SESSION_COOKIE_SAMESITE", "lax")
    SESSION_MAX_AGE: int = int(os.getenv("SESSION_MAX_AGE", "3600"))

    RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
    RATE_LIMIT_LOGIN: str = os.getenv("RATE_LIMIT_LOGIN", "5/minute")
    RATE_LIMIT_REGISTER: str = os.getenv("RATE_LIMIT_REGISTER", "3/minute")
    RATE_LIMIT_GENERAL: str = os.getenv("RATE_LIMIT_GENERAL", "100/minute")

    LOCKOUT_MAX_ATTEMPTS: int = int(os.getenv("LOCKOUT_MAX_ATTEMPTS", "5"))
    LOCKOUT_DURATION_MINUTES: int = int(os.getenv("LOCKOUT_DURATION_MINUTES", "15"))

    TOTP_ISSUER: str = os.getenv("TOTP_ISSUER", "Evidentia")

    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM: str = os.getenv("SMTP_FROM", "Evidentia Security <security@evidentia.local>")
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

    EVIDENCE_STORAGE_PATH: Path = BASE_DIR / os.getenv("EVIDENCE_STORAGE_PATH", "./app/storage/evidence")
    MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", "100"))

    STORAGE_BACKEND: str = os.getenv(
        "STORAGE_BACKEND",
        "s3" if os.getenv("R2_ENDPOINT_URL") else "local",
    )
    R2_ACCOUNT_ID: str = os.getenv("R2_ACCOUNT_ID", "")
    R2_ENDPOINT_URL: str = os.getenv("R2_ENDPOINT_URL", "")
    R2_ACCESS_KEY_ID: str = os.getenv("R2_ACCESS_KEY_ID", "")
    R2_SECRET_ACCESS_KEY: str = os.getenv("R2_SECRET_ACCESS_KEY", "")
    R2_BUCKET: str = os.getenv("R2_BUCKET", "")
    R2_PRESIGNED_URL_EXPIRY: int = int(os.getenv("R2_PRESIGNED_URL_EXPIRY", "300"))

    DEMO_MODE: bool = os.getenv("DEMO_MODE", "false").lower() == "true"
    ALLOWED_MIME_TYPES: List[str] = os.getenv("ALLOWED_MIME_TYPES", "application/pdf,image/jpeg,image/png,image/gif,text/plain").split(",")

    GENESIS_HASH: str = "0" * 64


settings = Settings()

settings.EVIDENCE_STORAGE_PATH.mkdir(parents=True, exist_ok=True)
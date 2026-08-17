import os

os.environ["DATABASE_URL"] = "sqlite:///./test_chain.db"
os.environ["DEBUG"] = "false"

import re
import html
import time
import pyotp
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models import User, AuditLog
from app.services.audit import verify_audit_chain, compute_hash

USERNAME = f"chainuser{int(time.time())}"


def get_csrf(client) -> str:
    token = client.get("/login").text
    return html.unescape(re.search(r'name="csrf_token" value="([^"]+)"', token).group(1))


with TestClient(app) as client:
    r = client.post(
        "/register",
        data={
            "username": USERNAME,
            "email": f"{USERNAME}@example.com",
            "password": "CorrectHorseBatteryStaple1!",
            "confirm_password": "CorrectHorseBatteryStaple1!",
            "csrf_token": get_csrf(client),
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    print("1. register ok")

    db = SessionLocal()
    setup_html = client.get("/verify-2fa").text
    secret = db.query(User).filter(User.username == USERNAME).first().totp_secret
    db.close()

    setup_csrf = html.unescape(re.search(r'name="csrf_token" value="([^"]+)"', setup_html).group(1))
    r = client.post(
        "/verify-2fa",
        data={"totp_code": pyotp.TOTP(secret).now(), "csrf_token": setup_csrf},
        follow_redirects=False,
    )
    assert r.status_code in (302, 307)
    print("2. 2FA setup ok")

chain = verify_audit_chain()
assert chain["valid"], f"chain invalid: {chain}"
print(f"3. chain valid: {chain['total_records']} records")

# Tamper with the oldest record's details (simulates Demo D manual DB edit)
db = SessionLocal()
oldest = db.query(AuditLog).order_by(AuditLog.id.asc()).first()
original_details = oldest.details
oldest.details = "TAMPERED"
db.commit()
db.close()

chain = verify_audit_chain()
assert not chain["valid"], "tampering must be detected"
assert chain["first_corruption_index"] == 0, chain
print(f"4. tampering detected at index {chain['first_corruption_index']}: {chain['message']}")

# Restore, then verify integrity restored
db = SessionLocal()
oldest = db.query(AuditLog).order_by(AuditLog.id.asc()).first()
oldest.details = original_details
db.commit()
db.close()

chain = verify_audit_chain()
assert chain["valid"], f"restored chain invalid: {chain}"
print(f"5. chain valid again after restore ({chain['total_records']} records)")

print("ALL CHAIN TESTS PASSED")
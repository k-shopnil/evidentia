import os
import shutil

os.environ["DATABASE_URL"] = "sqlite:///./test_demo.db"
os.environ["EVIDENCE_STORAGE_PATH"] = "./test_storage_demo"
os.environ["DEBUG"] = "false"
os.environ["DEMO_MODE"] = "true"

import re
import html
import time
import hashlib
import pyotp
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models import User, Case, Evidence, AuditLog, DemoState
from app.services.audit import verify_audit_chain, canonicalize_audit_record
from app.storage import storage

TS = int(time.time())
UN_ADMIN = f"admin{TS}"


def get_csrf(client, path="/login"):
    token = client.get(path).text
    return html.unescape(re.search(r'name="csrf_token" value="([^"]+)"', token).group(1))


def register_admin(client):
    r = client.post(
        "/register",
        data={
            "username": UN_ADMIN,
            "email": f"{UN_ADMIN}@example.com",
            "password": "CorrectHorseBatteryStaple1!",
            "confirm_password": "CorrectHorseBatteryStaple1!",
            "csrf_token": get_csrf(client),
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    setup_html = client.get("/verify-2fa").text
    secret = None
    with SessionLocal() as db:
        secret = db.query(User).filter(User.username == UN_ADMIN).first().totp_secret
    r = client.post(
        "/verify-2fa",
        data={"totp_code": pyotp.TOTP(secret).now(), "csrf_token": get_csrf(client, "/verify-2fa")},
        follow_redirects=False,
    )
    assert r.status_code in (302, 307)


with TestClient(app) as client:
    register_admin(client)
    with SessionLocal() as db:
        db.query(User).filter(User.username == UN_ADMIN).update({"role": "admin"})
        db.commit()
    print("1. admin registered")

    # --- Demo reset: rebuilds the full scenario ---
    r = client.post("/audit/demo-reset", data={"csrf_token": get_csrf(client, "/audit")}, follow_redirects=False)
    assert r.status_code == 302
    assert "msg=demo-reset" in r.headers["location"]
    with SessionLocal() as db:
        demo_user = db.query(User).filter(User.username == "demo_officer").first()
        assert demo_user, "demo user not seeded"
        case = db.query(Case).filter(Case.created_by == demo_user.id).first()
        assert case, "demo case not seeded"
        evidence = db.query(Evidence).filter(Evidence.case_id == case.id).first()
        assert evidence
    print("2. demo data seeded (user + case + evidence)")

    chain = verify_audit_chain()
    assert chain["valid"], f"chain invalid after seed: {chain}"
    print(f"3. chain valid after seed ({chain['total_records']} records)")

    # --- Evidence tamper/restore via UI buttons ---
    r = client.post(
        f"/evidence/{evidence.id}/demo-tamper",
        data={"csrf_token": get_csrf(client, f"/evidence/{evidence.id}")},
        follow_redirects=False,
    )
    assert r.status_code == 302
    r = client.post(
        f"/evidence/{evidence.id}/verify",
        data={"csrf_token": get_csrf(client, f"/evidence/{evidence.id}")},
    )
    assert "Integrity Compromised" in r.text
    print("4. evidence tampered -> verify shows COMPROMISED")

    r = client.post(
        f"/evidence/{evidence.id}/demo-restore",
        data={"csrf_token": get_csrf(client, f"/evidence/{evidence.id}")},
        follow_redirects=False,
    )
    assert r.status_code == 302
    r = client.post(
        f"/evidence/{evidence.id}/verify",
        data={"csrf_token": get_csrf(client, f"/evidence/{evidence.id}")},
    )
    assert "Integrity Verified" in r.text
    print("5. evidence restored -> verify shows VERIFIED")

    # --- Audit chain tamper/restore via UI buttons ---
    r = client.post(
        "/audit/demo-tamper",
        data={"csrf_token": get_csrf(client, "/audit")},
        follow_redirects=False,
    )
    assert r.status_code == 302
    chain = verify_audit_chain()
    assert not chain["valid"], "tampering not detected"
    print(f"6. audit tamper simulated -> chain INVALID ({chain['message']})")

    r = client.post(
        "/audit/demo-restore",
        data={"csrf_token": get_csrf(client, "/audit")},
        follow_redirects=False,
    )
    assert r.status_code == 302
    chain = verify_audit_chain()
    assert chain["valid"], f"chain not restored: {chain}"
    print(f"7. audit restored -> chain VALID ({chain['total_records']} records)")

    # --- Lockout + unlock via admin UI ---
    with SessionLocal() as db:
        db.query(User).filter(User.id == demo_user.id).update(
            {"failed_attempts": 5, "locked_until": __import__("datetime").datetime.utcnow()}
        )
        db.commit()
    r = client.post(
        f"/admin/users/{demo_user.id}/unlock",
        data={"csrf_token": get_csrf(client, "/admin/users")},
        follow_redirects=False,
    )
    assert r.status_code == 302
    with SessionLocal() as db:
        u = db.query(User).filter(User.id == demo_user.id).first()
        assert u.failed_attempts == 0 and u.locked_until is None
    print("8. locked user unlocked via admin button")

    chain = verify_audit_chain()
    assert chain["valid"], f"final chain invalid: {chain}"
    print(f"9. final chain valid ({chain['total_records']} records)")

print("ALL DEMO MODE TESTS PASSED")
import os
import shutil

os.environ["DATABASE_URL"] = "sqlite:///./test_cases.db"
os.environ["EVIDENCE_STORAGE_PATH"] = "./test_storage"
os.environ["DEBUG"] = "false"

import re
import html
import time
import hashlib
import pyotp
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models import User, Case, Evidence, AuditLog
from app.services.audit import verify_audit_chain

TS = int(time.time())
UN_A = f"user_a{TS}"
UN_B = f"user_b{TS}"


def get_csrf(client, path="/login"):
    token = client.get(path).text
    return html.unescape(re.search(r'name="csrf_token" value="([^"]+)"', token).group(1))


def register_and_login(client, username):
    r = client.post(
        "/register",
        data={
            "username": username,
            "email": f"{username}@example.com",
            "password": "CorrectHorseBatteryStaple1!",
            "confirm_password": "CorrectHorseBatteryStaple1!",
            "csrf_token": get_csrf(client),
        },
        follow_redirects=False,
    )
    assert r.status_code == 302

    setup_html = client.get("/verify-2fa").text
    db = SessionLocal()
    secret = db.query(User).filter(User.username == username).first().totp_secret
    db.close()
    assert secret

    r = client.post(
        "/verify-2fa",
        data={
            "totp_code": pyotp.TOTP(secret).now(),
            "csrf_token": html.unescape(re.search(r'name="csrf_token" value="([^"]+)"', setup_html).group(1)),
        },
        follow_redirects=False,
    )
    assert r.status_code in (302, 307)


def case_csrf(client, case_id):
    token = client.get(f"/cases/{case_id}").text
    return html.unescape(re.search(r'name="csrf_token" value="([^"]+)"', token).group(1))


with TestClient(app) as client:
    register_and_login(client, UN_A)
    print("1. user A registered + 2FA")

    # --- Phase 4: cases ---
    r = client.post(
        "/cases/create",
        data={
            "title": "Test Case Alpha",
            "description": "First test case",
            "csrf_token": get_csrf(client, "/cases/create"),
        },
        follow_redirects=False,
    )
    assert r.status_code == 302, r.text
    case_id = int(r.headers["location"].rstrip("/").split("/")[-1])
    print("2. case created ->", case_id)

    db = SessionLocal()
    case = db.query(Case).filter(Case.id == case_id).first()
    assert case.case_number == f"CASE-{case.created_by:04d}-0001"
    assert case.status.value == "open"
    db.close()

    r = client.get("/cases")
    assert "Test Case Alpha" in r.text and case.case_number in r.text
    print("3. case visible in list")

    r = client.post(
        f"/cases/{case_id}/update",
        data={"title": "Test Case Alpha (updated)", "status": "archived", "csrf_token": case_csrf(client, case_id)},
        follow_redirects=False,
    )
    assert r.status_code == 302
    r = client.get(f"/cases/{case_id}")
    assert "Test Case Alpha (updated)" in r.text
    print("4. case updated")

    # --- Phase 5: evidence ---
    content = b"SENSITIVE EVIDENCE BYTES: latent fingerprint analysis report."
    expected_hash = hashlib.sha256(content).hexdigest()

    r = client.post(
        f"/cases/{case_id}/evidence/upload",
        files={"file": ("report.txt", content, "text/plain")},
        data={"csrf_token": get_csrf(client, f"/cases/{case_id}/evidence/upload")},
        follow_redirects=False,
    )
    assert r.status_code == 302, r.text
    evidence_id = int(r.headers["location"].rstrip("/").split("/")[-1])
    print("5. evidence uploaded ->", evidence_id)

    r = client.get(f"/evidence/{evidence_id}")
    assert expected_hash in r.text and "text/plain" in r.text
    print("6. evidence detail shows sha256")

    r = client.post(
        f"/evidence/{evidence_id}/verify",
        data={"csrf_token": get_csrf(client, f"/evidence/{evidence_id}")},
    )
    if "Integrity Verified" not in r.text:
        print("DEBUG verify status:", r.status_code, "url:", r.url)
        print("DEBUG verify body head:", r.text[:400])
    assert "Integrity Verified" in r.text and "Integrity Compromised" not in r.text
    print("7. integrity verified")

    r = client.get(f"/evidence/{evidence_id}/download")
    assert r.status_code == 200 and r.content == content
    print("8. download returns original bytes")

    # Tamper with the stored object, verify -> must fail
    from app.storage import storage
    db = SessionLocal()
    ev = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    db.close()

    storage.put(ev.stored_filename, content + b"TAMPERED")

    r = client.post(
        f"/evidence/{evidence_id}/verify",
        data={"csrf_token": get_csrf(client, f"/evidence/{evidence_id}")},
    )
    assert "Integrity Compromised" in r.text
    print("9. tampered file detected")

    # Restore
    storage.put(ev.stored_filename, content)

    # --- Authorization: user B must NOT see user A's case ---
    client_b = TestClient(app)
    register_and_login(client_b, UN_B)
    assert client_b.get(f"/cases/{case_id}").status_code == 403
    assert client_b.get(f"/evidence/{evidence_id}").status_code == 403
    assert client_b.get(f"/evidence/{evidence_id}/download").status_code == 403
    print("10. cross-user access denied (403)")

    # --- Admin surface ---
    db = SessionLocal()
    a_id = db.query(User).filter(User.username == UN_A).first().id
    b_id = db.query(User).filter(User.username == UN_B).first().id
    db.query(User).filter(User.id == a_id).update({"role": "admin"})
    db.commit()
    db.close()

    assert client.get("/admin/users").status_code == 200
    assert client_b.get("/admin/users").status_code == 403
    print("10b. admin can view /admin/users; non-admin blocked (403)")

    # promote B to admin (2 admins), then A demotes B -> audited, allowed
    db = SessionLocal()
    db.query(User).filter(User.id == b_id).update({"role": "admin"})
    db.commit()
    db.close()

    admin_csrf = html.unescape(
        re.search(r'name="csrf_token" value="([^"]+)"', client_b.get("/admin/users").text).group(1)
    )

    r = client_b.post(
        f"/admin/users/{a_id}/toggle-role",
        data={"csrf_token": admin_csrf},
        follow_redirects=False,
    )
    if r.status_code != 302:
        print("DEBUG toggle status:", r.status_code, "body:", r.text[:300])
    assert r.status_code == 302
    db = SessionLocal()
    assert db.query(User).filter(User.id == a_id).first().role.value == "investigator"
    assert db.query(User).filter(User.id == b_id).first().role.value == "admin"
    db.close()
    print("10c. demotion by admin allowed when another admin remains")

    # B (now only admin) cannot demote itself -> blocked
    r2 = client_b.post(f"/admin/users/{b_id}/toggle-role", data={"csrf_token": admin_csrf})
    assert r2.status_code == 400
    db = SessionLocal()
    assert db.query(User).filter(User.id == b_id).first().role.value == "admin"
    db.close()
    print("10d. admin cannot self-demote")

    # A is now investigator, B is the only admin -> B promotes A back (positive path)
    r3 = client_b.post(
        f"/admin/users/{a_id}/toggle-role",
        data={"csrf_token": admin_csrf},
        follow_redirects=False,
    )
    if r3.status_code != 302:
        print("DEBUG promote status:", r3.status_code, "body:", r3.text[:300])
    assert r3.status_code == 302
    db = SessionLocal()
    assert db.query(User).filter(User.id == a_id).first().role.value == "admin"
    db.close()
    print("10e. only admin can still promote investigators")

    # --- Delete evidence, close case ---
    r = client.post(
        f"/evidence/{evidence_id}/delete",
        data={"csrf_token": case_csrf(client, case_id)},
        follow_redirects=False,
    )
    if r.status_code != 302:
        print("DEBUG delete status:", r.status_code, "url:", r.url)
        print("DEBUG delete body head:", r.text[:400])
    assert r.status_code == 302
    assert client.get(f"/evidence/{evidence_id}").status_code == 404
    print("11. evidence deleted")

    r = client.post(
        f"/cases/{case_id}/close",
        data={"csrf_token": case_csrf(client, case_id)},
        follow_redirects=False,
    )
    assert r.status_code == 302
    r = client.get(f"/cases/{case_id}")
    assert "closed" in r.text
    print("12. case closed")

    # --- Phase 6 UI: audit page + in-app chain verification ---
    r = client.get("/audit")
    assert r.status_code == 200 and "AUDIT" in r.text.upper()
    token = html.unescape(re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1))
    r = client.post("/audit/verify", data={"csrf_token": token})
    assert r.status_code == 200 and "Chain" in r.text
    print("13. audit page + verify POST ok")

# --- Audit chain still valid after all operations ---
chain = verify_audit_chain()
assert chain["valid"], f"chain invalid after workflow: {chain}"
actions = []
with SessionLocal() as db:
    actions = [a.action for a in db.query(AuditLog).order_by(AuditLog.id.asc()).all()]
for expected in [
    "CASE_CREATED",
    "CASE_UPDATED",
    "EVIDENCE_UPLOADED",
    "EVIDENCE_INTEGRITY_VERIFIED",
    "EVIDENCE_INTEGRITY_FAILED",
    "EVIDENCE_DOWNLOADED",
    "EVIDENCE_DELETED",
    "CASE_CLOSED",
    "AUDIT_CHAIN_VERIFIED",
    "ADMIN_USER_ACTION",
]:
    assert expected in actions, f"missing audit action {expected}"
print(f"14. chain valid: {chain['total_records']} records")
print("ALL CASE/EVIDENCE TESTS PASSED")
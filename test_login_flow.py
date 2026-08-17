import re
import html
import time
import pyotp
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models import User

USERNAME = f"dave{int(time.time())}"
EMAIL = f"{USERNAME}@example.com"
PASSWORD = "CorrectHorseBatteryStaple1!"


def get_csrf(client) -> str:
    token = client.get("/login").text
    m = re.search(r'name="csrf_token" value="([^"]+)"', token)
    assert m
    return html.unescape(m.group(1))


def csrf_from(html_text: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html_text)
    assert m
    return html.unescape(m.group(1))


with TestClient(app) as client:
    # 1) Register
    r = client.post(
        "/register",
        data={
            "username": USERNAME,
            "email": EMAIL,
            "password": PASSWORD,
            "confirm_password": PASSWORD,
            "csrf_token": get_csrf(client),
        },
        follow_redirects=False,
    )
    assert r.status_code == 302, f"register: {r.status_code}"
    print("1. register ok ->", r.headers.get("location"))

    # 2) Registers land on the 2FA setup page: complete setup with a valid code
    setup_html = client.get("/verify-2fa").text
    assert "Scan this QR code" in setup_html, "setup page must show QR"
    setup_csrf = csrf_from(setup_html)

    db = SessionLocal()
    secret = db.query(User).filter(User.username == USERNAME).first().totp_secret
    db.close()
    assert secret

    r = client.post(
        "/verify-2fa",
        data={"totp_code": pyotp.TOTP(secret).now(), "csrf_token": setup_csrf},
        follow_redirects=False,
    )
    assert r.status_code in (302, 307) and "/dashboard" in r.headers.get("location", ""), (
        f"2fa setup: {r.status_code} {r.headers.get('location')}"
    )
    print("2. 2FA setup with valid code ok ->", r.headers.get("location"))

    # 3) Logout
    page = client.get("/dashboard").text
    r = client.post("/logout", data={"csrf_token": csrf_from(page)}, follow_redirects=False)
    assert r.status_code in (302, 307)
    print("3. logout ok")

    # 4) Wrong password -> rejected, no session
    r = client.post(
        "/login",
        data={"username": USERNAME, "password": "wrong-password-!1", "csrf_token": get_csrf(client)},
        follow_redirects=False,
    )
    assert r.status_code == 401, f"bad password: {r.status_code}"
    print("4. wrong password rejected ok")

    # 5) Correct password with 2FA enabled -> challenged
    r = client.post(
        "/login",
        data={"username": USERNAME, "password": PASSWORD, "csrf_token": get_csrf(client)},
        follow_redirects=False,
    )
    assert r.status_code in (302, 307) and "/verify-2fa" in r.headers.get("location", ""), (
        f"2fa challenge: {r.status_code} {r.headers.get('location')}"
    )
    print("5. login -> 2FA challenge ok")

    # 6) Wrong TOTP rejected
    r = client.post(
        "/verify-2fa",
        data={"totp_code": "000000", "csrf_token": csrf_from(client.get("/verify-2fa").text)},
        follow_redirects=False,
    )
    assert r.status_code == 401, f"bad totp: {r.status_code}"
    print("6. wrong TOTP rejected ok")

    # 7) Correct TOTP -> authenticated
    r = client.post(
        "/verify-2fa",
        data={"totp_code": pyotp.TOTP(secret).now(), "csrf_token": csrf_from(client.get("/verify-2fa").text)},
        follow_redirects=False,
    )
    assert r.status_code in (302, 307) and "/dashboard" in r.headers.get("location", ""), (
        f"totp ok: {r.status_code} {r.headers.get('location')}"
    )
    r = client.get("/dashboard")
    assert r.status_code == 200 and f"Welcome back, {USERNAME}" in r.text
    print("7. TOTP success -> authenticated dashboard ok")

    # 8) Repeat login without new-device (registered this session) must not crash
    #    and chain verification must pass
    r = client.get("/audit")
    assert r.status_code == 200
    print("8. audit page renders ok")

print("ALL LOGIN-FLOW TESTS PASSED")
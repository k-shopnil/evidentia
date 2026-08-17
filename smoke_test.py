import re
import html
from fastapi.testclient import TestClient

from app.main import app


def get_csrf(client) -> str:
    token = client.get("/login").text
    m = re.search(r'name="csrf_token" value="([^"]+)"', token)
    assert m, "csrf token not found in login page"
    return html.unescape(m.group(1))


with TestClient(app) as client:
    r = client.get("/login")
    print("GET /login:", r.status_code)
    assert r.status_code == 200 and "Login" in r.text

    csrf = get_csrf(client)
    r = client.post(
        "/register",
        data={
            "username": "alice",
            "email": "alice@example.com",
            "password": "CorrectHorseBatteryStaple1!",
            "confirm_password": "CorrectHorseBatteryStaple1!",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    print("POST /register:", r.status_code, r.headers.get("location"))
    assert r.status_code in (302, 307)

    r = client.get("/verify-2fa")
    print("GET /verify-2fa (setup page):", r.status_code)
    assert r.status_code == 200 and "Scan this QR code" in r.text

    r = client.get("/audit", follow_redirects=False)
    print("GET /audit (unauth):", r.status_code, r.headers.get("location"))
    assert r.status_code in (302, 307)

    r = client.get("/dashboard", follow_redirects=False)
    print("GET /dashboard (unauth):", r.status_code, r.headers.get("location"))
    assert r.status_code in (302, 307)

    r = client.post("/logout", data={}, follow_redirects=False)
    print("POST /logout (no csrf):", r.status_code)
    assert r.status_code == 422  # missing required CSRF form field

print("ALL SMOKE TESTS PASSED")
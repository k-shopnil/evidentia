from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from datetime import datetime
import pyotp

from app.database import get_db
from app.config import settings
from app.models import User, UserRole
from app.security.password import hash_password, verify_password
from app.security.totp import generate_secret, get_totp_uri, generate_qr_code, verify_totp
from app.security.csrf import get_csrf_token, validate_csrf_token
from app.security.device import generate_device_fingerprint, is_known_device, register_device, get_device_info
from app.security.auth import (
    session_manager, increment_failed_attempts,
    reset_failed_attempts, verify_2fa, utcnow,
    AUTH_STATE_PASSWORD_VERIFIED, AUTH_STATE_AUTHENTICATED
)
from app.security.rate_limit import limiter
from app.services.audit import record_audit
from app.services.email import send_account_locked_alert
from app.services.alerts import notify_new_device
from app.templating import templates


router = APIRouter(prefix="", tags=["auth"])


def get_csrf_token_for_session(request: Request) -> str:
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    return get_csrf_token(session_id)


@router.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    user = session_manager.get_session_data(request)
    if user and user.get("auth_state") == AUTH_STATE_AUTHENTICATED:
        return RedirectResponse(url="/dashboard")
    
    csrf_token = get_csrf_token_for_session(request)
    return templates.TemplateResponse("auth/login.html", {"request": request, "csrf_token": csrf_token})


@router.post("/login", response_class=HTMLResponse)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    
    if not validate_csrf_token(csrf_token, session_id):
        return templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "error": "Invalid CSRF token", "csrf_token": get_csrf_token_for_session(request)},
            status_code=400
        )
    
    user = db.query(User).filter(User.username == username).first()
    
    if not user:
        record_audit(user_id=None, action="AUTH_LOGIN_FAILURE", details={"username": username, "reason": "user_not_found"})
        return templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "error": "Invalid username or password", "csrf_token": get_csrf_token_for_session(request)},
            status_code=401
        )
    
    if user.locked_until and user.locked_until > utcnow():
        record_audit(user_id=user.id, action="AUTH_LOGIN_FAILURE", details={"reason": "account_locked"})
        remaining = (user.locked_until - utcnow()).total_seconds() // 60 + 1
        remaining = int(max(remaining, 1))
        lock_msg = f"Account is locked. Try again in about {remaining} minute{'s' if remaining != 1 else ''}."
        return templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "error": lock_msg, "csrf_token": get_csrf_token_for_session(request)},
            status_code=403
        )
    
    if not verify_password(password, user.password_hash):
        increment_failed_attempts(user.id)
        db.refresh(user)
        record_audit(user_id=user.id, action="AUTH_LOGIN_FAILURE", details={"reason": "invalid_password"})
        
        if user.failed_attempts >= settings.LOCKOUT_MAX_ATTEMPTS:
            send_account_locked_alert(user.email, user.username, utcnow().isoformat(), request.client.host)
            lock_msg = f"Account locked for {settings.LOCKOUT_DURATION_MINUTES} minutes after {settings.LOCKOUT_MAX_ATTEMPTS} failed attempts."
            return templates.TemplateResponse(
                "auth/login.html",
                {"request": request, "error": lock_msg, "csrf_token": get_csrf_token_for_session(request)},
                status_code=403
            )
        
        remaining = settings.LOCKOUT_MAX_ATTEMPTS - user.failed_attempts
        attempts_msg = f"Invalid username or password. {remaining} attempt{'s' if remaining != 1 else ''} left before lockout."
        return templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "error": attempts_msg, "csrf_token": get_csrf_token_for_session(request)},
            status_code=401
        )
    
    reset_failed_attempts(user.id)
    
    if user.totp_enabled:
        session_data = {
            "session_id": session_id or pyotp.random_base32(),
            "auth_state": AUTH_STATE_PASSWORD_VERIFIED,
            "user_id": user.id,
            "2fa_required": True,
        }
        
        response = RedirectResponse(url="/verify-2fa", status_code=302)
        session_manager.set_session_cookie(response, session_data)
        return response
    
    device_fingerprint = generate_device_fingerprint(
        request.headers.get("user-agent", ""),
        request.headers.get("accept-language", ""),
        request.client.host
    )
    
    device_name = get_device_info(request.headers.get("user-agent", ""))
    is_new_device = not is_known_device(db, user.id, device_fingerprint)
    
    if is_new_device:
        register_device(db, user.id, device_fingerprint, device_name)
        db.commit()
        record_audit(
            user_id=user.id,
            action="AUTH_NEW_DEVICE",
            details={"device_id": device_fingerprint, "device_name": device_name}
        )
        notify_new_device(user.id, device_name, device_fingerprint,
                          request.client.host or "", utcnow().isoformat())

    session_data = {
        "session_id": session_id or pyotp.random_base32(),
        "auth_state": AUTH_STATE_AUTHENTICATED,
        "user_id": user.id,
        "device_id": device_fingerprint,
    }
    
    record_audit(user_id=user.id, action="AUTH_LOGIN_SUCCESS", details={"device_id": device_fingerprint})
    
    response = RedirectResponse(url="/dashboard", status_code=302)
    session_manager.set_session_cookie(response, session_data)
    return response


@router.get("/register", response_class=HTMLResponse)
async def register_get(request: Request):
    csrf_token = get_csrf_token_for_session(request)
    return templates.TemplateResponse("auth/register.html", {"request": request, "csrf_token": csrf_token})


@router.post("/register", response_class=HTMLResponse)
@limiter.limit(settings.RATE_LIMIT_REGISTER)
async def register_post(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    phone: str = Form(""),
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    
    if not validate_csrf_token(csrf_token, session_id):
        return templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "error": "Invalid CSRF token", "csrf_token": get_csrf_token_for_session(request)},
            status_code=400
        )
    
    if password != confirm_password:
        return templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "error": "Passwords do not match", "csrf_token": get_csrf_token_for_session(request)},
            status_code=400
        )
    
    if len(password) < 12:
        return templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "error": "Password must be at least 12 characters", "csrf_token": get_csrf_token_for_session(request)},
            status_code=400
        )
    
    if db.query(User).filter(User.username == username).first():
        return templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "error": "Username already exists", "csrf_token": get_csrf_token_for_session(request)},
            status_code=400
        )
    
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "error": "Email already registered", "csrf_token": get_csrf_token_for_session(request)},
            status_code=400
        )
    
    password_hash = hash_password(password)
    
    is_first_user = db.query(User).count() == 0
    user = User(
        username=username,
        email=email,
        phone=phone.strip() or None,
        password_hash=password_hash,
        role=UserRole.ADMIN if is_first_user else UserRole.INVESTIGATOR,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    record_audit(user_id=user.id, action="AUTH_REGISTER", details={"username": username})
    
    session_data = {
        "session_id": pyotp.random_base32(),
        "auth_state": AUTH_STATE_PASSWORD_VERIFIED,
        "user_id": user.id,
        "2fa_required": True,
    }
    
    response = RedirectResponse(url="/verify-2fa", status_code=302)
    session_manager.set_session_cookie(response, session_data)
    return response


@router.get("/verify-2fa", response_class=HTMLResponse)
async def verify_2fa_get(request: Request, db: Session = Depends(get_db)):
    session_data = session_manager.get_session_data(request)
    if not session_data or session_data.get("auth_state") != AUTH_STATE_PASSWORD_VERIFIED:
        return RedirectResponse(url="/login")

    user_id = session_data.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        return RedirectResponse(url="/login")

    setup = user.totp_secret is None
    if setup:
        user.totp_secret = generate_secret()
        db.commit()

    totp_uri = get_totp_uri(user.totp_secret, user.username)
    qr_code = generate_qr_code(totp_uri)
    csrf_token = get_csrf_token_for_session(request)

    return templates.TemplateResponse(
        "auth/verify_2fa.html",
        {"request": request, "qr_code": qr_code, "secret": user.totp_secret, "csrf_token": csrf_token, "setup": setup}
    )


@router.post("/verify-2fa", response_class=HTMLResponse)
@limiter.limit("10/minute")
async def verify_2fa_post(
    request: Request,
    totp_code: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    session_data = session_manager.get_session_data(request)
    if not session_data or session_data.get("auth_state") != AUTH_STATE_PASSWORD_VERIFIED:
        return RedirectResponse(url="/login")
    
    session_id = session_data.get("session_id", "")
    
    if not validate_csrf_token(csrf_token, session_id):
        return templates.TemplateResponse(
            "auth/verify_2fa.html",
            {"request": request, "error": "Invalid CSRF token", "csrf_token": get_csrf_token_for_session(request)},
            status_code=400
        )
    
    user_id = session_data.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()

    if not user or not user.totp_secret:
        return RedirectResponse(url="/login")

    setup = not user.totp_enabled

    if not verify_totp(user.totp_secret, totp_code):
        record_audit(user_id=user.id, action="AUTH_2FA_FAILURE", details={"reason": "invalid_code"})
        return templates.TemplateResponse(
            "auth/verify_2fa.html",
            {"request": request, "error": "Invalid 2FA code", "csrf_token": get_csrf_token_for_session(request), "setup": setup},
            status_code=401
        )

    if setup:
        user.totp_enabled = True
        db.commit()
    
    device_fingerprint = generate_device_fingerprint(
        request.headers.get("user-agent", ""),
        request.headers.get("accept-language", ""),
        request.client.host
    )
    
    device_name = get_device_info(request.headers.get("user-agent", ""))
    is_new_device = not is_known_device(db, user.id, device_fingerprint)
    
    if is_new_device:
        register_device(db, user.id, device_fingerprint, device_name)
        db.commit()
        record_audit(
            user_id=user.id,
            action="AUTH_NEW_DEVICE",
            details={"device_id": device_fingerprint, "device_name": device_name}
        )
        notify_new_device(user.id, device_name, device_fingerprint,
                          request.client.host or "", utcnow().isoformat())

    record_audit(user_id=user.id, action="AUTH_2FA_SUCCESS", details={"device_id": device_fingerprint})
    record_audit(user_id=user.id, action="AUTH_LOGIN_SUCCESS", details={"device_id": device_fingerprint})
    
    session_data = {
        "session_id": session_id,
        "auth_state": AUTH_STATE_AUTHENTICATED,
        "user_id": user.id,
        "device_id": device_fingerprint,
    }
    
    response = RedirectResponse(url="/dashboard", status_code=302)
    session_manager.set_session_cookie(response, session_data)
    return response


@router.post("/logout")
async def logout(
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""

    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url="/login", status_code=400)

    if session_data and session_data.get("user_id"):
        record_audit(user_id=session_data["user_id"], action="AUTH_LOGOUT", details={})

    response = RedirectResponse(url="/login", status_code=302)
    session_manager.clear_session_cookie(response)
    return response
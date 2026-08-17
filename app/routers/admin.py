from fastapi import APIRouter, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Optional

from app.database import get_db
from app.config import settings
from app.models import User, UserRole
from app.security.csrf import get_csrf_token, validate_csrf_token
from app.security.auth import session_manager, require_admin, get_current_user, AUTH_STATE_AUTHENTICATED
from app.services.audit import get_audit_logs
from app.templating import templates


router = APIRouter(prefix="/admin", tags=["admin"])


def get_csrf_token_for_session(request: Request) -> str:
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    return get_csrf_token(session_id)


@router.get("/users", response_class=HTMLResponse)
async def admin_users(
    request: Request,
    skip: int = 0,
    limit: int = 50,
    user=Depends(require_admin),
    db: Session = Depends(get_db)
):
    users = db.query(User).order_by(User.created_at.desc()).offset(skip).limit(limit).all()
    total = db.query(User).count()
    csrf_token = get_csrf_token_for_session(request)
    
    return templates.TemplateResponse(
        "admin/users.html",
        {"request": request, "user": user, "users": users, "total": total, "skip": skip, "limit": limit, "csrf_token": csrf_token}
    )


@router.post("/users/{user_id}/toggle-role", response_class=HTMLResponse)
async def admin_toggle_role(
    request: Request,
    user_id: int,
    csrf_token: str = Form(...),
    user=Depends(require_admin),
    db: Session = Depends(get_db)
):
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    
    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url="/admin/users", status_code=status.HTTP_400_BAD_REQUEST)
    
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if target_user.id == user.id:
        return RedirectResponse(url="/admin/users", status_code=status.HTTP_400_BAD_REQUEST)

    if target_user.role == UserRole.ADMIN:
        admin_count = db.query(User).filter(User.role == UserRole.ADMIN).count()
        if admin_count <= 1:
            return RedirectResponse(url="/admin/users", status_code=status.HTTP_400_BAD_REQUEST)

    old_role = target_user.role
    target_user.role = UserRole.ADMIN if target_user.role == UserRole.INVESTIGATOR else UserRole.INVESTIGATOR
    
    db.commit()
    
    from app.services.audit import record_audit
    record_audit(
        user_id=user.id,
        action="ADMIN_USER_ACTION",
        entity_type="User",
        entity_id=target_user.id,
        details={"action": "role_change", "old_role": old_role.value, "new_role": target_user.role.value}
    )
    
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_302_FOUND)


@router.post("/users/{user_id}/reset-2fa", response_class=HTMLResponse)
async def admin_reset_2fa(
    request: Request,
    user_id: int,
    csrf_token: str = Form(...),
    user=Depends(require_admin),
    db: Session = Depends(get_db)
):
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    
    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url="/admin/users", status_code=status.HTTP_400_BAD_REQUEST)
    
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    target_user.totp_secret = None
    target_user.totp_enabled = False
    db.commit()
    
    from app.services.audit import record_audit
    record_audit(
        user_id=user.id,
        action="ADMIN_USER_ACTION",
        entity_type="User",
        entity_id=target_user.id,
        details={"action": "reset_2fa"}
    )
    
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_302_FOUND)


@router.get("/audit", response_class=HTMLResponse)
async def admin_audit(
    request: Request,
    skip: int = 0,
    limit: int = 100,
    user=Depends(require_admin)
):
    logs, total = get_audit_logs(skip, limit)
    csrf_token = get_csrf_token_for_session(request)
    
    return templates.TemplateResponse(
        "audit/list.html",
        {"request": request, "user": user, "logs": logs, "total": total, "skip": skip, "limit": limit, "filters": {}, "csrf_token": csrf_token}
    )


@router.post("/users/{user_id}/unlock", response_class=HTMLResponse)
async def admin_unlock_user(
    request: Request,
    user_id: int,
    csrf_token: str = Form(...),
    user=Depends(require_admin),
    db: Session = Depends(get_db)
):
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""

    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url="/admin/users", status_code=status.HTTP_400_BAD_REQUEST)

    from app.services.demo import unlock_user

    try:
        unlock_user(user_id, user.id)
        return RedirectResponse(url="/admin/users?msg=demo-unlocked", status_code=status.HTTP_302_FOUND)
    except HTTPException as e:
        return RedirectResponse(url=f"/admin/users?msg=error-{e.status_code}", status_code=status.HTTP_302_FOUND)
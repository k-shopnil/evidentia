from fastapi import APIRouter, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime

from app.database import get_db
from app.config import settings
from app.models import User, AuditLog
from app.security.csrf import get_csrf_token, validate_csrf_token
from app.security.auth import session_manager, get_current_user, require_admin, AUTH_STATE_AUTHENTICATED
from app.services.audit import record_audit, verify_audit_chain, get_audit_logs
from app.templating import templates


router = APIRouter(prefix="/audit", tags=["audit"])


def get_csrf_token_for_session(request: Request) -> str:
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    return get_csrf_token(session_id)


def parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


@router.get("", response_class=HTMLResponse)
async def audit_list(
    request: Request,
    skip: int = 0,
    limit: int = 100,
    username: Optional[str] = None,
    log_id: Optional[str] = None,
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")
    
    search_user_id: Optional[int] = None
    if user.role.value != "admin":
        search_user_id = user.id
    
    try:
        log_id_val = int(log_id) if log_id else None
    except (TypeError, ValueError):
        log_id_val = None
    
    start_time = parse_datetime(start)
    end_time = parse_datetime(end)
    
    logs, total = get_audit_logs(
        skip, limit,
        user_id=search_user_id,
        username=username,
        action=action,
        entity_type=entity_type,
        log_id=log_id_val,
        start_time=start_time,
        end_time=end_time,
    )
    
    scope = db.query(AuditLog)
    if search_user_id is not None:
        scope = scope.filter(AuditLog.user_id == search_user_id)
    actions = [r[0] for r in scope.with_entities(AuditLog.action).distinct().order_by(AuditLog.action).all()]
    entity_types = [
        r[0] for r in scope
        .filter(AuditLog.entity_type.isnot(None))
        .with_entities(AuditLog.entity_type)
        .distinct().order_by(AuditLog.entity_type).all()
    ]
    
    csrf_token = get_csrf_token_for_session(request)
    
    filters = {
        "username": username or "",
        "log_id": log_id or "",
        "action": action or "",
        "entity_type": entity_type or "",
        "start": start or "",
        "end": end or "",
        "active": bool(username or log_id or action or entity_type or start or end),
    }
    
    return templates.TemplateResponse(
        "audit/list.html",
        {
            "request": request,
            "user": user,
            "logs": logs,
            "total": total,
            "skip": skip,
            "limit": limit,
            "filters": filters,
            "actions": actions,
            "entity_types": entity_types,
            "csrf_token": csrf_token
        }
    )


@router.post("/verify", response_class=HTMLResponse)
async def verify_audit_post(
    request: Request,
    csrf_token: str = Form(...),
    user=Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")
    
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    
    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url="/audit", status_code=status.HTTP_400_BAD_REQUEST)
    
    result = verify_audit_chain()
    
    record_audit(
        user_id=user.id,
        action="AUDIT_CHAIN_VERIFIED" if result["valid"] else "AUDIT_CHAIN_TAMPERING_DETECTED",
        details=result
    )
    
    logs, total = get_audit_logs(limit=100)
    csrf_token = get_csrf_token_for_session(request)
    
    return templates.TemplateResponse(
        "audit/list.html",
        {
            "request": request,
            "user": user,
            "logs": logs,
            "total": total,
            "skip": 0,
            "limit": 100,
            "filters": {},
            "csrf_token": csrf_token,
            "verify_result": result
        }
    )


def _demo_redirect(msg: str) -> RedirectResponse:
    return RedirectResponse(url=f"/audit?msg={msg}", status_code=status.HTTP_302_FOUND)


@router.post("/demo-tamper", response_class=HTMLResponse)
async def demo_tamper_audit(
    request: Request,
    csrf_token: str = Form(...),
    user=Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")

    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url="/audit", status_code=status.HTTP_400_BAD_REQUEST)

    from app.services.demo import tamper_audit_chain

    try:
        tamper_audit_chain(user.id)
        return _demo_redirect("demo-tampered")
    except HTTPException as e:
        return _demo_redirect(f"error-{e.status_code}")


@router.post("/demo-restore", response_class=HTMLResponse)
async def demo_restore_audit(
    request: Request,
    csrf_token: str = Form(...),
    user=Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")

    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url="/audit", status_code=status.HTTP_400_BAD_REQUEST)

    from app.services.demo import restore_audit_chain

    try:
        restore_audit_chain(user.id)
        return _demo_redirect("demo-restored")
    except HTTPException as e:
        return _demo_redirect(f"error-{e.status_code}")


@router.post("/demo-reset", response_class=HTMLResponse)
async def demo_reset(
    request: Request,
    csrf_token: str = Form(...),
    user=Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")

    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url="/audit", status_code=status.HTTP_400_BAD_REQUEST)

    from app.services.demo import reset_demo_data

    try:
        result = reset_demo_data(user.id)
        return _demo_redirect(f"demo-reset")
    except HTTPException as e:
        return _demo_redirect(f"error-{e.status_code}")
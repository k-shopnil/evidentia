from fastapi import APIRouter, Request, Form, Depends, HTTPException, status as http_status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Optional

from app.database import get_db
from app.config import settings
from app.models import User, Case, CaseStatus
from app.security.csrf import get_csrf_token, validate_csrf_token
from app.security.auth import session_manager, get_current_user, require_authentication, AUTH_STATE_AUTHENTICATED
from app.services.cases import create_case, get_cases, get_case_by_id, update_case, close_case
from app.services.audit import record_audit
from app.templating import templates


router = APIRouter(prefix="/cases", tags=["cases"])


def get_csrf_token_for_session(request: Request) -> str:
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    return get_csrf_token(session_id)


@router.get("", response_class=HTMLResponse)
async def list_cases(request: Request, user=Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    
    cases_list = get_cases(user.id, user.role.value)
    csrf_token = get_csrf_token_for_session(request)
    
    return templates.TemplateResponse(
        "cases/list.html",
        {"request": request, "user": user, "cases": cases_list, "csrf_token": csrf_token}
    )


@router.get("/create", response_class=HTMLResponse)
async def create_case_get(request: Request, user=Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    
    csrf_token = get_csrf_token_for_session(request)
    return templates.TemplateResponse("cases/create.html", {"request": request, "user": user, "csrf_token": csrf_token})


@router.post("/create", response_class=HTMLResponse)
async def create_case_post(
    request: Request,
    title: str = Form(...),
    description: str = Form(""),
    csrf_token: str = Form(...),
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login")
    
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    
    if not validate_csrf_token(csrf_token, session_id):
        return templates.TemplateResponse(
            "cases/create.html",
            {"request": request, "user": user, "error": "Invalid CSRF token", "csrf_token": get_csrf_token_for_session(request)},
            status_code=http_status.HTTP_400_BAD_REQUEST
        )
    
    if not title.strip():
        return templates.TemplateResponse(
            "cases/create.html",
            {"request": request, "user": user, "error": "Title is required", "csrf_token": get_csrf_token_for_session(request)},
            status_code=http_status.HTTP_400_BAD_REQUEST
        )
    
    case = create_case(title.strip(), description.strip() if description else None, user.id)
    
    return RedirectResponse(url=f"/cases/{case.id}", status_code=http_status.HTTP_302_FOUND)


@router.get("/{case_id}", response_class=HTMLResponse)
async def case_detail(request: Request, case_id: int, user=Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    
    case = get_case_by_id(case_id, user.id, user.role.value)
    csrf_token = get_csrf_token_for_session(request)
    
    from app.services.evidence import get_evidence_for_download
    from app.database import get_db_context
    from app.models import Evidence
    
    with get_db_context() as db:
        evidence_list = db.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.created_at.desc()).all()
    
    return templates.TemplateResponse(
        "cases/detail.html",
        {"request": request, "user": user, "case": case, "evidence_list": evidence_list, "csrf_token": csrf_token}
    )


@router.post("/{case_id}/update", response_class=HTMLResponse)
async def update_case_post(
    request: Request,
    case_id: int,
    title: str = Form(None),
    description: str = Form(None),
    status: str = Form(None),
    csrf_token: str = Form(...),
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login")
    
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    
    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url=f"/cases/{case_id}", status_code=http_status.HTTP_400_BAD_REQUEST)
    
    case = update_case(case_id, title, description, status, user.id, user.role.value)
    
    return RedirectResponse(url=f"/cases/{case_id}", status_code=http_status.HTTP_302_FOUND)


@router.post("/{case_id}/close", response_class=HTMLResponse)
async def close_case_post(
    request: Request,
    case_id: int,
    csrf_token: str = Form(...),
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login")
    
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    
    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url=f"/cases/{case_id}", status_code=http_status.HTTP_400_BAD_REQUEST)
    
    case = close_case(case_id, user.id, user.role.value)
    
    record_audit(
        user_id=user.id,
        action="CASE_CLOSED",
        entity_type="Case",
        entity_id=case.id,
        details={"case_number": case.case_number}
    )
    
    return RedirectResponse(url=f"/cases/{case_id}", status_code=http_status.HTTP_302_FOUND)
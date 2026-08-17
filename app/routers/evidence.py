from fastapi import APIRouter, Request, Form, Depends, HTTPException, status, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pathlib import Path

from app.database import get_db
from app.config import settings
from app.models import User, Evidence
from app.security.csrf import get_csrf_token, validate_csrf_token
from app.security.auth import session_manager, get_current_user, AUTH_STATE_AUTHENTICATED
from app.services.evidence import (
    upload_evidence,
    verify_evidence_integrity,
    get_evidence_for_download,
    get_evidence_download_url,
    delete_evidence,
)
from app.services.audit import record_audit
from app.templating import templates


router = APIRouter(prefix="", tags=["evidence"])


def get_csrf_token_for_session(request: Request) -> str:
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    return get_csrf_token(session_id)


@router.get("/cases/{case_id}/evidence/upload", response_class=HTMLResponse)
async def upload_evidence_get(request: Request, case_id: int, user=Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    
    from app.services.cases import get_case_by_id
    case = get_case_by_id(case_id, user.id, user.role.value)
    csrf_token = get_csrf_token_for_session(request)
    
    return templates.TemplateResponse(
        "evidence/upload.html",
        {"request": request, "user": user, "case": case, "csrf_token": csrf_token}
    )


@router.post("/cases/{case_id}/evidence/upload", response_class=HTMLResponse)
async def upload_evidence_post(
    request: Request,
    case_id: int,
    file: UploadFile = File(...),
    csrf_token: str = Form(...),
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login")
    
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    
    if not validate_csrf_token(csrf_token, session_id):
        from app.services.cases import get_case_by_id
        case = get_case_by_id(case_id, user.id, user.role.value)
        return templates.TemplateResponse(
            "evidence/upload.html",
            {"request": request, "user": user, "case": case, "error": "Invalid CSRF token", "csrf_token": get_csrf_token_for_session(request)},
            status_code=status.HTTP_400_BAD_REQUEST
        )
    
    if not file.filename:
        from app.services.cases import get_case_by_id
        case = get_case_by_id(case_id, user.id, user.role.value)
        return templates.TemplateResponse(
            "evidence/upload.html",
            {"request": request, "user": user, "case": case, "error": "No file selected", "csrf_token": get_csrf_token_for_session(request)},
            status_code=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        evidence = await upload_evidence(case_id, file, user.id)
        return RedirectResponse(url=f"/evidence/{evidence.id}", status_code=status.HTTP_302_FOUND)
    except HTTPException as e:
        from app.services.cases import get_case_by_id
        case = get_case_by_id(case_id, user.id, user.role.value)
        return templates.TemplateResponse(
            "evidence/upload.html",
            {"request": request, "user": user, "case": case, "error": e.detail, "csrf_token": get_csrf_token_for_session(request)},
            status_code=e.status_code
        )


@router.get("/evidence/{evidence_id}", response_class=HTMLResponse)
async def evidence_detail(request: Request, evidence_id: int, user=Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    
    from app.database import get_db_context
    from app.services.cases import get_case_by_id
    
    with get_db_context() as db:
        evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
        if not evidence:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
        
        case = get_case_by_id(evidence.case_id, user.id, user.role.value)
    
    csrf_token = get_csrf_token_for_session(request)
    
    return templates.TemplateResponse(
        "evidence/detail.html",
        {"request": request, "user": user, "evidence": evidence, "case": case, "csrf_token": csrf_token}
    )


@router.get("/evidence/{evidence_id}/download")
async def download_evidence(request: Request, evidence_id: int, user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    evidence = get_evidence_for_download(evidence_id, user.id, user.role.value)

    record_audit(
        user_id=user.id,
        action="EVIDENCE_DOWNLOADED",
        entity_type="Evidence",
        entity_id=evidence_id,
        details={"filename": evidence.filename}
    )

    presigned_url = get_evidence_download_url(evidence)
    if presigned_url:
        return RedirectResponse(url=presigned_url, status_code=status.HTTP_302_FOUND)

    from app.storage import storage
    local_path = storage.local_path(evidence.stored_filename)
    if not local_path or not local_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence file missing")

    return FileResponse(
        path=str(local_path),
        filename=evidence.filename,
        media_type=evidence.mime_type
    )


@router.post("/evidence/{evidence_id}/verify", response_class=HTMLResponse)
async def verify_evidence_post(
    request: Request,
    evidence_id: int,
    csrf_token: str = Form(...),
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login")
    
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    
    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url=f"/evidence/{evidence_id}", status_code=status.HTTP_400_BAD_REQUEST)
    
    result = verify_evidence_integrity(evidence_id)
    
    action = "EVIDENCE_INTEGRITY_VERIFIED" if result["match"] else "EVIDENCE_INTEGRITY_FAILED"
    record_audit(
        user_id=user.id,
        action=action,
        entity_type="Evidence",
        entity_id=evidence_id,
        details={
            "match": result["match"],
            "original_hash": result["original_hash"],
            "computed_hash": result["computed_hash"],
        }
    )
    
    from app.database import get_db_context
    from app.services.cases import get_case_by_id
    
    with get_db_context() as db:
        evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
        case = get_case_by_id(evidence.case_id, user.id, user.role.value)
    
    csrf_token = get_csrf_token_for_session(request)
    
    return templates.TemplateResponse(
        "evidence/detail.html",
        {
            "request": request,
            "user": user,
            "evidence": evidence,
            "case": case,
            "csrf_token": csrf_token,
            "verify_result": result
        }
    )


@router.post("/evidence/{evidence_id}/delete", response_class=HTMLResponse)
async def delete_evidence_post(
    request: Request,
    evidence_id: int,
    csrf_token: str = Form(...),
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login")
    
    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    
    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url=f"/evidence/{evidence_id}", status_code=status.HTTP_400_BAD_REQUEST)
    
    from app.database import get_db_context
    from app.services.cases import get_case_by_id
    
    with get_db_context() as db:
        evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
        if not evidence:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
        
        case_id = evidence.case_id
        case = get_case_by_id(case_id, user.id, user.role.value)
    
    delete_evidence(evidence_id, user.id, user.role.value)
    
    return RedirectResponse(url=f"/cases/{case_id}", status_code=status.HTTP_302_FOUND)


@router.post("/evidence/{evidence_id}/demo-tamper", response_class=HTMLResponse)
async def demo_tamper_evidence(
    request: Request,
    evidence_id: int,
    csrf_token: str = Form(...),
    user=Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")

    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""

    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url=f"/evidence/{evidence_id}", status_code=status.HTTP_400_BAD_REQUEST)

    from app.services.demo import tamper_evidence

    try:
        tamper_evidence(evidence_id, user.id)
        return RedirectResponse(url=f"/evidence/{evidence_id}?msg=demo-tampered", status_code=status.HTTP_302_FOUND)
    except HTTPException as e:
        return RedirectResponse(url=f"/evidence/{evidence_id}?msg=error-{e.status_code}", status_code=status.HTTP_302_FOUND)


@router.post("/evidence/{evidence_id}/demo-restore", response_class=HTMLResponse)
async def demo_restore_evidence(
    request: Request,
    evidence_id: int,
    csrf_token: str = Form(...),
    user=Depends(get_current_user)
):
    if not user:
        return RedirectResponse(url="/login")

    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""

    if not validate_csrf_token(csrf_token, session_id):
        return RedirectResponse(url=f"/evidence/{evidence_id}", status_code=status.HTTP_400_BAD_REQUEST)

    from app.services.demo import restore_evidence

    try:
        restore_evidence(evidence_id, user.id)
        return RedirectResponse(url=f"/evidence/{evidence_id}?msg=demo-restored", status_code=status.HTTP_302_FOUND)
    except HTTPException as e:
        return RedirectResponse(url=f"/evidence/{evidence_id}?msg=error-{e.status_code}", status_code=status.HTTP_302_FOUND)
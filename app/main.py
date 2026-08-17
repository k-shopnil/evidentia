from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from app.config import settings
from app.database import init_db
from app.templating import templates
from app.security.rate_limit import limiter
from app.security.auth import get_current_user
from app.routers import auth, cases, evidence, audit, admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    description="Secure Digital Evidence Locker",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(auth.router)
app.include_router(cases.router)
app.include_router(evidence.router)
app.include_router(audit.router)
app.include_router(admin.router)


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard")
    return RedirectResponse(url="/login")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")

    from app.services.cases import get_cases
    from app.services.audit import get_audit_logs
    from app.database import get_db_context
    from app.models import Evidence, Case
    from app.security.csrf import get_csrf_token
    from app.security.auth import session_manager

    cases_list = get_cases(user.id, user.role.value)

    with get_db_context() as db:
        evidence_count = db.query(Evidence).join(Case).filter(Case.created_by == user.id).count()

    recent_audits, _ = get_audit_logs(user_id=user.id, limit=10)

    session_data = session_manager.get_session_data(request)
    session_id = session_data.get("session_id") if session_data else ""
    csrf_token = get_csrf_token(session_id)

    return templates.TemplateResponse(
        "dashboard/index.html",
        {
            "request": request,
            "user": user,
            "cases": cases_list,
            "evidence_count": evidence_count,
            "recent_audits": recent_audits,
            "csrf_token": csrf_token,
        }
    )


@app.get("/health")
async def health():
    return {"status": "healthy", "app": settings.APP_NAME}
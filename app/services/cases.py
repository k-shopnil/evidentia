from typing import List, Optional
from datetime import datetime, timezone
from app.database import get_db_context
from app.models import Case, CaseStatus, User
from app.services.audit import record_audit
from fastapi import HTTPException, status


def create_case(
    title: str,
    description: Optional[str],
    user_id: int
) -> Case:
    with get_db_context() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        case_count = db.query(Case).filter(Case.created_by == user_id).count()
        case_number = f"CASE-{user_id:04d}-{case_count + 1:04d}"
        
        case = Case(
            case_number=case_number,
            title=title,
            description=description,
            created_by=user_id,
        )
        db.add(case)
        db.flush()
        
        record_audit(
            user_id=user_id,
            action="CASE_CREATED",
            entity_type="Case",
            entity_id=case.id,
            details={
                "case_number": case_number,
                "title": title,
            },
            db=db
        )
        
        db.commit()
        db.refresh(case)
        return case


def get_cases(
    user_id: int,
    user_role: str,
    skip: int = 0,
    limit: int = 50
) -> List[Case]:
    with get_db_context() as db:
        query = db.query(Case)
        
        if user_role != "admin":
            query = query.filter(Case.created_by == user_id)
        
        return query.order_by(Case.created_at.desc()).offset(skip).limit(limit).all()


def get_case_by_id(case_id: int, user_id: int, user_role: str) -> Case:
    with get_db_context() as db:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
        
        if user_role != "admin" and case.created_by != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this case")
        
        return case


def update_case(
    case_id: int,
    title: Optional[str],
    description: Optional[str],
    status: Optional[str],
    user_id: int,
    user_role: str
) -> Case:
    with get_db_context() as db:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
        
        if user_role != "admin" and case.created_by != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to update this case")

        valid_statuses = {s.value for s in CaseStatus}
        if status is not None and status not in valid_statuses:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid status. Allowed: {', '.join(sorted(valid_statuses))}")
        if title is not None and not title.strip():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Title cannot be empty")

        status_enum = CaseStatus(status) if status is not None else None

        changes = {}
        if title is not None and title != case.title:
            changes["title"] = {"old": case.title, "new": title}
            case.title = title
        if description is not None and description != case.description:
            changes["description"] = {"old": case.description, "new": description}
            case.description = description
        if status is not None and status != case.status.value:
            changes["status"] = {"old": case.status.value, "new": status}
            case.status = status_enum
        
        if changes:
            record_audit(
                user_id=user_id,
                action="CASE_UPDATED",
                entity_type="Case",
                entity_id=case.id,
                details={"changes": changes},
                db=db
            )
        
        db.commit()
        db.refresh(case)
        return case


def close_case(case_id: int, user_id: int, user_role: str) -> Case:
    return update_case(case_id, None, None, "closed", user_id, user_role)
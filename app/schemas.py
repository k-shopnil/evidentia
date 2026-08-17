from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List
from datetime import datetime
from app.models import UserRole, CaseStatus


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(..., min_length=12, max_length=128)
    confirm_password: str

    @validator("confirm_password")
    def passwords_match(cls, v, values):
        if "password" in values and v != values["password"]:
            raise ValueError("Passwords do not match")
        return v


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None


class UserResponse(UserBase):
    id: int
    role: UserRole
    totp_enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None


class TokenData(BaseModel):
    username: Optional[str] = None


class CaseBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class CaseCreate(CaseBase):
    pass


class CaseUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[CaseStatus] = None


class CaseResponse(CaseBase):
    id: int
    case_number: str
    status: CaseStatus
    created_by: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class EvidenceBase(BaseModel):
    filename: str
    mime_type: str
    file_size: int


class EvidenceResponse(EvidenceBase):
    id: int
    case_id: int
    stored_filename: str
    sha256_hash: str
    uploaded_by: int
    created_at: datetime

    class Config:
        from_attributes = True


class EvidenceUploadResponse(BaseModel):
    message: str
    evidence: EvidenceResponse


class EvidenceVerifyResponse(BaseModel):
    evidence_id: int
    match: bool
    original_hash: str
    computed_hash: str
    message: str


class AuditLogBase(BaseModel):
    action: str
    entity_type: Optional[str] = None
    entity_id: Optional[int] = None
    details: Optional[str] = None


class AuditLogResponse(AuditLogBase):
    id: int
    user_id: Optional[int]
    timestamp: datetime
    previous_hash: str
    current_hash: str

    class Config:
        from_attributes = True


class AuditVerifyRequest(BaseModel):
    pass


class AuditVerifyResponse(BaseModel):
    valid: bool
    total_records: int
    first_corruption_index: Optional[int] = None
    message: str


class DeviceInfo(BaseModel):
    device_id: str
    device_name: Optional[str] = None
    last_seen: datetime


class TOTPSetupResponse(BaseModel):
    secret: str
    qr_code_url: str


class MessageResponse(BaseModel):
    message: str
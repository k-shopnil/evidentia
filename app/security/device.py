import hashlib
import hmac
import json
from typing import Optional
from app.config import settings
from app.database import get_db_context
from app.models import UserDevice


def generate_device_fingerprint(user_agent: str, accept_language: str, ip: str) -> str:
    data = f"{user_agent}|{accept_language}|{ip}"
    return hashlib.sha256(data.encode()).hexdigest()[:64]


def is_known_device(db, user_id: int, device_id: str) -> bool:
    device = db.query(UserDevice).filter(
        UserDevice.user_id == user_id,
        UserDevice.device_id == device_id
    ).first()
    return device is not None


def register_device(db, user_id: int, device_id: str, device_name: str = None) -> UserDevice:
    device = db.query(UserDevice).filter(
        UserDevice.user_id == user_id,
        UserDevice.device_id == device_id
    ).first()
    
    if device:
        device.last_seen = __import__('datetime').datetime.now(__import__('datetime').timezone.utc)
        if device_name and not device.device_name:
            device.device_name = device_name
    else:
        device = UserDevice(
            user_id=user_id,
            device_id=device_id,
            device_name=device_name
        )
        db.add(device)
    
    db.flush()
    return device


def get_device_info(user_agent: str) -> str:
    if "Mobile" in user_agent:
        return "Mobile Device"
    elif "Tablet" in user_agent:
        return "Tablet"
    else:
        return "Desktop"
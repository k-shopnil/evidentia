from app.config import settings
from app.database import get_db_context
from app.models import User
from app.services.audit import record_audit
from app.services.email import send_new_device_alert, send_sms


def notify_new_device(
    user_id: int,
    device_name: str,
    device_id: str,
    ip: str,
    timestamp: str,
) -> dict:
    with get_db_context() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"delivered": False, "channel": "none", "reason": "user_not_found"}

        channel = "none"
        delivered = False
        reason = ""

        if user.phone and settings.TWILIO_ACCOUNT_SID:
            channel = "sms"
            message = (
                f"[Evidentia] New device login on {user.username}: "
                f"{device_name} at {timestamp}. If this wasn't you, contact your administrator."
            )
            delivered = send_sms(user.phone, message)
            if not delivered:
                reason = "sms_delivery_failed"

        if not delivered:
            channel = "email"
            delivered = send_new_device_alert(user.email, user.username, device_name, device_id, timestamp, ip)
            if not delivered:
                reason = "smtp_not_configured"

        device_id_short = device_id[:16]
        record_audit(
            user_id=user.id,
            action="SECURITY_ALERT_NEW_DEVICE",
            details={
                "channel": "sms" if channel == "sms" and delivered else ("email" if channel == "email" else "unavailable"),
                "delivered": delivered,
                "device_name": device_name,
                "device_id": device_id_short,
                "ip": ip,
                "recipient": user.phone if channel == "sms" and delivered else user.email,
                "reason": reason,
            },
            db=db,
        )

    return {
        "delivered": delivered,
        "channel": channel,
        "reason": reason,
    }
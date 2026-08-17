import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from app.config import settings
from app.services.audit import record_audit


def send_email(to_email: str, subject: str, body: str, is_html: bool = False) -> bool:
    if not settings.SMTP_HOST or not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
        return False
    
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM
        msg["To"] = to_email
        
        if is_html:
            msg.attach(MIMEText(body, "html"))
        else:
            msg.attach(MIMEText(body, "plain"))
        
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            if settings.SMTP_USE_TLS:
                server.starttls()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.send_message(msg)
        
        return True
    except Exception:
        return False


def send_new_device_alert(
    user_email: str,
    username: str,
    device_name: str,
    device_id: str,
    timestamp: str,
    ip: str
) -> bool:
    subject = f"[Sentry] New Device Login Detected"
    
    body = f"""
Security Alert: New Device Login

Hello {username},

A new device was used to access your Sentry account.

Device: {device_name} ({device_id[:16]}...)
Time: {timestamp}
IP Address: {ip}

If this was you, no action is needed. If you don't recognize this device, 
please contact your system administrator immediately.

This is an automated security notification from Sentry.
"""
    
    return send_email(user_email, subject, body)


def send_account_locked_alert(
    user_email: str,
    username: str,
    timestamp: str,
    ip: str
) -> bool:
    subject = f"[Sentry] Account Locked - Too Many Failed Attempts"
    
    body = f"""
Security Alert: Account Locked

Hello {username},

Your Sentry account has been temporarily locked due to too many failed login attempts.

Time: {timestamp}
IP Address: {ip}

The account will unlock automatically after the lockout period expires.
If you did not attempt to log in, please contact your system administrator.

This is an automated security notification from Sentry.
"""
    
    return send_email(user_email, subject, body)
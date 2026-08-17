import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from app.config import settings


def send_email(to_email: str, subject: str, body: str, is_html: bool = False, html_body: Optional[str] = None) -> bool:
    if not settings.SMTP_HOST or not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM
        msg["To"] = to_email

        msg.attach(MIMEText(body, "plain"))
        if is_html:
            msg.attach(MIMEText(html_body or body, "html"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            if settings.SMTP_USE_TLS:
                server.starttls()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.send_message(msg)

        return True
    except Exception:
        return False


def _new_device_html(username: str, device_name: str, device_id: str, timestamp: str, ip: str) -> str:
    device_id_short = device_id[:16]
    return f"""
<div style="background:#0A0A0B;color:#F2F2EE;font-family:Arial,Helvetica,sans-serif;padding:24px;">
  <div style="max-width:520px;margin:0 auto;border:1px solid #212126;border-radius:10px;overflow:hidden;">
    <div style="padding:16px 24px;border-bottom:1px solid #212126;background:#111114;">
      <span style="color:#F8FF20;font-weight:bold;letter-spacing:2px;">EVIDENTIA</span>
      <span style="color:#8B8B94;margin-left:8px;font-size:12px;">SECURITY NOTIFICATION</span>
    </div>
    <div style="padding:24px;">
      <h2 style="color:#F8FF20;font-size:16px;margin:0 0 12px 0;">New device login detected</h2>
      <p style="margin:0 0 16px 0;color:#8B8B94;font-size:13px;">Hello <strong style="color:#F2F2EE;">{username}</strong>, a new device just signed in to your account.</p>
      <table style="width:100%;font-size:13px;border-collapse:collapse;">
        <tr><td style="padding:6px 0;color:#8B8B94;">Device</td><td style="padding:6px 0;text-align:right;color:#F2F2EE;">{device_name} ({device_id_short}...)</td></tr>
        <tr><td style="padding:6px 0;color:#8B8B94;">Time</td><td style="padding:6px 0;text-align:right;color:#F2F2EE;">{timestamp}</td></tr>
        <tr><td style="padding:6px 0;color:#8B8B94;">IP address</td><td style="padding:6px 0;text-align:right;color:#F2F2EE;">{ip}</td></tr>
      </table>
      <p style="margin:16px 0 0 0;color:#8B8B94;font-size:13px;">If this was you, no action is needed. If you don't recognize this device, contact your system administrator immediately.</p>
      <p style="margin:24px 0 0 0;color:#5A5A63;font-size:11px;">Automated security notification from Evidentia. Do not reply.</p>
    </div>
  </div>
</div>
"""


def send_new_device_alert(
    user_email: str,
    username: str,
    device_name: str,
    device_id: str,
    timestamp: str,
    ip: str
) -> bool:
    subject = "[Evidentia] New Device Login Detected"
    device_id_short = device_id[:16]
    body = f"""Security Alert: New Device Login

Hello {username},

A new device was used to access your Evidentia account.

Device: {device_name} ({device_id_short}...)
Time: {timestamp}
IP Address: {ip}

If this was you, no action is needed. If you don't recognize this device,
please contact your system administrator immediately.

This is an automated security notification from Evidentia.
"""
    return send_email(
        user_email,
        subject,
        body,
        is_html=True,
        html_body=_new_device_html(username, device_name, device_id, timestamp, ip),
    )


def send_sms(to_phone: str, message: str) -> bool:
    if not settings.TWILIO_ACCOUNT_SID or not settings.TWILIO_AUTH_TOKEN or not settings.TWILIO_FROM_NUMBER:
        return False

    try:
        from twilio.rest import Client
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        client.messages.create(
            body=message,
            from_=settings.TWILIO_FROM_NUMBER,
            to=to_phone,
        )
        return True
    except Exception:
        return False


def send_account_locked_alert(
    user_email: str,
    username: str,
    timestamp: str,
    ip: str
) -> bool:
    subject = "[Evidentia] Account Locked - Too Many Failed Attempts"

    body = f"""Security Alert: Account Locked

Hello {username},

Your Evidentia account has been temporarily locked due to too many failed login attempts.

Time: {timestamp}
IP Address: {ip}

The account will unlock automatically after the lockout period expires.
If you did not attempt to log in, please contact your system administrator.

This is an automated security notification from Evidentia.
"""

    return send_email(user_email, subject, body)
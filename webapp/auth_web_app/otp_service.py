import os
import hmac
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
from random import SystemRandom

from database import delete_otp, get_otp, save_otp


OTP_VALIDITY_SECONDS = 300
_random = SystemRandom()

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.office365.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", SMTP_USER)


def generate_otp():
    return f"{_random.randint(0, 999999):06d}"


def _send_email_thread(recipient_email: str, otp_code: str):
    """Envoie l'email dans un thread séparé pour ne pas bloquer le serveur."""
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_FROM
        msg["To"] = recipient_email
        msg["Subject"] = "Votre code de vérification SecureAuth"
        body = f"""Bonjour,

Votre code de vérification est :

    {otp_code}

Ce code est valable 5 minutes.

— L'équipe SecureAuth"""
        msg.attach(MIMEText(body, "plain", "utf-8"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=25) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, [recipient_email], msg.as_string())
        print(f"[EMAIL OK] OTP envoyé à {recipient_email}")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")


def send_otp_email(recipient_email: str, otp_code: str) -> bool:
    if not SMTP_USER or not SMTP_PASSWORD:
        print(f"[DEV] OTP pour {recipient_email} : {otp_code}")
        return True

    # Envoi dans un thread séparé pour éviter le timeout gunicorn
    thread = threading.Thread(
        target=_send_email_thread,
        args=(recipient_email, otp_code),
        daemon=True
    )
    thread.start()
    return True


def create_and_store_otp(user_id: int, recipient_email: str):
    otp_code = generate_otp()
    expiration = datetime.now(timezone.utc) + timedelta(seconds=OTP_VALIDITY_SECONDS)
    save_otp(user_id, otp_code, expiration.isoformat())
    send_otp_email(recipient_email, otp_code)
    return True, expiration


def validate_otp(user_id: int, submitted_code: str):
    otp_row = get_otp(user_id)
    if not otp_row:
        return False, "Aucun OTP actif."

    expiration = datetime.fromisoformat(otp_row["expiration_time"])
    now = datetime.now(timezone.utc)

    if now > expiration:
        delete_otp(user_id)
        return False, "OTP expire."

    if not hmac.compare_digest(otp_row["otp_code"], submitted_code):
        return False, "OTP incorrect."

    delete_otp(user_id)
    return True, "OTP valide."

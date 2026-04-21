import os
import hmac
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
from random import SystemRandom

from database import delete_otp, get_otp, save_otp


OTP_VALIDITY_SECONDS = 300  # 5 minutes
_random = SystemRandom()

GMAIL_ADDRESS = os.environ.get("GMAIL_ADDRESS", "robinapimail@gmail.com")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "lwmd iweg zhml eqsh")


def generate_otp():
    return f"{_random.randint(0, 999999):06d}"


def send_otp_email(recipient_email: str, otp_code: str) -> bool:
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Votre code de vérification SecureAuth"
        msg["From"] = GMAIL_ADDRESS
        msg["To"] = recipient_email

        body = f"""Bonjour,

Votre code de vérification à usage unique est :

    {otp_code}

Ce code est valable 5 minutes.

Si vous n'avez pas demandé ce code, ignorez cet email.

— L'équipe SecureAuth
"""
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_ADDRESS, recipient_email, msg.as_string())

        print(f"[OTP] Email envoyé à {recipient_email}")
        return True

    except Exception as e:
        print(f"[OTP ERROR] {e}")
        return False


def create_and_store_otp(user_id: int, recipient_email: str):
    otp_code = generate_otp()
    expiration = datetime.now(timezone.utc) + timedelta(seconds=OTP_VALIDITY_SECONDS)
    save_otp(user_id, otp_code, expiration.isoformat())
    success = send_otp_email(recipient_email, otp_code)
    return success, expiration


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

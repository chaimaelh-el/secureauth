import os
import hmac
import resend
from datetime import datetime, timedelta, timezone
from random import SystemRandom
 
from database import delete_otp, get_otp, save_otp
 
 
OTP_VALIDITY_SECONDS = 300  # 5 minutes
_random = SystemRandom()
 
resend.api_key = os.environ.get("RESEND_API_KEY", "")
 
 
def generate_otp():
    return f"{_random.randint(0, 999999):06d}"
 
 
def send_otp_email(recipient_email: str, otp_code: str) -> bool:
    try:
        resend.Emails.send({
            "from": "onboarding@resend.dev",
            "to": recipient_email,
            "subject": "Votre code de vérification SecureAuth",
            "text": f"""Bonjour,
 
Votre code de vérification à usage unique est :
 
    {otp_code}
 
Ce code est valable 5 minutes.
 
Si vous n'avez pas demandé ce code, ignorez cet email.
 
— L'équipe SecureAuth
"""
        })
        return True
    except Exception as e:
        print(f"[RESEND ERROR] {e}")
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
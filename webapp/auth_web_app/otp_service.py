import os
import hmac
from datetime import datetime, timedelta, timezone
from random import SystemRandom

from database import delete_otp, get_otp, save_otp


OTP_VALIDITY_SECONDS = 300
_random = SystemRandom()


def generate_otp():
    return f"{_random.randint(0, 999999):06d}"


def send_otp_email(recipient_email: str, otp_code: str) -> bool:
    # Affiche le code dans les logs pour la démonstration
    print(f"[OTP] Code pour {recipient_email} : {otp_code}")
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

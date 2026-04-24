import re
import hashlib
import requests
import bleach



WEAK_PASSWORDS = {
    "123456", "12345678", "password", "password123",
    "qwerty", "azerty", "admin", "letmein", "welcome",
    "iloveyou", "sunshine", "monkey", "dragon", "master",
    "abc123", "111111", "123123", "admin123",
}


EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)


USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{3,30}$")



# Nettoyage XSS

def sanitize_input(value: str) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = bleach.clean(value, tags=[], attributes={}, strip=True)
    return cleaned.strip()



def validate_username(username: str):
    if not username:
        return False, "Le nom d'utilisateur est obligatoire."
    if len(username) < 3 or len(username) > 30:
        return False, "Le nom d'utilisateur doit contenir entre 3 et 30 caractères."
    if not USERNAME_REGEX.match(username):
        return False, "Le nom d'utilisateur ne peut contenir que des lettres, chiffres, tirets et underscores."
    return True, "OK"


def validate_email(email: str):
    if not email:
        return False, "L'email est obligatoire."
    if len(email) > 254:
        return False, "L'email est trop long."
    if not EMAIL_REGEX.match(email):
        return False, "Format d'email invalide."
    return True, "OK"


# ─────────────────────────────────────────────
# Have I Been Pwned — vérification des fuites
# ─────────────────────────────────────────────

def is_password_pwned(password: str) -> int:
    """
    Vérifie si le mot de passe a été compromis via Have I Been Pwned.
    Utilise k-Anonymity : seuls les 5 premiers caractères du hash SHA1
    sont envoyés — le mot de passe ne quitte jamais le serveur.
    Retourne le nombre de fois que le mot de passe a été trouvé (0 = sain).
    """
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=3,
            headers={"Add-Padding": "true"},
        )

        if response.status_code != 200:
            return 0  

        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)

        return 0

    except Exception:
        return 0  



def evaluate_password_strength(password: str):
    score = 0
    checks = {
        "length": len(password) >= 12,
        "length_basic": len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[^A-Za-z0-9]", password)),
        "not_weak": password.lower() not in WEAK_PASSWORDS,
        "no_spaces": " " not in password,
    }

    score += 2 if checks["length"] else (1 if checks["length_basic"] else 0)
    score += 1 if checks["uppercase"] else 0
    score += 1 if checks["lowercase"] else 0
    score += 1 if checks["digit"] else 0
    score += 2 if checks["special"] else 0
    score += 1 if checks["not_weak"] else -3

    if score <= 3:
        label = "Faible"
    elif score <= 6:
        label = "Moyen"
    else:
        label = "Fort"

    return score, label, checks


def validate_password(password: str):
    """
    Valide le mot de passe selon les règles de sécurité + Have I Been Pwned.
    Retourne (valid: bool, message: str, strength_label: str).
    """
    score, label, checks = evaluate_password_strength(password)

    if not checks["length_basic"]:
        return False, "Le mot de passe doit contenir au moins 8 caractères.", label
    if not checks["uppercase"]:
        return False, "Le mot de passe doit contenir au moins une majuscule.", label
    if not checks["lowercase"]:
        return False, "Le mot de passe doit contenir au moins une minuscule.", label
    if not checks["digit"]:
        return False, "Le mot de passe doit contenir au moins un chiffre.", label
    if not checks["special"]:
        return False, "Le mot de passe doit contenir au moins un caractère spécial.", label
    if not checks["not_weak"]:
        return False, "Ce mot de passe est trop commun et a été refusé.", "Faible"
    if not checks["no_spaces"]:
        return False, "Le mot de passe ne doit pas contenir d'espaces.", label

  
    pwned_count = is_password_pwned(password)
    if pwned_count > 0:
        return False, f"⚠️ Ce mot de passe existe dans {pwned_count:,} bases de données de hackers. Choisissez-en un autre plus unique.", "Compromis"

    return True, "Mot de passe valide.", label
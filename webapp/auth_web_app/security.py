import re
import bleach
 
 
# --- Mots de passe trop communs ---
WEAK_PASSWORDS = {
    "123456", "12345678", "password", "password123",
    "qwerty", "azerty", "admin", "letmein", "welcome",
    "iloveyou", "sunshine", "monkey", "dragon", "master",
    "abc123", "111111", "123123", "admin123",
}
 
# --- Regex de validation d'email stricte ---
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)
 
# --- Regex username : lettres, chiffres, tirets, underscores, 3-30 caractères ---
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{3,30}$")
 
 
# ─────────────────────────────────────────────
# Nettoyage XSS
# ─────────────────────────────────────────────
 
def sanitize_input(value: str) -> str:
    """
    Nettoie une chaîne pour prévenir les attaques XSS.
    Supprime tous les tags HTML et les attributs dangereux.
    """
    if not isinstance(value, str):
        return ""
    # bleach.clean avec allowed_tags=[] supprime tout le HTML
    cleaned = bleach.clean(value, tags=[], attributes={}, strip=True)
    return cleaned.strip()
 
 
# ─────────────────────────────────────────────
# Validation des champs utilisateur
# ─────────────────────────────────────────────
 
def validate_username(username: str):
    """
    Valide le nom d'utilisateur.
    Retourne (valid: bool, message: str).
    """
    if not username:
        return False, "Le nom d'utilisateur est obligatoire."
    if len(username) < 3 or len(username) > 30:
        return False, "Le nom d'utilisateur doit contenir entre 3 et 30 caractères."
    if not USERNAME_REGEX.match(username):
        return False, "Le nom d'utilisateur ne peut contenir que des lettres, chiffres, tirets et underscores."
    return True, "OK"
 
 
def validate_email(email: str):
    """
    Valide le format de l'email.
    Retourne (valid: bool, message: str).
    """
    if not email:
        return False, "L'email est obligatoire."
    if len(email) > 254:
        return False, "L'email est trop long."
    if not EMAIL_REGEX.match(email):
        return False, "Format d'email invalide."
    return True, "OK"
 
 
# ─────────────────────────────────────────────
# Force du mot de passe
# ─────────────────────────────────────────────
 
def evaluate_password_strength(password: str):
    score = 0
    checks = {
        "length": len(password) >= 12,          # Augmenté à 12 (plus sécurisé)
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
    Valide le mot de passe selon les règles de sécurité.
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
 
    return True, "Mot de passe valide.", label
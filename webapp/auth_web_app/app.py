import os
from datetime import datetime, timezone
from pathlib import Path
 
import bcrypt
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
 
from database import (
    create_tables,
    add_user,
    get_recent_logs,
    get_user,
    get_user_by_email,
    get_user_by_id,
    update_failed_attempts,
    save_log,
)
from otp_service import OTP_VALIDITY_SECONDS, create_and_store_otp, validate_otp
from security import (
    evaluate_password_strength,
    sanitize_input,
    validate_email,
    validate_password,
    validate_username,
)
 
 
BASE_DIR = Path(__file__).resolve().parent
 
app = Flask(__name__)
 
# ─────────────────────────────────────────────
# Configuration de base
# ─────────────────────────────────────────────
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("La variable d'environnement SECRET_KEY doit être définie.")
 
app.config["SESSION_COOKIE_HTTPONLY"] = True   # Inaccessible au JS
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Protection CSRF basique
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
 
# ─────────────────────────────────────────────
# En-têtes de sécurité HTTP (CSP, HSTS, X-Frame, etc.)
# ─────────────────────────────────────────────
csp = {
    "default-src": "'self'",
    "script-src": "'self'",
    "style-src": ["'self'", "'unsafe-inline'"],  # à restreindre si possible
    "img-src": "'self' data:",
    "font-src": "'self'",
    "object-src": "'none'",
    "base-uri": "'self'",
    "form-action": "'self'",
}
 
Talisman(
    app,
    content_security_policy=csp,
    force_https=os.environ.get("FLASK_ENV") == "production",
    strict_transport_security=True,
    session_cookie_secure=os.environ.get("FLASK_ENV") == "production",
    x_content_type_options=True,
    x_xss_protection=True,
    referrer_policy="no-referrer",
)
 
# ─────────────────────────────────────────────
# Rate Limiting (anti brute-force)
# ─────────────────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)
 
# ─────────────────────────────────────────────
# Rôle admin (à définir en variable d'environnement)
# ─────────────────────────────────────────────
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
 
 
def current_user():
    user_id = session.get("authenticated_user_id")
    if not user_id:
        return None
    return get_user_by_id(user_id)
 
 
def is_admin(user):
    """Vérifie si l'utilisateur connecté est administrateur."""
    return user is not None and user["username"] == ADMIN_USERNAME
 
 
# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
 
@app.route("/")
def index():
    return render_template("index.html", user=current_user())
 
 
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def register():
    if request.method == "POST":
        # Nettoyage XSS
        username = sanitize_input(request.form.get("username", ""))
        email = sanitize_input(request.form.get("email", "")).lower()
        password = request.form.get("password", "")  # Pas de sanitize sur mot de passe
 
        if not username or not email or not password:
            flash("Tous les champs sont obligatoires.", "error")
            return redirect(url_for("register"))
 
        # Validation username
        valid_u, msg_u = validate_username(username)
        if not valid_u:
            flash(msg_u, "error")
            return redirect(url_for("register"))
 
        # Validation email
        valid_e, msg_e = validate_email(email)
        if not valid_e:
            flash(msg_e, "error")
            return redirect(url_for("register"))
 
        if get_user(username):
            flash("Ce nom d'utilisateur existe déjà.", "error")
            return redirect(url_for("register"))
 
        if get_user_by_email(email):
            flash("Cet email est déjà utilisé.", "error")
            return redirect(url_for("register"))
 
        valid, message, strength = validate_password(password)
        if not valid:
            flash(f"{message} Niveau détecté : {strength}.", "error")
            return redirect(url_for("register"))
 
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
        user_id = add_user(username, email, password_hash)
        save_log(user_id, "register", "success", "Compte créé avec succès.")
        flash("Compte créé. Vous pouvez maintenant vous connecter.", "success")
        return redirect(url_for("login"))
 
    return render_template("register.html", user=current_user())
 
 
@app.route("/api/password-check", methods=["POST"])
@limiter.limit("30 per minute")
def password_check():
    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    if not isinstance(password, str) or len(password) > 256:
        return {"valid": False, "message": "Requête invalide.", "strength": "Faible", "score": 0, "checks": {}}
    valid, message, strength = validate_password(password)
    score, _, checks = evaluate_password_strength(password)
    return {
        "valid": valid,
        "message": message,
        "strength": strength,
        "score": score,
        "checks": checks,
    }
 
 
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # Anti brute-force global par IP
def login():
    if request.method == "POST":
        # Nettoyage XSS du champ username (pas du mot de passe)
        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")
 
        # Longueur max pour éviter les attaques DoS via bcrypt
        if len(password) > 128:
            flash("Identifiants invalides.", "error")
            return redirect(url_for("login"))
 
        user = get_user(username)
 
        # Réponse identique que l'utilisateur existe ou non (anti-énumération)
        if not user:
            save_log(None, "login", "failed", f"Tentative sur utilisateur inconnu.")
            flash("Identifiants invalides.", "error")
            return redirect(url_for("login"))
 
        if user["is_blocked"]:
            save_log(user["id"], "login", "blocked", "Compte bloqué - trop d'essais.")
            flash("Compte bloqué après 3 tentatives échouées. Contactez l'administrateur.", "error")
            return redirect(url_for("login"))
 
        password_ok = bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8"))
        if not password_ok:
            failed_attempts = user["failed_attempts"] + 1
            blocked = failed_attempts >= 3
            update_failed_attempts(user["id"], failed_attempts, blocked)
            status = "blocked" if blocked else "failed"
            save_log(user["id"], "login", status, f"Échec {failed_attempts}/3.")
            flash("Identifiants invalides." if not blocked else "Compte bloqué après 3 tentatives.", "error")
            return redirect(url_for("login"))
 
        update_failed_attempts(user["id"], 0, False)
 
        # Envoi OTP par email
        email = user["email"]
        success, expiration = create_and_store_otp(user["id"], email)
 
        # On stocke UNIQUEMENT l'ID et l'expiration, JAMAIS le code OTP en session
        session["pending_otp_user_id"] = user["id"]
        session["otp_expires_at"] = expiration.isoformat()
 
        if not success:
            save_log(user["id"], "otp", "email_error", "Échec d'envoi de l'OTP par email.")
            flash("Erreur lors de l'envoi du code OTP. Veuillez réessayer.", "error")
            return redirect(url_for("login"))
 
        save_log(user["id"], "login", "pending_otp", "Mot de passe correct. OTP envoyé par email.")
        flash(f"Un code de vérification a été envoyé à votre adresse email.", "success")
        return redirect(url_for("otp"))
 
    return render_template("login.html", user=current_user())
 
 
@app.route("/otp", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def otp():
    pending_user_id = session.get("pending_otp_user_id")
    if not pending_user_id:
        flash("Aucune vérification OTP en attente.", "error")
        return redirect(url_for("login"))
 
    if request.method == "POST":
        otp_code = sanitize_input(request.form.get("otp_code", ""))
 
        # Validation format (6 chiffres exactement)
        if not otp_code.isdigit() or len(otp_code) != 6:
            flash("Le code OTP doit contenir exactement 6 chiffres.", "error")
            return redirect(url_for("otp"))
 
        valid, message = validate_otp(pending_user_id, otp_code)
 
        if not valid:
            if message in ("OTP expire.", "Aucun OTP actif."):
                session.pop("pending_otp_user_id", None)
                session.pop("otp_expires_at", None)
                save_log(pending_user_id, "otp", "expired", message)
                flash("OTP expiré. Reconnectez-vous pour recevoir un nouveau code.", "error")
                return redirect(url_for("login"))
            else:
                save_log(pending_user_id, "otp", "failed", "Code OTP incorrect.")
            flash("Code OTP incorrect.", "error")
            return redirect(url_for("otp"))
 
        session.pop("pending_otp_user_id", None)
        session.pop("otp_expires_at", None)
        session["authenticated_user_id"] = pending_user_id
        save_log(pending_user_id, "otp", "success", "Double authentification validée.")
        flash("Connexion réussie avec double authentification.", "success")
        return redirect(url_for("dashboard"))
 
    expires_at = session.get("otp_expires_at")
    remaining_seconds = OTP_VALIDITY_SECONDS
    if expires_at:
        expiration = datetime.fromisoformat(expires_at)
        remaining_seconds = max(0, int((expiration - datetime.now(timezone.utc)).total_seconds()))
 
    return render_template(
        "otp.html",
        user=current_user(),
        remaining_seconds=remaining_seconds,
        # ⚠️ Plus de demo_otp : le code n'est JAMAIS transmis au template
    )
 
 
@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        flash("Connectez-vous pour accéder au tableau de bord.", "error")
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user)
 
 
@app.route("/logs")
def logs():
    """
    Page des logs réservée aux administrateurs uniquement.
    Un utilisateur normal reçoit une erreur 403.
    """
    user = current_user()
    if not user:
        flash("Connectez-vous pour consulter les logs.", "error")
        return redirect(url_for("login"))
 
    if not is_admin(user):
        save_log(user["id"], "logs", "unauthorized", "Tentative d'accès non autorisé aux logs.")
        abort(403)
 
    return render_template("logs.html", user=user, logs=get_recent_logs())
 
 
@app.route("/logout")
def logout():
    user_id = session.get("authenticated_user_id")
    if user_id:
        save_log(user_id, "logout", "success", "Déconnexion utilisateur.")
    session.clear()
    flash("Session terminée.", "success")
    return redirect(url_for("index"))
 
 
# ─────────────────────────────────────────────
# Gestionnaires d'erreurs personnalisés
# ─────────────────────────────────────────────
 
@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403
 
 
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404
 
 
@app.errorhandler(429)
def rate_limit_exceeded(e):
    flash("Trop de tentatives. Veuillez patienter avant de réessayer.", "error")
    return render_template("429.html"), 429
 
 
# ─────────────────────────────────────────────
# Démarrage
# ─────────────────────────────────────────────
 
if __name__ == "__main__":
    create_tables()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
 
 
create_tables()
 
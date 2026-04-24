import os
import secrets
import requests as http_requests
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from dotenv import load_dotenv
load_dotenv()

from database import (
    create_tables,
    add_user,
    get_recent_logs,
    get_user,
    get_user_by_email,
    get_user_by_id,
    update_failed_attempts,
    update_password,
    save_log,
    save_reset_token,
    get_reset_token,
    mark_reset_token_used,
)
from otp_service import OTP_VALIDITY_SECONDS, create_and_store_otp, validate_otp, send_otp_email
from security import (
    evaluate_password_strength,
    sanitize_input,
    validate_email,
    validate_password,
    validate_username,
)

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev_local_key_123")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"

RECAPTCHA_SITE_KEY = os.environ.get("RECAPTCHA_SITE_KEY", "6LdoUsQsAAAAAA9Doic9ocT2vtKJR_YlH-ynWEEz")
RECAPTCHA_SECRET_KEY = os.environ.get("RECAPTCHA_SECRET_KEY", "6LdoUsQsAAAAALO0H7F1KDfxw5WKEONXDefqvErL")

csp = {
    "default-src": "'self'",
    "script-src": ["'self'", "https://www.google.com", "https://www.gstatic.com"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:", "https://www.gstatic.com"],
    "font-src": ["'self'", "https://fonts.gstatic.com"],
    "frame-src": "https://www.google.com",
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

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
RESET_TOKEN_VALIDITY_SECONDS = 900


def current_user():
    user_id = session.get("authenticated_user_id")
    if not user_id:
        return None
    return get_user_by_id(user_id)


def is_admin(user):
    return user is not None and user["username"] == ADMIN_USERNAME


def verify_recaptcha(token):
    """Vérifie le token reCAPTCHA auprès de Google."""
    try:
        resp = http_requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": RECAPTCHA_SECRET_KEY, "response": token},
            timeout=5,
        )
        result = resp.json()
        return result.get("success", False)
    except Exception:
        return False


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
        # Vérification CAPTCHA
        captcha_token = request.form.get("g-recaptcha-response", "")
        if not verify_recaptcha(captcha_token):
            flash("Veuillez valider le CAPTCHA.", "error")
            return redirect(url_for("register"))

        username = sanitize_input(request.form.get("username", ""))
        email = sanitize_input(request.form.get("email", "")).lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("Tous les champs sont obligatoires.", "error")
            return redirect(url_for("register"))

        valid_u, msg_u = validate_username(username)
        if not valid_u:
            flash(msg_u, "error")
            return redirect(url_for("register"))

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

    return render_template("register.html", user=current_user(), recaptcha_site_key=RECAPTCHA_SITE_KEY)


@app.route("/api/password-check", methods=["POST"])
@limiter.limit("30 per minute")
def password_check():
    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    if not isinstance(password, str) or len(password) > 256:
        return {"valid": False, "message": "Requête invalide.", "strength": "Faible", "score": 0, "checks": {}}
    valid, message, strength = validate_password(password)
    score, _, checks = evaluate_password_strength(password)
    return {"valid": valid, "message": message, "strength": strength, "score": score, "checks": checks}


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        # Vérification CAPTCHA
        captcha_token = request.form.get("g-recaptcha-response", "")
        if not verify_recaptcha(captcha_token):
            flash("Veuillez valider le CAPTCHA.", "error")
            return redirect(url_for("login"))

        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")

        if len(password) > 128:
            flash("Identifiants invalides.", "error")
            return redirect(url_for("login"))

        user = get_user(username)

        if not user:
            save_log(None, "login", "failed", "Tentative sur utilisateur inconnu.")
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

        email = user["email"]
        success, expiration = create_and_store_otp(user["id"], email)

        session["pending_otp_user_id"] = user["id"]
        session["otp_expires_at"] = expiration.isoformat()

        if not success:
            save_log(user["id"], "otp", "email_error", "Échec d'envoi de l'OTP par email.")
            flash("Erreur lors de l'envoi du code OTP. Veuillez réessayer.", "error")
            return redirect(url_for("login"))

        save_log(user["id"], "login", "pending_otp", "Mot de passe correct. OTP envoyé par email.")
        flash("Un code de vérification a été envoyé à votre adresse email.", "success")
        return redirect(url_for("otp"))

    return render_template("login.html", user=current_user(), recaptcha_site_key=RECAPTCHA_SITE_KEY)


@app.route("/otp", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def otp():
    pending_user_id = session.get("pending_otp_user_id")
    if not pending_user_id:
        flash("Aucune vérification OTP en attente.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_code = sanitize_input(request.form.get("otp_code", ""))

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

    return render_template("otp.html", user=current_user(), remaining_seconds=remaining_seconds)


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def forgot_password():
    if request.method == "POST":
        email = sanitize_input(request.form.get("email", "")).lower()

        if not email:
            flash("L'email est obligatoire.", "error")
            return redirect(url_for("forgot_password"))

        valid_e, msg_e = validate_email(email)
        if not valid_e:
            flash(msg_e, "error")
            return redirect(url_for("forgot_password"))

        user = get_user_by_email(email)

        if user:
            token = secrets.token_urlsafe(32)
            expiration = datetime.now(timezone.utc) + timedelta(seconds=RESET_TOKEN_VALIDITY_SECONDS)
            save_reset_token(user["id"], token, expiration.isoformat())
            reset_link = url_for("reset_password", token=token, _external=True)
            subject = "Réinitialisation de votre mot de passe SecureAuth"
            body = f"""Bonjour {user["username"]},

Vous avez demandé la réinitialisation de votre mot de passe.

Cliquez sur ce lien pour créer un nouveau mot de passe :

    {reset_link}

Ce lien est valable 15 minutes.

Si vous n'avez pas fait cette demande, ignorez cet email.

— L'équipe SecureAuth
"""
            send_otp_email(email, body, subject=subject)
            save_log(user["id"], "forgot_password", "success", "Lien de réinitialisation envoyé.")

        flash("Si cet email existe, un lien de réinitialisation a été envoyé.", "success")
        return redirect(url_for("login"))

    return render_template("forgot_password.html", user=current_user())


@app.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def reset_password(token):
    token_row = get_reset_token(token)

    if not token_row:
        flash("Lien invalide ou expiré.", "error")
        return redirect(url_for("forgot_password"))

    if token_row["used"]:
        flash("Ce lien a déjà été utilisé.", "error")
        return redirect(url_for("forgot_password"))

    expiration = datetime.fromisoformat(token_row["expiration_time"])
    if datetime.now(timezone.utc) > expiration:
        flash("Lien expiré. Veuillez faire une nouvelle demande.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if password != confirm:
            flash("Les mots de passe ne correspondent pas.", "error")
            return redirect(url_for("reset_password", token=token))

        valid, message, strength = validate_password(password)
        if not valid:
            flash(f"{message} Niveau détecté : {strength}.", "error")
            return redirect(url_for("reset_password", token=token))

        new_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
        update_password(token_row["user_id"], new_hash)
        mark_reset_token_used(token)
        save_log(token_row["user_id"], "reset_password", "success", "Mot de passe réinitialisé.")
        flash("Mot de passe réinitialisé avec succès. Vous pouvez vous connecter.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", user=current_user(), token=token)


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        flash("Connectez-vous pour accéder au tableau de bord.", "error")
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user)


@app.route("/logs")
def logs():
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


if __name__ == "__main__":
    create_tables()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)


create_tables()
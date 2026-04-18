# SecureAuth Web App

Application web d'authentification securisee en Python, HTML, CSS et JavaScript.

## Fonctionnalites

- Base SQLite avec tables `users`, `otp_codes` et `logs`
- Inscription avec verification de robustesse du mot de passe
- Hash des mots de passe avec `bcrypt`
- Connexion avec blocage automatique apres 3 echecs
- OTP a 6 chiffres avec expiration en 30 secondes
- Journalisation des actions de securite

## Lancement

```bash
cd auth_web_app
python3 -m pip install -r requirements.txt
python3 app.py
```

Puis ouvrir `http://127.0.0.1:5000`.

## Deploiement Railway

Le repo est prepare pour Railway avec les fichiers racine `requirements.txt`, `Procfile` et `runtime.txt`.

- Root Directory: laisser vide
- Build Command: laisser vide en general
- Start Command: laisser vide en general

Si vous voulez forcer la commande de demarrage manuellement:

```bash
cd auth_web_app && gunicorn --bind 0.0.0.0:$PORT app:app
```

## Notes

- L'OTP est affiche dans l'interface pour une demonstration locale. En production, il faudrait l'envoyer par email ou SMS.
- Changez `SECRET_KEY` dans `app.py` avant tout usage reel.
- SQLite sur Railway n'est pas persistant sur le long terme. Pour un vrai deploiement, il faut migrer vers PostgreSQL ou un volume persistant.

# Rapport de Projet

## Architecture

Le projet est separe en modules clairs:

- `app.py`: routes Flask, orchestration inscription, connexion, OTP et session
- `database.py`: creation SQLite et acces aux tables
- `security.py`: controle de robustesse des mots de passe
- `otp_service.py`: generation, expiration et validation OTP
- `templates/` et `static/`: interface web HTML/CSS/JS

## Choix Techniques

- **Flask** pour un backend simple et lisible
- **SQLite** pour un stockage local facile a presenter
- **bcrypt** pour le hashage securise des mots de passe
- **OTP 6 chiffres** avec expiration courte de 30 secondes

## Mesures de Securite

- Verification stricte du mot de passe
- Refus des mots de passe trop communs
- Hashage des mots de passe avant stockage
- Blocage du compte apres 3 tentatives ratees
- Suppression de l'OTP apres usage
- Logs des incidents: mauvais mot de passe, mauvais OTP, OTP expire, compte bloque

## Limites

- L'OTP est affiche en clair pour la demo
- La cle secrete Flask doit etre externalisee en variable d'environnement
- Le deblocage d'un compte n'est pas automatise

## Presentation

Flux de demonstration conseille:

1. Creer un compte avec un mot de passe faible pour montrer le refus.
2. Creer un compte valide puis se connecter.
3. Entrer un mauvais mot de passe plusieurs fois pour montrer le blocage.
4. Se connecter avec un compte valide, recuperer l'OTP affiche et finaliser la connexion.
5. Montrer la page `Logs` pour prouver la tracabilite.

const passwordInput = document.querySelector("#password-input");
const strengthLabel = document.querySelector("#password-strength-label");
const feedbackLabel = document.querySelector("#password-feedback");
const passwordChecks = document.querySelector("#password-checks");
const passwordToggles = document.querySelectorAll("[data-password-toggle]");
const generateBtn = document.querySelector("#generate-password-btn");

// ─────────────────────────────────────────────
// Générateur de mot de passe sécurisé
// ─────────────────────────────────────────────

function generateSecurePassword() {
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const digits = "0123456789";
    const special = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    const all = upper + lower + digits + special;

    let password = "";
    // Garantir au moins un de chaque catégorie
    password += upper[Math.floor(Math.random() * upper.length)];
    password += lower[Math.floor(Math.random() * lower.length)];
    password += digits[Math.floor(Math.random() * digits.length)];
    password += special[Math.floor(Math.random() * special.length)];

    // Compléter jusqu'à 16 caractères
    for (let i = 4; i < 16; i++) {
        password += all[Math.floor(Math.random() * all.length)];
    }

    // Mélanger les caractères
    return password.split("").sort(() => Math.random() - 0.5).join("");
}

if (generateBtn && passwordInput) {
    generateBtn.addEventListener("click", () => {
        const newPassword = generateSecurePassword();
        passwordInput.value = newPassword;
        passwordInput.type = "text"; // Afficher le mot de passe généré

        // Mettre à jour l'icône du toggle
        const toggle = passwordInput.closest(".password-field")?.querySelector("[data-password-toggle]");
        if (toggle) {
            const eyeOn = toggle.querySelector(".icon-eye");
            const eyeOff = toggle.querySelector(".icon-eye-off");
            if (eyeOn) eyeOn.style.display = "none";
            if (eyeOff) eyeOff.style.display = "block";
            toggle.setAttribute("aria-pressed", "true");
        }

        // Lancer l'analyse du mot de passe généré
        updatePasswordFeedback(newPassword);

        // Copier dans le presse-papier
        navigator.clipboard.writeText(newPassword).then(() => {
            generateBtn.textContent = "✅ Copié !";
            setTimeout(() => {
                generateBtn.textContent = "🔑 Générer un mot de passe sécurisé";
            }, 2000);
        }).catch(() => {
            generateBtn.textContent = "🔑 Générer un mot de passe sécurisé";
        });
    });
}

// ─────────────────────────────────────────────
// Analyse du mot de passe en temps réel
// ─────────────────────────────────────────────

async function updatePasswordFeedback(password) {
    if (!passwordInput || !strengthLabel || !feedbackLabel || !passwordChecks) {
        return;
    }

    if (!password) {
        strengthLabel.textContent = "Niveau: en attente";
        feedbackLabel.textContent = "Saisissez un mot de passe pour lancer la vérification.";
        feedbackLabel.classList.remove("valid", "invalid");
        [...passwordChecks.children].forEach((item) => {
            item.className = "";
        });
        return;
    }

    const response = await fetch("/api/password-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
    });

    const data = await response.json();
    strengthLabel.textContent = `Niveau: ${data.strength}`;
    feedbackLabel.textContent = data.message;
    feedbackLabel.classList.remove("valid", "invalid");
    feedbackLabel.classList.add(data.valid ? "valid" : "invalid");

    const checkState = [
        data.checks.length_basic,
        data.checks.uppercase,
        data.checks.lowercase,
        data.checks.digit,
        data.checks.special,
    ];

    [...passwordChecks.children].forEach((item, index) => {
        item.className = checkState[index] ? "valid" : "invalid";
    });
}

if (passwordInput) {
    passwordInput.addEventListener("input", (event) => {
        updatePasswordFeedback(event.target.value);
    });
}

// ─────────────────────────────────────────────
// Toggle afficher/masquer mot de passe
// ─────────────────────────────────────────────

passwordToggles.forEach((toggle) => {
    const passwordField = toggle.closest(".password-field");
    const input = passwordField?.querySelector("input");
    const eyeOn = toggle.querySelector(".icon-eye");
    const eyeOff = toggle.querySelector(".icon-eye-off");

    if (!input) return;

    toggle.addEventListener("click", () => {
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        if (eyeOn) eyeOn.style.display = show ? "none" : "block";
        if (eyeOff) eyeOff.style.display = show ? "block" : "none";
        toggle.setAttribute("aria-label", show ? "Masquer le mot de passe" : "Afficher le mot de passe");
        toggle.setAttribute("aria-pressed", show ? "true" : "false");
    });
});

// ─────────────────────────────────────────────
// Countdown OTP
// ─────────────────────────────────────────────

const countdown = document.querySelector(".countdown");
const countdownValue = document.querySelector("#countdown-value");

if (countdown && countdownValue) {
    let remaining = Number(countdown.dataset.remaining || "0");
    const timer = window.setInterval(() => {
        remaining -= 1;
        countdownValue.textContent = String(Math.max(remaining, 0));
        if (remaining <= 0) {
            countdown.textContent = "Temps restant: 0 seconde. Le code est probablement expiré.";
            window.clearInterval(timer);
        }
    }, 1000);
}
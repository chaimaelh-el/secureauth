const passwordInput = document.querySelector("#password-input");
const strengthLabel = document.querySelector("#password-strength-label");
const feedbackLabel = document.querySelector("#password-feedback");
const passwordChecks = document.querySelector("#password-checks");
const passwordToggles = document.querySelectorAll("[data-password-toggle]");

async function updatePasswordFeedback(password) {
    if (!passwordInput || !strengthLabel || !feedbackLabel || !passwordChecks) {
        return;
    }

    if (!password) {
        strengthLabel.textContent = "Niveau: en attente";
        feedbackLabel.textContent = "Saisissez un mot de passe pour lancer la verification.";
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
        data.checks.length,
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

passwordToggles.forEach((toggle) => {
    const passwordField = toggle.closest(".password-field");
    const input = passwordField?.querySelector("input");

    if (!input) {
        return;
    }

    toggle.addEventListener("click", () => {
        const shouldShowPassword = input.type === "password";
        input.type = shouldShowPassword ? "text" : "password";
        toggle.setAttribute(
            "aria-label",
            shouldShowPassword ? "Masquer le mot de passe" : "Afficher le mot de passe",
        );
        toggle.setAttribute("aria-pressed", shouldShowPassword ? "true" : "false");
        toggle.classList.toggle("is-visible", shouldShowPassword);
    });
});

const countdown = document.querySelector(".countdown");
const countdownValue = document.querySelector("#countdown-value");

if (countdown && countdownValue) {
    let remaining = Number(countdown.dataset.remaining || "0");
    const timer = window.setInterval(() => {
        remaining -= 1;
        countdownValue.textContent = String(Math.max(remaining, 0));
        if (remaining <= 0) {
            countdown.textContent = "Temps restant: 0 seconde. Le code est probablement expire.";
            window.clearInterval(timer);
        }
    }, 1000);
}

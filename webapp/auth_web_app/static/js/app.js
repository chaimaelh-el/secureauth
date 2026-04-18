const passwordInput = document.querySelector("#password-input");
const strengthLabel = document.querySelector("#password-strength-label");
const feedbackLabel = document.querySelector("#password-feedback");
const passwordChecks = document.querySelector("#password-checks");

async function updatePasswordFeedback(password) {
    if (!passwordInput || !strengthLabel || !feedbackLabel || !passwordChecks) {
        return;
    }

    if (!password) {
        strengthLabel.textContent = "Niveau: en attente";
        feedbackLabel.textContent = "Saisissez un mot de passe pour lancer la verification.";
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

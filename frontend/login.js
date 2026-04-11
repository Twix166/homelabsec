const loginForm = document.getElementById("login-form");
const usernameInput = document.getElementById("login-username");
const passwordInput = document.getElementById("login-password");
const submitButton = document.getElementById("login-submit");
const errorBox = document.getElementById("login-error");

function nextTarget() {
  const params = new URLSearchParams(window.location.search);
  return params.get("next") || "/";
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  submitButton.disabled = true;
  submitButton.textContent = "Signing in";

  try {
    await window.HomelabSecAuth.apiJson("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: usernameInput.value,
        password: passwordInput.value,
      }),
    }, true);
    window.location.href = nextTarget();
  } catch (error) {
    errorBox.hidden = false;
    errorBox.textContent = `Sign-in failed: ${error.message}`;
    submitButton.disabled = false;
    submitButton.textContent = "Sign in";
  }
});

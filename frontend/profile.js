const profileForm = document.getElementById("profile-form");
const profileMessage = document.getElementById("profile-message");

async function initProfile() {
  const user = await window.HomelabSecAuth.requireUser();
  window.HomelabSecAuth.mountHeaderNav(document.getElementById("page-nav"), user, "");
  window.HomelabSecAuth.mountProfileMenu(document.getElementById("profile-menu"), user);
  document.getElementById("profile-display-name").value = user.display_name || "";
  document.getElementById("profile-email").value = user.email || "";
}

profileForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  profileMessage.hidden = true;

  const payload = {
    display_name: document.getElementById("profile-display-name").value,
    email: document.getElementById("profile-email").value,
  };

  const currentPassword = document.getElementById("profile-current-password").value;
  const newPassword = document.getElementById("profile-new-password").value;
  if (currentPassword || newPassword) {
    payload.current_password = currentPassword;
    payload.new_password = newPassword;
  }

  try {
    const response = await window.HomelabSecAuth.apiJson("/api/auth/me", {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    window.HomelabSecAuth.mountProfileMenu(document.getElementById("profile-menu"), response.user);
    profileMessage.hidden = false;
    profileMessage.className = "empty-state auth-success";
    profileMessage.textContent = "Profile updated.";
    document.getElementById("profile-current-password").value = "";
    document.getElementById("profile-new-password").value = "";
  } catch (error) {
    profileMessage.hidden = false;
    profileMessage.className = "empty-state auth-error";
    profileMessage.textContent = `Failed to update profile: ${error.message}`;
  }
});

initProfile().catch((error) => {
  profileMessage.hidden = false;
  profileMessage.className = "empty-state auth-error";
  profileMessage.textContent = `Failed to load profile: ${error.message}`;
});

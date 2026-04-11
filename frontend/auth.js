(function () {
  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function nextUrl() {
    return `${window.location.pathname}${window.location.search}${window.location.hash}`;
  }

  function redirectToLogin() {
    const target = encodeURIComponent(nextUrl());
    window.location.href = `/login.html?next=${target}`;
  }

  async function apiJson(url, options = {}, allowUnauthorized = false) {
    const response = await fetch(url, {
      credentials: "same-origin",
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });

    if (response.status === 401) {
      if (!allowUnauthorized) {
        redirectToLogin();
      }
      throw new Error("401 Unauthorized");
    }

    if (!response.ok) {
      let detail = `${response.status} ${response.statusText}`;
      try {
        const payload = await response.json();
        detail = payload.detail || detail;
      } catch (_) {
        // keep status detail
      }
      throw new Error(detail);
    }

    return response.json();
  }

  async function requireUser({ admin = false } = {}) {
    const payload = await apiJson("/api/auth/me", {}, true).catch(() => null);
    if (!payload || !payload.user) {
      redirectToLogin();
      throw new Error("Authentication required");
    }
    if (admin && payload.user.role !== "admin") {
      window.location.href = "/";
      throw new Error("Admin access required");
    }
    return payload.user;
  }

  function mountHeaderNav(container, user, current = "") {
    if (!container || !user) {
      return;
    }

    const items = [
      { href: "/", label: "Dashboard", key: "dashboard", allowed: true },
      { href: "/admin.html", label: "Admin", key: "admin", allowed: user.role === "admin" },
    ].filter((item) => item.allowed);

    container.innerHTML = `
      <nav class="header-nav" aria-label="Primary">
        ${items
          .map(
            (item) =>
              `<a class="filter-button ${item.key === current ? "is-active" : ""}" href="${item.href}">${item.label}</a>`
          )
          .join("")}
      </nav>
    `;
  }

  function mountProfileMenu(container, user) {
    if (!container || !user) {
      return;
    }

    container.innerHTML = `
      <div class="profile-menu-shell">
        <button id="profile-menu-button" class="profile-button" type="button" aria-haspopup="menu" aria-expanded="false">
          <span class="profile-avatar">${escapeHtml((user.display_name || user.username).slice(0, 1).toUpperCase())}</span>
          <span class="profile-meta">
            <strong>${escapeHtml(user.display_name || user.username)}</strong>
            <span>${escapeHtml(user.role)}</span>
          </span>
        </button>
        <div id="profile-menu-dropdown" class="profile-dropdown" role="menu">
          <a href="/profile.html" role="menuitem">Edit profile</a>
          ${user.role === "admin" ? '<a href="/admin.html" role="menuitem">Admin console</a>' : ""}
          <button id="profile-sign-out" type="button" role="menuitem">Sign out</button>
        </div>
      </div>
    `;

    const button = container.querySelector("#profile-menu-button");
    const dropdown = container.querySelector("#profile-menu-dropdown");
    const signOutButton = container.querySelector("#profile-sign-out");

    const closeMenu = () => {
      button.setAttribute("aria-expanded", "false");
      dropdown.classList.remove("is-open");
    };

    button.addEventListener("click", () => {
      const nextState = !dropdown.classList.contains("is-open");
      button.setAttribute("aria-expanded", nextState ? "true" : "false");
      dropdown.classList.toggle("is-open", nextState);
    });

    document.addEventListener("click", (event) => {
      if (!container.contains(event.target)) {
        closeMenu();
      }
    });

    signOutButton.addEventListener("click", async () => {
      await apiJson("/api/auth/logout", { method: "POST", body: "{}" }).catch(() => null);
      window.location.href = "/login.html";
    });
  }

  window.HomelabSecAuth = {
    apiJson,
    escapeHtml,
    requireUser,
    mountHeaderNav,
    mountProfileMenu,
  };
})();

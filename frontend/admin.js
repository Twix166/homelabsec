const moduleList = document.getElementById("module-list");
const sourceList = document.getElementById("source-list");
const userList = document.getElementById("user-list");
const createUserForm = document.getElementById("create-user-form");
const userMessage = document.getElementById("user-message");
const adminStatus = document.getElementById("admin-status");

function escapeHtml(value) {
  return window.HomelabSecAuth.escapeHtml(value);
}

function renderToggleCard(item, type) {
  const key = type === "module" ? item.module_key : item.source_key;
  const label = type === "module" ? item.display_name : item.display_name;
  const description = item.description || "";
  const metadata = type === "module" ? key : `${item.source_kind} · ${key}`;
  return `
    <article class="list-card admin-console-card">
      <div class="list-topline">
        <div class="list-title">${escapeHtml(label)}</div>
        <button class="filter-button toggle-button ${item.enabled ? "is-active" : ""}" data-type="${type}" data-key="${escapeHtml(key)}" type="button">
          ${item.enabled ? "Enabled" : "Disabled"}
        </button>
      </div>
      <div class="list-meta">
        <span>${escapeHtml(metadata)}</span>
        <span>${escapeHtml(description)}</span>
      </div>
    </article>
  `;
}

function renderUserCard(user) {
  return `
    <article class="list-card admin-console-card">
      <div class="list-topline">
        <div class="list-title">${escapeHtml(user.display_name || user.username)}</div>
        <span class="pill ${user.role === "admin" ? "notable" : ""}">${escapeHtml(user.role)}</span>
      </div>
      <div class="list-meta">
        <span>${escapeHtml(user.username)}</span>
        <span>${escapeHtml(user.email || "no email")}</span>
        <span>${user.is_active ? "active" : "disabled"}</span>
        <span>${escapeHtml(user.last_login_at || "never signed in")}</span>
      </div>
      <div class="admin-user-actions">
        <button class="filter-button toggle-user-button ${user.is_active ? "is-active" : ""}" data-user-id="${escapeHtml(user.user_id)}" data-active="${user.is_active ? "true" : "false"}" type="button">
          ${user.is_active ? "Disable" : "Enable"}
        </button>
      </div>
    </article>
  `;
}

function formatDate(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function buildQuickLinks() {
  const { protocol, hostname, origin } = window.location;
  const links = [
    { label: "Dashboard", href: origin.replace("/admin.html", "/") },
    { label: "API health", href: `${protocol}//${hostname}:8088/health` },
    { label: "Prometheus", href: "http://127.0.0.1:9090" },
    { label: "Grafana", href: "http://127.0.0.1:3001" },
    { label: "Alertmanager", href: "http://127.0.0.1:9093" },
  ];
  if (hostname === "localhost" || hostname === "127.0.0.1") {
    links.push({ label: "Secure edge", href: "https://localhost:18443" });
  }
  return links;
}

function renderAdminStatus(status) {
  const freshness = status.scheduler_freshness || {};
  const summary = status.summary || {};
  const latestScan = status.latest_scan_run;
  const quickLinks = buildQuickLinks()
    .map((link) => `<a class="pill" href="${escapeHtml(link.href)}" target="_blank" rel="noreferrer">${escapeHtml(link.label)}</a>`)
    .join("");

  adminStatus.innerHTML = `
    <article class="list-card admin-card">
      <div class="admin-header">
        <div>
          <div class="admin-eyebrow">Control plane</div>
          <div class="list-title">API status</div>
        </div>
        <span class="pill status-pill ${freshness.status === "stale" ? "high" : "low"}">${escapeHtml(status.api_status || "unknown")}</span>
      </div>
      <div class="admin-grid">
        <div class="admin-metric">
          <span class="admin-label">Generated</span>
          <strong class="admin-value">${escapeHtml(formatDate(status.generated_at))}</strong>
        </div>
        <div class="admin-metric">
          <span class="admin-label">Scheduler</span>
          <strong class="admin-value">${escapeHtml(freshness.status || "unknown")}</strong>
        </div>
        <div class="admin-metric">
          <span class="admin-label">Stale after</span>
          <strong class="admin-value">${escapeHtml(freshness.stale_after_minutes ?? "-")} min</strong>
        </div>
        <div class="admin-metric">
          <span class="admin-label">Scan age</span>
          <strong class="admin-value">${escapeHtml(freshness.age_minutes ?? "-")} min</strong>
        </div>
      </div>
      <div class="admin-grid admin-grid-compact">
        <div class="admin-metric compact">
          <span class="admin-label">Assets</span>
          <strong class="admin-value">${escapeHtml(summary.assets ?? 0)}</strong>
        </div>
        <div class="admin-metric compact">
          <span class="admin-label">Observations</span>
          <strong class="admin-value">${escapeHtml(summary.network_observations ?? 0)}</strong>
        </div>
        <div class="admin-metric compact">
          <span class="admin-label">Fingerprints</span>
          <strong class="admin-value">${escapeHtml(summary.fingerprints ?? 0)}</strong>
        </div>
      </div>
      ${
        latestScan
          ? `
            <div class="admin-scan">
              <div class="admin-scan-title">Latest scan</div>
              <div class="list-meta">
                <span>${escapeHtml(latestScan.scan_type || "scan")}</span>
                <span>${escapeHtml(latestScan.status || "unknown")}</span>
                <span>${escapeHtml(formatDate(latestScan.completed_at || latestScan.started_at))}</span>
              </div>
              <div class="list-meta mono">
                <span>${escapeHtml(latestScan.scan_run_id)}</span>
              </div>
            </div>
          `
          : '<div class="empty-state">No scan runs recorded yet.</div>'
      }
      <div class="admin-links">${quickLinks}</div>
    </article>
  `;
}

async function loadAdminConsole() {
  const user = await window.HomelabSecAuth.requireUser({ admin: true });
  window.HomelabSecAuth.mountHeaderNav(document.getElementById("page-nav"), user, "admin");
  window.HomelabSecAuth.mountProfileMenu(document.getElementById("profile-menu"), user);

  const [statusPayload, modulesPayload, sourcesPayload, usersPayload] = await Promise.all([
    window.HomelabSecAuth.apiJson("/api/admin/status"),
    window.HomelabSecAuth.apiJson("/api/admin/modules"),
    window.HomelabSecAuth.apiJson("/api/admin/data_sources"),
    window.HomelabSecAuth.apiJson("/api/admin/users"),
  ]);

  renderAdminStatus(statusPayload);
  moduleList.innerHTML = (modulesPayload.modules || []).map((module) => renderToggleCard(module, "module")).join("");
  sourceList.innerHTML = (sourcesPayload.sources || []).map((source) => renderToggleCard(source, "source")).join("");
  userList.innerHTML = (usersPayload.users || []).map(renderUserCard).join("");

  for (const button of document.querySelectorAll(".toggle-button")) {
    button.addEventListener("click", async () => {
      const { type, key } = button.dataset;
      const enabled = !button.classList.contains("is-active");
      const url = type === "module" ? `/api/admin/modules/${key}` : `/api/admin/data_sources/${key}`;
      await window.HomelabSecAuth.apiJson(url, {
        method: "PATCH",
        body: JSON.stringify({ enabled }),
      });
      await loadAdminConsole();
    });
  }

  for (const button of document.querySelectorAll(".toggle-user-button")) {
    button.addEventListener("click", async () => {
      const userId = button.dataset.userId;
      const nextActive = button.dataset.active !== "true";
      await window.HomelabSecAuth.apiJson(`/api/admin/users/${userId}`, {
        method: "PATCH",
        body: JSON.stringify({ is_active: nextActive }),
      });
      await loadAdminConsole();
    });
  }
}

createUserForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  userMessage.hidden = true;

  try {
    await window.HomelabSecAuth.apiJson("/api/admin/users", {
      method: "POST",
      body: JSON.stringify({
        username: document.getElementById("new-user-username").value,
        display_name: document.getElementById("new-user-display-name").value,
        email: document.getElementById("new-user-email").value,
        role: document.getElementById("new-user-role").value,
        password: document.getElementById("new-user-password").value,
      }),
    });
    createUserForm.reset();
    userMessage.hidden = false;
    userMessage.className = "empty-state auth-success";
    userMessage.textContent = "User created.";
    await loadAdminConsole();
  } catch (error) {
    userMessage.hidden = false;
    userMessage.className = "empty-state auth-error";
    userMessage.textContent = `Failed to create user: ${error.message}`;
  }
});

loadAdminConsole().catch((error) => {
  adminStatus.innerHTML = `<div class="empty-state">Failed to load admin status: ${escapeHtml(error.message)}</div>`;
  moduleList.innerHTML = `<div class="empty-state">Failed to load modules: ${escapeHtml(error.message)}</div>`;
  sourceList.innerHTML = `<div class="empty-state">Failed to load raw data sources: ${escapeHtml(error.message)}</div>`;
  userList.innerHTML = `<div class="empty-state">Failed to load users: ${escapeHtml(error.message)}</div>`;
});

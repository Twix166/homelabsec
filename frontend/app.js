const endpoints = {
  health: "/api/health",
  summary: "/api/report/summary",
  daily: "/api/report/daily",
  assets: "/api/assets",
};

const elements = {
  healthStatus: document.getElementById("health-status"),
  reportGenerated: document.getElementById("report-generated"),
  statAssets: document.getElementById("stat-assets"),
  statObservations: document.getElementById("stat-observations"),
  statFingerprints: document.getElementById("stat-fingerprints"),
  statChanges: document.getElementById("stat-changes"),
  recentChanges: document.getElementById("recent-changes"),
  notableAssets: document.getElementById("notable-assets"),
  assetsTable: document.getElementById("assets-table"),
  refreshButton: document.getElementById("refresh-button"),
  emptyTemplate: document.getElementById("empty-state-template"),
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
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

function formatConfidence(value) {
  if (typeof value !== "number") {
    return "-";
  }
  return `${Math.round(value * 100)}%`;
}

function setEmptyState(container, message) {
  container.innerHTML = "";
  const node = elements.emptyTemplate.content.firstElementChild.cloneNode(true);
  node.textContent = message;
  container.appendChild(node);
}

function severityClass(severity) {
  if (!severity) {
    return "";
  }
  return String(severity).toLowerCase();
}

function renderRecentChanges(changes) {
  if (!changes.length) {
    setEmptyState(elements.recentChanges, "No recent changes in the last 24 hours.");
    return;
  }

  elements.recentChanges.innerHTML = changes
    .slice(0, 8)
    .map(
      (change) => `
        <article class="list-card">
          <div class="list-topline">
            <div class="list-title">${escapeHtml(change.preferred_name || "Unnamed asset")}</div>
            <span class="pill ${severityClass(change.severity)}">${escapeHtml(change.severity || "info")}</span>
          </div>
          <div class="list-meta">
            <span>${escapeHtml(change.change_type || "unknown_change")}</span>
            <span>${escapeHtml(change.role || "unknown")}</span>
            <span>${escapeHtml(formatDate(change.detected_at))}</span>
          </div>
        </article>
      `
    )
    .join("");
}

function renderNotableAssets(assets) {
  if (!assets.length) {
    setEmptyState(elements.notableAssets, "No notable assets right now.");
    return;
  }

  elements.notableAssets.innerHTML = assets
    .slice(0, 8)
    .map(
      (asset) => `
        <article class="list-card">
          <div class="list-topline">
            <div class="list-title">${escapeHtml(asset.preferred_name || "Unnamed asset")}</div>
            <span class="pill">${escapeHtml(asset.role || "unknown")}</span>
          </div>
          <div class="list-meta">
            <span>Confidence ${escapeHtml(formatConfidence(asset.role_confidence))}</span>
            <span>Last seen ${escapeHtml(formatDate(asset.last_seen))}</span>
          </div>
          <div class="list-meta mono">
            <span>${escapeHtml(asset.asset_id)}</span>
          </div>
        </article>
      `
    )
    .join("");
}

function renderAssetsTable(assets) {
  if (!assets.length) {
    elements.assetsTable.innerHTML = `
      <tr>
        <td colspan="6">
          <div class="empty-state">No assets available.</div>
        </td>
      </tr>
    `;
    return;
  }

  elements.assetsTable.innerHTML = assets
    .map(
      (asset) => `
        <tr>
          <td><span class="asset-name">${escapeHtml(asset.preferred_name || "Unnamed asset")}</span></td>
          <td>${escapeHtml(asset.role || "unknown")}</td>
          <td>${escapeHtml(formatConfidence(asset.role_confidence))}</td>
          <td>${escapeHtml(formatDate(asset.first_seen))}</td>
          <td>${escapeHtml(formatDate(asset.last_seen))}</td>
          <td class="mono">${escapeHtml(asset.asset_id)}</td>
        </tr>
      `
    )
    .join("");
}

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function loadDashboard() {
  elements.refreshButton.disabled = true;
  elements.refreshButton.textContent = "Refreshing";

  try {
    const [health, summary, daily, assets] = await Promise.all([
      fetchJson(endpoints.health),
      fetchJson(endpoints.summary),
      fetchJson(endpoints.daily),
      fetchJson(endpoints.assets),
    ]);

    elements.healthStatus.textContent = health.status || "ok";
    elements.reportGenerated.textContent = formatDate(daily.report_generated_at);
    elements.statAssets.textContent = summary.assets ?? "-";
    elements.statObservations.textContent = summary.network_observations ?? "-";
    elements.statFingerprints.textContent = summary.fingerprints ?? "-";
    elements.statChanges.textContent = daily.recent_change_count ?? "-";

    renderRecentChanges(daily.recent_changes || []);
    renderNotableAssets(daily.notable_assets || []);
    renderAssetsTable(assets.assets || []);
  } catch (error) {
    elements.healthStatus.textContent = "error";
    elements.reportGenerated.textContent = "-";
    setEmptyState(elements.recentChanges, `Failed to load dashboard: ${error.message}`);
    setEmptyState(elements.notableAssets, "Dashboard data unavailable.");
    renderAssetsTable([]);
  } finally {
    elements.refreshButton.disabled = false;
    elements.refreshButton.textContent = "Refresh";
  }
}

elements.refreshButton.addEventListener("click", () => {
  loadDashboard();
});

loadDashboard();

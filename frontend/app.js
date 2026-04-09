const endpoints = {
  health: "/api/health",
  summary: "/api/report/summary",
  daily: "/api/report/daily",
  assets: "/api/assets",
  observations: "/api/observations",
  fingerprints: "/api/fingerprints",
  adminStatus: "/api/admin/status",
};

const elements = {
  healthStatus: document.getElementById("health-status"),
  reportGenerated: document.getElementById("report-generated"),
  statAssets: document.getElementById("stat-assets"),
  statObservations: document.getElementById("stat-observations"),
  statFingerprints: document.getElementById("stat-fingerprints"),
  statChanges: document.getElementById("stat-changes"),
  summaryAssets: document.getElementById("summary-assets"),
  summaryObservations: document.getElementById("summary-observations"),
  summaryFingerprints: document.getElementById("summary-fingerprints"),
  summaryChanges: document.getElementById("summary-changes"),
  detailTitle: document.getElementById("detail-title"),
  detailDescription: document.getElementById("detail-description"),
  detailList: document.getElementById("detail-list"),
  assetCount: document.getElementById("asset-count"),
  adminStatus: document.getElementById("admin-status"),
  recentChanges: document.getElementById("recent-changes"),
  assetsTable: document.getElementById("assets-table"),
  filterAssetsAll: document.getElementById("filter-assets-all"),
  filterAssetsNotable: document.getElementById("filter-assets-notable"),
  refreshButton: document.getElementById("refresh-button"),
  emptyTemplate: document.getElementById("empty-state-template"),
};

const dashboardState = {
  assets: [],
  observations: [],
  fingerprints: [],
  changes: [],
  notableAssetIds: new Set(),
  adminStatus: null,
  activeSummary: "changes",
  assetFilter: "all",
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

function assetInventoryRows() {
  const assets =
    dashboardState.assetFilter === "notable"
      ? dashboardState.assets.filter((asset) => dashboardState.notableAssetIds.has(asset.asset_id))
      : dashboardState.assets;

  return assets.map((asset) => {
    const isNotable = dashboardState.notableAssetIds.has(asset.asset_id);
    return `
      <tr>
        <td><span class="asset-name">${escapeHtml(asset.preferred_name || "Unnamed asset")}</span></td>
        <td>${isNotable ? '<span class="pill notable">Most notable</span>' : '<span class="muted-cell">-</span>'}</td>
        <td>${escapeHtml(asset.role || "unknown")}</td>
        <td>${escapeHtml(formatConfidence(asset.role_confidence))}</td>
        <td>${escapeHtml(formatDate(asset.first_seen))}</td>
        <td>${escapeHtml(formatDate(asset.last_seen))}</td>
        <td class="mono">${escapeHtml(asset.asset_id)}</td>
      </tr>
    `;
  });
}

function renderAssetsTable() {
  const rows = assetInventoryRows();
  const shownCount = rows.length;
  const totalCount = dashboardState.assets.length;
  const colSpan = 7;
  elements.assetCount.textContent = `${shownCount}/${totalCount}`;
  if (!rows.length) {
    const message =
      dashboardState.assetFilter === "notable"
        ? "No notable assets available."
        : "No assets available.";
    elements.assetsTable.innerHTML = `
      <tr>
        <td colspan="${colSpan}">
          <div class="empty-state">${message}</div>
        </td>
      </tr>
    `;
    return;
  }

  elements.assetsTable.innerHTML = rows.join("");
}

function updateAssetFilterButtons() {
  elements.filterAssetsAll.classList.toggle("is-active", dashboardState.assetFilter === "all");
  elements.filterAssetsNotable.classList.toggle("is-active", dashboardState.assetFilter === "notable");
}

function buildQuickLinks() {
  const { protocol, hostname, origin } = window.location;
  const links = [
    { label: "Dashboard", href: origin },
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
  if (!status) {
    setEmptyState(elements.adminStatus, "Admin status unavailable.");
    return;
  }

  const freshness = status.scheduler_freshness || {};
  const summary = status.summary || {};
  const latestScan = status.latest_scan_run;
  const quickLinks = buildQuickLinks()
    .map(
      (link) => `
        <a class="pill" href="${escapeHtml(link.href)}" target="_blank" rel="noreferrer">${escapeHtml(link.label)}</a>
      `
    )
    .join("");

  elements.adminStatus.innerHTML = `
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
          : `
            <div class="empty-state">No scan runs recorded yet.</div>
          `
      }
      <div class="admin-links">
        ${quickLinks}
      </div>
    </article>
  `;
}

function renderDetailCards(items, renderItem, emptyMessage) {
  if (!items.length) {
    setEmptyState(elements.detailList, emptyMessage);
    return;
  }

  elements.detailList.innerHTML = items.map(renderItem).join("");
}

function renderSummaryDetail(summaryKey) {
  dashboardState.activeSummary = summaryKey;

  if (summaryKey === "assets") {
    dashboardState.assetFilter = "all";
    updateAssetFilterButtons();
    renderAssetsTable();
    window.scrollTo({
      top: elements.assetsTable.closest(".panel").offsetTop - 24,
      behavior: "smooth",
    });
    return;
  }

  if (summaryKey === "observations") {
    elements.detailTitle.textContent = "Observations";
    elements.detailDescription.textContent = "Recent network observations ordered by observed time.";
    renderDetailCards(
      dashboardState.observations,
      (observation) => `
        <article class="list-card">
          <div class="list-topline">
            <div class="list-title">${escapeHtml(observation.preferred_name || observation.ip_address || "Unassigned observation")}</div>
            <span class="pill">${escapeHtml(observation.service_name || "observation")}</span>
          </div>
          <div class="list-meta">
            <span>${escapeHtml(observation.ip_address || "no_ip")}</span>
            <span>${escapeHtml(observation.protocol || "-")}${observation.port ? `/${escapeHtml(observation.port)}` : ""}</span>
            <span>${escapeHtml(observation.service_product || observation.os_guess || "-")}</span>
            <span>${escapeHtml(formatDate(observation.observed_at))}</span>
          </div>
          <div class="list-meta mono">
            <span>${escapeHtml(observation.observation_id)}</span>
          </div>
        </article>
      `,
      "No observations available."
    );
    return;
  }

  if (summaryKey === "fingerprints") {
    elements.detailTitle.textContent = "Fingerprints";
    elements.detailDescription.textContent = "Recent stored fingerprints ordered by creation time.";
    renderDetailCards(
      dashboardState.fingerprints,
      (fingerprint) => `
        <article class="list-card">
          <div class="list-topline">
            <div class="list-title">${escapeHtml(fingerprint.preferred_name || "Unnamed asset")}</div>
            <span class="pill">${escapeHtml(fingerprint.role || "unknown")}</span>
          </div>
          <div class="list-meta">
            <span>${escapeHtml(formatDate(fingerprint.created_at))}</span>
            <span>Asset ${escapeHtml(fingerprint.asset_id)}</span>
          </div>
          <div class="list-meta mono">
            <span>${escapeHtml(fingerprint.fingerprint_hash)}</span>
          </div>
        </article>
      `,
      "No fingerprints available."
    );
    return;
  }

  elements.detailTitle.textContent = "24h changes";
  elements.detailDescription.textContent = "Detected changes from the last 24 hours.";
  renderDetailCards(
    dashboardState.changes,
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
        <div class="list-meta mono">
          <span>${escapeHtml(change.asset_id)}</span>
        </div>
      </article>
    `,
    "No recent changes in the last 24 hours."
  );
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
    const [health, summary, daily, assets, observations, fingerprints, adminStatus] = await Promise.all([
      fetchJson(endpoints.health),
      fetchJson(endpoints.summary),
      fetchJson(endpoints.daily),
      fetchJson(endpoints.assets),
      fetchJson(endpoints.observations),
      fetchJson(endpoints.fingerprints),
      fetchJson(endpoints.adminStatus),
    ]);

    dashboardState.assets = assets.assets || [];
    dashboardState.observations = observations.observations || [];
    dashboardState.fingerprints = fingerprints.fingerprints || [];
    dashboardState.changes = daily.recent_changes || [];
    dashboardState.notableAssetIds = new Set((daily.notable_assets || []).map((asset) => asset.asset_id));
    dashboardState.adminStatus = adminStatus;

    elements.healthStatus.textContent = health.status || "ok";
    elements.reportGenerated.textContent = formatDate(daily.report_generated_at);
    elements.statAssets.textContent = summary.assets ?? "-";
    elements.statObservations.textContent = summary.network_observations ?? "-";
    elements.statFingerprints.textContent = summary.fingerprints ?? "-";
    elements.statChanges.textContent = daily.recent_change_count ?? "-";

    renderRecentChanges(dashboardState.changes);
    updateAssetFilterButtons();
    renderAssetsTable();
    renderAdminStatus(dashboardState.adminStatus);
    renderSummaryDetail(dashboardState.activeSummary);
  } catch (error) {
    elements.healthStatus.textContent = "error";
    elements.reportGenerated.textContent = "-";
    elements.detailTitle.textContent = "Detail view";
    elements.detailDescription.textContent = "Click a summary card to list the underlying items.";
    setEmptyState(elements.detailList, `Failed to load detail data: ${error.message}`);
    setEmptyState(elements.adminStatus, `Failed to load admin status: ${error.message}`);
    setEmptyState(elements.recentChanges, `Failed to load dashboard: ${error.message}`);
    renderAssetsTable();
  } finally {
    elements.refreshButton.disabled = false;
    elements.refreshButton.textContent = "Refresh";
  }
}

elements.refreshButton.addEventListener("click", () => {
  loadDashboard();
});

elements.summaryAssets.addEventListener("click", () => {
  renderSummaryDetail("assets");
});

elements.summaryObservations.addEventListener("click", () => {
  renderSummaryDetail("observations");
});

elements.summaryFingerprints.addEventListener("click", () => {
  renderSummaryDetail("fingerprints");
});

elements.summaryChanges.addEventListener("click", () => {
  renderSummaryDetail("changes");
});

elements.filterAssetsAll.addEventListener("click", () => {
  dashboardState.assetFilter = "all";
  updateAssetFilterButtons();
  renderAssetsTable();
});

elements.filterAssetsNotable.addEventListener("click", () => {
  dashboardState.assetFilter = "notable";
  updateAssetFilterButtons();
  renderAssetsTable();
});

loadDashboard();

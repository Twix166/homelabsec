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
  assetsTable: document.getElementById("assets-table"),
  filterAssetsAll: document.getElementById("filter-assets-all"),
  filterAssetsNotable: document.getElementById("filter-assets-notable"),
  filterConfidenceRed: document.getElementById("filter-confidence-red"),
  filterConfidenceGreen: document.getElementById("filter-confidence-green"),
  filterConfidenceBlue: document.getElementById("filter-confidence-blue"),
  sortButtons: Array.from(document.querySelectorAll(".sort-button")),
  refreshButton: document.getElementById("refresh-button"),
  emptyTemplate: document.getElementById("empty-state-template"),
};

const dashboardState = {
  assets: [],
  observations: [],
  fingerprints: [],
  changes: [],
  notableAssetIds: new Set(),
  notableReasonsByAssetId: new Map(),
  recentChangeByAssetId: new Map(),
  activeSummary: "changes",
  assetFilter: "all",
  assetSortKey: "last_seen",
  assetSortDirection: "desc",
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

function confidenceBand(value) {
  if (typeof value !== "number") {
    return {
      label: "Unscored",
      className: "confidence-unknown",
      summary: "No confidence score is available yet.",
      nextStep: "Run classification again after discovery, or enrich the asset with more identifying signals.",
    };
  }

  if (value >= 0.85) {
  return {
    label: "High",
      className: "confidence-high",
      filterKey: "green",
      summary: "The score is high because the fingerprint has strong service and platform signals that match a known role.",
      nextStep: "Keep discovery current. If you want to validate it further, confirm the exposed services or compare against the learned lookup entry.",
    };
  }

  if (value >= 0.6) {
    return {
      label: "Medium",
      className: "confidence-medium",
      filterKey: "blue",
      summary: "The score is moderate because some signals match, but the fingerprint is still somewhat ambiguous.",
      nextStep: "Improve it by collecting more service details, identifying the host more precisely, or validating it over SSH with a targeted script.",
    };
  }

  return {
    label: "Low",
    className: "confidence-low",
    filterKey: "red",
    summary: "The score is low because the current fingerprint is weak, generic, or missing enough detail for a reliable role match.",
    nextStep: "Improve it by rescanning, exposing more service metadata, or using SSH-based inspection to gather stronger host evidence.",
  };
}

function confidenceTooltip(value) {
  const band = confidenceBand(value);
  const score = typeof value === "number" ? formatConfidence(value) : "Not scored";
  return `${band.label} confidence (${score}). ${band.summary} ${band.nextStep}`;
}

function notableReason(asset) {
  const reasons = [];
  if (!asset.role || asset.role === "unknown") {
    reasons.push("Role is unknown or not yet classified.");
  }
  if (typeof asset.role_confidence !== "number") {
    reasons.push("Confidence has not been scored yet.");
  } else if (asset.role_confidence < 0.6) {
    reasons.push(`Confidence is below the notable threshold at ${formatConfidence(asset.role_confidence)}.`);
  }
  return reasons[0] || "This asset is tracked closely because it needs additional classification review.";
}

function describeChange(change) {
  if (!change) {
    return "";
  }
  if (change.old_value && change.new_value) {
    return `${change.change_type} changed from ${change.old_value} to ${change.new_value}.`;
  }
  if (change.new_value) {
    return `${change.change_type} changed to ${change.new_value}.`;
  }
  if (change.old_value) {
    return `${change.change_type} changed from ${change.old_value}.`;
  }
  return `${change.change_type} was detected at ${formatDate(change.detected_at)}.`;
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

function filterAssets(assets) {
  if (dashboardState.assetFilter === "notable") {
    return assets.filter((asset) => dashboardState.notableAssetIds.has(asset.asset_id));
  }

  if (["red", "green", "blue"].includes(dashboardState.assetFilter)) {
    return assets.filter((asset) => confidenceBand(asset.role_confidence).filterKey === dashboardState.assetFilter);
  }

  return assets;
}

function sortValue(asset, sortKey) {
  if (sortKey === "flags") {
    const notableScore = dashboardState.notableAssetIds.has(asset.asset_id) ? 2 : 0;
    const recentChangeScore = dashboardState.recentChangeByAssetId.has(asset.asset_id) ? 1 : 0;
    return notableScore + recentChangeScore;
  }

  if (sortKey === "role_confidence") {
    return typeof asset.role_confidence === "number" ? asset.role_confidence : -1;
  }

  if (sortKey === "first_seen" || sortKey === "last_seen") {
    return asset[sortKey] ? new Date(asset[sortKey]).getTime() : 0;
  }

  return String(asset[sortKey] ?? "").toLowerCase();
}

function sortedAssets(assets) {
  const direction = dashboardState.assetSortDirection === "asc" ? 1 : -1;
  const sortKey = dashboardState.assetSortKey;

  return [...assets].sort((left, right) => {
    const leftValue = sortValue(left, sortKey);
    const rightValue = sortValue(right, sortKey);

    if (leftValue < rightValue) {
      return -1 * direction;
    }
    if (leftValue > rightValue) {
      return 1 * direction;
    }

    return String(left.asset_id).localeCompare(String(right.asset_id)) * direction;
  });
}

function assetInventoryRows() {
  const assets = sortedAssets(filterAssets(dashboardState.assets));

  return assets.map((asset) => {
    const isNotable = dashboardState.notableAssetIds.has(asset.asset_id);
    const recentChange = dashboardState.recentChangeByAssetId.get(asset.asset_id);
    const confidence = confidenceBand(asset.role_confidence);
    const flagPills = [];
    if (isNotable) {
      flagPills.push(
        `<a class="pill notable pill-link" href="/asset.html?id=${encodeURIComponent(asset.asset_id)}&focus=notable" title="${escapeHtml(dashboardState.notableReasonsByAssetId.get(asset.asset_id) || notableReason(asset))}" aria-label="${escapeHtml(dashboardState.notableReasonsByAssetId.get(asset.asset_id) || notableReason(asset))}">Most notable</a>`
      );
    }
    if (recentChange) {
      const recentChangeTooltip = `${describeChange(recentChange)} Detected ${formatDate(recentChange.detected_at)}.`;
      flagPills.push(
        `<a class="pill recent-change pill-link" href="/asset.html?id=${encodeURIComponent(asset.asset_id)}&focus=recent_change" title="${escapeHtml(recentChangeTooltip)}" aria-label="${escapeHtml(recentChangeTooltip)}">Recent change</a>`
      );
    }
    return `
      <tr>
        <td><span class="asset-name">${escapeHtml(asset.preferred_name || "Unnamed asset")}</span></td>
        <td>${escapeHtml(asset.mac_vendor || "Unknown brand")}</td>
        <td>${flagPills.length ? flagPills.join(" ") : '<span class="muted-cell">-</span>'}</td>
        <td>${escapeHtml(asset.role || "unknown")}</td>
        <td>
          <span
            class="pill confidence-pill ${escapeHtml(confidence.className)}"
            title="${escapeHtml(confidenceTooltip(asset.role_confidence))}"
            aria-label="${escapeHtml(confidenceTooltip(asset.role_confidence))}"
          >
            ${escapeHtml(formatConfidence(asset.role_confidence))}
          </span>
        </td>
        <td>${escapeHtml(formatDate(asset.first_seen))}</td>
        <td>${escapeHtml(formatDate(asset.last_seen))}</td>
        <td class="mono"><a class="detail-link" href="/asset.html?id=${encodeURIComponent(asset.asset_id)}">Details</a> ${escapeHtml(asset.asset_id)}</td>
      </tr>
    `;
  });
}

function renderAssetsTable() {
  const rows = assetInventoryRows();
  const shownCount = rows.length;
  const totalCount = dashboardState.assets.length;
  const colSpan = 8;
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
  elements.filterConfidenceRed.classList.toggle("is-active", dashboardState.assetFilter === "red");
  elements.filterConfidenceGreen.classList.toggle("is-active", dashboardState.assetFilter === "green");
  elements.filterConfidenceBlue.classList.toggle("is-active", dashboardState.assetFilter === "blue");
}

function updateSortButtons() {
  for (const button of elements.sortButtons) {
    const isActive = button.dataset.sortKey === dashboardState.assetSortKey;
    button.classList.toggle("is-active", isActive);
    button.dataset.sortDirection = isActive ? dashboardState.assetSortDirection : "";
  }
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

  if (summaryKey === "changes") {
    dashboardState.assetFilter = "all";
    updateAssetFilterButtons();
    renderAssetsTable();
    elements.detailTitle.textContent = "Recent changes";
    elements.detailDescription.textContent = "Recent changes now appear inline in the Asset inventory flags column. Click a Recent change pill to open the affected asset.";
    setEmptyState(elements.detailList, "Use the Asset inventory flags to inspect recent changes.");
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

}

async function fetchJson(url) {
  return window.HomelabSecAuth.apiJson(url);
}

async function loadDashboard() {
  elements.refreshButton.disabled = true;
  elements.refreshButton.textContent = "Refreshing";

  try {
    const [health, summary, daily, assets, observations, fingerprints] = await Promise.all([
      fetchJson(endpoints.health),
      fetchJson(endpoints.summary),
      fetchJson(endpoints.daily),
      fetchJson(endpoints.assets),
      fetchJson(endpoints.observations),
      fetchJson(endpoints.fingerprints),
    ]);

    dashboardState.assets = assets.assets || [];
    dashboardState.observations = observations.observations || [];
    dashboardState.fingerprints = fingerprints.fingerprints || [];
    dashboardState.changes = daily.recent_changes || [];
    dashboardState.notableAssetIds = new Set((daily.notable_assets || []).map((asset) => asset.asset_id));
    dashboardState.notableReasonsByAssetId = new Map(
      (daily.notable_assets || []).map((asset) => [asset.asset_id, notableReason(asset)])
    );
    dashboardState.recentChangeByAssetId = new Map(
      (daily.recent_changes || []).map((change) => [change.asset_id, change])
    );
    elements.healthStatus.textContent = health.status || "ok";
    elements.reportGenerated.textContent = formatDate(daily.report_generated_at);
    elements.statAssets.textContent = summary.assets ?? "-";
    elements.statObservations.textContent = summary.network_observations ?? "-";
    elements.statFingerprints.textContent = summary.fingerprints ?? "-";
    elements.statChanges.textContent = daily.recent_change_count ?? "-";

    updateAssetFilterButtons();
    updateSortButtons();
    renderAssetsTable();
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

elements.filterConfidenceRed.addEventListener("click", () => {
  dashboardState.assetFilter = "red";
  updateAssetFilterButtons();
  renderAssetsTable();
});

elements.filterConfidenceGreen.addEventListener("click", () => {
  dashboardState.assetFilter = "green";
  updateAssetFilterButtons();
  renderAssetsTable();
});

elements.filterConfidenceBlue.addEventListener("click", () => {
  dashboardState.assetFilter = "blue";
  updateAssetFilterButtons();
  renderAssetsTable();
});

for (const button of elements.sortButtons) {
  button.addEventListener("click", () => {
    const { sortKey } = button.dataset;
    if (!sortKey) {
      return;
    }

    if (dashboardState.assetSortKey === sortKey) {
      dashboardState.assetSortDirection = dashboardState.assetSortDirection === "asc" ? "desc" : "asc";
    } else {
      dashboardState.assetSortKey = sortKey;
      dashboardState.assetSortDirection = sortKey === "last_seen" ? "desc" : "asc";
    }

    updateSortButtons();
    renderAssetsTable();
  });
}

async function initDashboard() {
  const user = await window.HomelabSecAuth.requireUser();
  window.HomelabSecAuth.mountHeaderNav(document.getElementById("page-nav"), user, "dashboard");
  window.HomelabSecAuth.mountProfileMenu(document.getElementById("profile-menu"), user);
  await loadDashboard();
}

initDashboard().catch((error) => {
  elements.healthStatus.textContent = "error";
  elements.reportGenerated.textContent = "-";
  setEmptyState(elements.detailList, `Failed to load dashboard: ${error.message}`);
  setEmptyState(elements.adminStatus, `Failed to load admin status: ${error.message}`);
  setEmptyState(elements.recentChanges, `Failed to load dashboard: ${error.message}`);
});

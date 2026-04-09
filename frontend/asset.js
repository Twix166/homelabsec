const emptyTemplate = document.getElementById("empty-state-template");
const titleEl = document.getElementById("asset-title");
const subtitleEl = document.getElementById("asset-subtitle");
const roleEl = document.getElementById("detail-role");
const confidenceEl = document.getElementById("detail-confidence");
const overviewEl = document.getElementById("asset-overview");
const servicesEl = document.getElementById("asset-services");
const lookupEl = document.getElementById("asset-lookup");
const rescanButton = document.getElementById("rescan-button");

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
  const node = emptyTemplate.content.firstElementChild.cloneNode(true);
  node.textContent = message;
  container.appendChild(node);
}

function assetIdFromUrl() {
  const params = new URLSearchParams(window.location.search);
  return params.get("id");
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

function renderOverview(detail) {
  const asset = detail.asset;
  titleEl.textContent = asset.preferred_name || "Unnamed asset";
  subtitleEl.textContent = asset.asset_id;
  roleEl.textContent = asset.role || "unknown";
  confidenceEl.textContent = formatConfidence(asset.role_confidence);

  const identifiers = (detail.identifiers || [])
    .map((identifier) => `<span class="pill">${escapeHtml(identifier.type)}:${escapeHtml(identifier.value)}</span>`)
    .join("");
  const latestRescan = detail.latest_rescan_request;

  overviewEl.innerHTML = `
    <article class="list-card">
      <div class="admin-grid admin-grid-compact">
        <div class="admin-metric compact">
          <span class="admin-label">First seen</span>
          <strong class="admin-value">${escapeHtml(formatDate(asset.first_seen))}</strong>
        </div>
        <div class="admin-metric compact">
          <span class="admin-label">Last seen</span>
          <strong class="admin-value">${escapeHtml(formatDate(asset.last_seen))}</strong>
        </div>
        <div class="admin-metric compact">
          <span class="admin-label">Asset ID</span>
          <strong class="admin-value mono">${escapeHtml(asset.asset_id)}</strong>
        </div>
      </div>
      <div class="list-meta">${identifiers || '<span class="muted-cell">No identifiers recorded.</span>'}</div>
      ${
        latestRescan
          ? `
            <div class="admin-scan">
              <div class="admin-scan-title">Latest rescan request</div>
              <div class="list-meta">
                <span>Status ${escapeHtml(latestRescan.status)}</span>
                <span>Requested ${escapeHtml(formatDate(latestRescan.requested_at))}</span>
                <span>Target ${escapeHtml(latestRescan.target_ip || "-")}</span>
              </div>
            </div>
          `
          : ""
      }
    </article>
  `;
}

function renderServices(detail) {
  const services = detail.exposed_services || [];
  if (!services.length) {
    setEmptyState(servicesEl, "No exposed services recorded for this asset.");
    return;
  }

  servicesEl.innerHTML = services
    .map(
      (service) => `
        <article class="list-card">
          <div class="list-topline">
            <div class="list-title">${escapeHtml(service.service_name || "service")} ${escapeHtml(service.port)}/${escapeHtml(service.protocol || "-")}</div>
            <span class="pill">${escapeHtml(service.ip_address || "no_ip")}</span>
          </div>
          <div class="list-meta">
            <span>${escapeHtml(service.service_product || "-")}</span>
            <span>${escapeHtml(service.service_version || "-")}</span>
            <span>${escapeHtml(service.os_guess || "-")}</span>
            <span>${escapeHtml(formatDate(service.observed_at))}</span>
          </div>
        </article>
      `
    )
    .join("");
}

function renderLookup(detail) {
  const lookup = detail.learned_lookup;
  if (!lookup) {
    setEmptyState(lookupEl, "No learned lookup entry matches this asset yet.");
    return;
  }

  lookupEl.innerHTML = `
    <article class="list-card">
      <div class="list-topline">
        <div class="list-title">${escapeHtml(lookup.role)}</div>
        <span class="pill">${escapeHtml(formatConfidence(lookup.confidence))}</span>
      </div>
      <div class="list-meta">
        <span>Source ${escapeHtml(lookup.source)}</span>
        <span>Samples ${escapeHtml(lookup.sample_count)}</span>
        <span>First learned ${escapeHtml(formatDate(lookup.first_learned_at))}</span>
        <span>Last learned ${escapeHtml(formatDate(lookup.last_learned_at))}</span>
      </div>
      <div class="list-meta mono">
        <span>${escapeHtml(lookup.signature_hash)}</span>
      </div>
    </article>
  `;
}

async function loadAssetDetail() {
  const assetId = assetIdFromUrl();
  if (!assetId) {
    titleEl.textContent = "Asset detail";
    subtitleEl.textContent = "Missing asset id";
    setEmptyState(overviewEl, "No asset id provided.");
    setEmptyState(servicesEl, "No asset id provided.");
    setEmptyState(lookupEl, "No asset id provided.");
    rescanButton.disabled = true;
    return;
  }

  const detail = await fetchJson(`/api/assets/${assetId}`);
  renderOverview(detail);
  renderServices(detail);
  renderLookup(detail);

  rescanButton.addEventListener("click", async () => {
    rescanButton.disabled = true;
    rescanButton.textContent = "Queued";
    try {
      await fetchJson(`/api/rescan/${assetId}`, { method: "POST" });
      await loadAssetDetail();
    } catch (error) {
      rescanButton.disabled = false;
      rescanButton.textContent = "Rescan host";
      window.alert(`Failed to queue rescan: ${error.message}`);
    }
  }, { once: true });
}

loadAssetDetail().catch((error) => {
  titleEl.textContent = "Asset detail";
  subtitleEl.textContent = "Failed to load asset";
  setEmptyState(overviewEl, `Failed to load asset: ${error.message}`);
  setEmptyState(servicesEl, "Asset detail unavailable.");
  setEmptyState(lookupEl, "Asset detail unavailable.");
  rescanButton.disabled = true;
});

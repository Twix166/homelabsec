const emptyTemplate = document.getElementById("empty-state-template");
const titleEl = document.getElementById("asset-title");
const subtitleEl = document.getElementById("asset-subtitle");
const roleEl = document.getElementById("detail-role");
const confidenceEl = document.getElementById("detail-confidence");
const overviewEl = document.getElementById("asset-overview");
const statusFlagsEl = document.getElementById("asset-status-flags");
const lynisPanelEl = document.getElementById("asset-lynis-panel");
const servicesEl = document.getElementById("asset-services");
const lookupEl = document.getElementById("asset-lookup");
const rescanButton = document.getElementById("rescan-button");
const lynisButton = document.getElementById("lynis-button");
const lynisModal = document.getElementById("lynis-modal");
const lynisCloseButton = document.getElementById("lynis-close-button");
const lynisStatusEl = document.getElementById("lynis-status");
const lynisRunStateEl = document.getElementById("lynis-run-state");
const lynisRunButton = document.getElementById("lynis-run-button");
const lynisTargetForm = document.getElementById("lynis-target-form");
const lynisSshHost = document.getElementById("lynis-ssh-host");
const lynisSshPort = document.getElementById("lynis-ssh-port");
const lynisSshUsername = document.getElementById("lynis-ssh-username");
const lynisSshPassword = document.getElementById("lynis-ssh-password");
const lynisUseSudo = document.getElementById("lynis-use-sudo");
const lynisNotes = document.getElementById("lynis-notes");

let currentUser = null;
let lynisPollTimer = null;

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

function openLynisModal() {
  lynisModal.hidden = false;
}

function closeLynisModal() {
  lynisModal.hidden = true;
  stopLynisPolling();
}

function stopLynisPolling() {
  if (lynisPollTimer !== null) {
    window.clearTimeout(lynisPollTimer);
    lynisPollTimer = null;
  }
}

function scheduleLynisPolling(assetId, delayMs = 5000) {
  stopLynisPolling();
  lynisPollTimer = window.setTimeout(async () => {
    try {
      await loadLynisStatus(assetId);
    } catch (error) {
      lynisRunStateEl.hidden = false;
      lynisRunStateEl.className = "empty-state auth-error";
      lynisRunStateEl.textContent = `Failed to refresh Lynis status: ${error.message}`;
    }
  }, delayMs);
}

function assetIdFromUrl() {
  const params = new URLSearchParams(window.location.search);
  return params.get("id");
}

function focusFromUrl() {
  const params = new URLSearchParams(window.location.search);
  return params.get("focus");
}

async function fetchJson(url, options) {
  return window.HomelabSecAuth.apiJson(url, options);
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
          <span class="admin-label">MAC brand</span>
          <strong class="admin-value">${escapeHtml(asset.mac_vendor || "Unknown brand")}</strong>
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

function renderStatusFlags(detail) {
  const cards = [];

  if (detail.notable_assessment?.is_notable) {
    cards.push(`
      <article class="list-card" id="notable-panel">
        <div class="list-topline">
          <div class="list-title">Most notable</div>
          <span class="pill notable">Most notable</span>
        </div>
        <div class="list-meta">
          <span>${escapeHtml(detail.notable_assessment.summary)}</span>
        </div>
        <div class="list-meta">
          ${(detail.notable_assessment.reasons || []).map((reason) => `<span>${escapeHtml(reason)}</span>`).join("")}
        </div>
        <div class="list-meta">
          <span>${escapeHtml(detail.notable_assessment.next_step || "")}</span>
        </div>
      </article>
    `);
  }

  if (detail.recent_change) {
    cards.push(`
      <article class="list-card" id="recent-change-panel">
        <div class="list-topline">
          <div class="list-title">Recent change</div>
          <span class="pill recent-change">Recent change</span>
        </div>
        <div class="list-meta">
          <span>${escapeHtml(detail.recent_change.change_type || "unknown_change")}</span>
          <span>${escapeHtml(detail.recent_change.severity || "info")}</span>
          <span>${escapeHtml(formatDate(detail.recent_change.detected_at))}</span>
        </div>
        <div class="list-meta">
          <span>${escapeHtml(detail.recent_change.summary || "Change detected in the last 24 hours.")}</span>
        </div>
      </article>
    `);
  }

  if (!cards.length) {
    setEmptyState(statusFlagsEl, "This asset has no notable or recent-change flags right now.");
    return;
  }

  statusFlagsEl.innerHTML = cards.join("");
}

function focusFlagPanel() {
  const focus = focusFromUrl();
  if (focus === "notable") {
    document.getElementById("notable-panel")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  if (focus === "recent_change") {
    document.getElementById("recent-change-panel")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function renderLynisPanel(detail) {
  const run = detail.latest_lynis_run;
  if (!run) {
    setEmptyState(lynisPanelEl, "Lynis has not yet been run on this asset.");
    return;
  }

  const summary = run.summary || {};
  lynisPanelEl.innerHTML = `
    <article class="list-card" id="lynis-results-panel">
      <div class="list-topline">
        <div class="list-title">Latest Lynis audit</div>
        <span class="pill ${escapeHtml(run.status === "completed" ? "low" : run.status === "failed" ? "critical" : "medium")}">${escapeHtml(run.status)}</span>
      </div>
      <div class="list-meta">
        <span>Requested ${escapeHtml(formatDate(run.requested_at))}</span>
        <span>Completed ${escapeHtml(formatDate(run.completed_at))}</span>
        <span>Hardening index ${escapeHtml(summary.hardening_index ?? "-")}</span>
        <span>Warnings ${escapeHtml(summary.warning_count ?? 0)}</span>
        <span>Suggestions ${escapeHtml(summary.suggestion_count ?? 0)}</span>
      </div>
      ${
        run.error_text
          ? `<div class="empty-state auth-error">${escapeHtml(run.error_text)}</div>`
          : ""
      }
      ${
        run.report_text
          ? `
            <details class="report-details">
              <summary>View Lynis report</summary>
              <pre class="report-block">${escapeHtml(run.report_text)}</pre>
            </details>
          `
          : ""
      }
      ${
        run.log_text
          ? `
            <details class="report-details">
              <summary>View Lynis log</summary>
              <pre class="report-block">${escapeHtml(run.log_text)}</pre>
            </details>
          `
          : ""
      }
    </article>
  `;
}

function renderLynisStatus(payload) {
  const target = payload.target;
  const latestRun = payload.latest_run;
  const parts = [];

  if (target) {
    parts.push(`
      <article class="list-card">
        <div class="list-topline">
          <div class="list-title">Configured target</div>
          <span class="pill">${escapeHtml(target.enabled ? "enabled" : "disabled")}</span>
        </div>
        <div class="list-meta">
          <span>${escapeHtml(target.ssh_username)}@${escapeHtml(target.ssh_host)}:${escapeHtml(target.ssh_port)}</span>
          <span>${escapeHtml(target.use_sudo ? "sudo" : "no sudo")}</span>
          <span>${escapeHtml(target.notes || "no notes")}</span>
        </div>
      </article>
    `);
  } else {
    parts.push('<div class="empty-state">No Lynis SSH target is configured for this asset yet.</div>');
  }

  if (latestRun) {
    const summary = latestRun.summary || {};
    parts.push(`
      <article class="list-card">
        <div class="list-topline">
          <div class="list-title">Latest audit</div>
          <span class="pill">${escapeHtml(latestRun.status)}</span>
        </div>
        <div class="list-meta">
          <span>Requested ${escapeHtml(formatDate(latestRun.requested_at))}</span>
          <span>Completed ${escapeHtml(formatDate(latestRun.completed_at))}</span>
          <span>Hardening index ${escapeHtml(summary.hardening_index ?? "-")}</span>
          <span>Warnings ${escapeHtml(summary.warning_count ?? 0)}</span>
          <span>Suggestions ${escapeHtml(summary.suggestion_count ?? 0)}</span>
        </div>
        ${
          latestRun.error_text
            ? `<div class="empty-state auth-error">${escapeHtml(latestRun.error_text)}</div>`
            : ""
        }
      </article>
    `);
  }

  lynisStatusEl.innerHTML = parts.join("");
  lynisRunButton.disabled = !payload.module_enabled || !payload.source_enabled || !target || !target.enabled;
  lynisRunButton.textContent = latestRun && ["pending", "running"].includes(latestRun.status) ? "Lynis running" : "Run Lynis audit";

  if (!payload.module_enabled) {
    lynisRunStateEl.hidden = false;
    lynisRunStateEl.className = "empty-state auth-error";
    lynisRunStateEl.textContent = "Lynis audit enrichment is disabled in the admin console.";
    stopLynisPolling();
    return;
  }

  if (!payload.source_enabled) {
    lynisRunStateEl.hidden = false;
    lynisRunStateEl.className = "empty-state auth-error";
    lynisRunStateEl.textContent = "The Lynis remote audit data source is disabled in the admin console.";
    stopLynisPolling();
    return;
  }

  if (latestRun && latestRun.status === "pending") {
    lynisRunStateEl.hidden = false;
    lynisRunStateEl.className = "empty-state";
    lynisRunStateEl.textContent = "Lynis audit is queued and waiting for the runner to claim it.";
    scheduleLynisPolling(payload.asset_id);
    return;
  }

  if (latestRun && latestRun.status === "running") {
    lynisRunStateEl.hidden = false;
    lynisRunStateEl.className = "empty-state";
    lynisRunStateEl.textContent = "Lynis audit is currently running on the target host. Status refreshes automatically.";
    scheduleLynisPolling(payload.asset_id);
    return;
  }

  if (latestRun && latestRun.status === "failed") {
    lynisRunStateEl.hidden = false;
    lynisRunStateEl.className = "empty-state auth-error";
    lynisRunStateEl.textContent = `Latest Lynis audit failed${latestRun.error_text ? `: ${latestRun.error_text}` : "."}`;
    stopLynisPolling();
    return;
  }

  if (latestRun && latestRun.status === "completed") {
    lynisRunStateEl.hidden = false;
    lynisRunStateEl.className = "empty-state auth-success";
    lynisRunStateEl.textContent = "Latest Lynis audit completed successfully.";
    stopLynisPolling();
    return;
  }

  lynisRunStateEl.hidden = false;
  lynisRunStateEl.className = "empty-state";
  lynisRunStateEl.textContent = target ? "No Lynis audit has been run for this asset yet." : "Configure a Lynis SSH target to enable host auditing for this asset.";
  stopLynisPolling();
}

async function loadLynisStatus(assetId) {
  const payload = await fetchJson(`/api/assets/${assetId}/lynis`);
  renderLynisStatus(payload);

  const target = payload.target;
  lynisTargetForm.hidden = currentUser?.role !== "admin";
  if (currentUser?.role === "admin" && target) {
    lynisSshHost.value = target.ssh_host || "";
    lynisSshPort.value = target.ssh_port || 22;
    lynisSshUsername.value = target.ssh_username || "";
    lynisUseSudo.checked = Boolean(target.use_sudo);
    lynisNotes.value = target.notes || "";
    lynisSshPassword.value = "";
  }
}

async function loadAssetDetail() {
  const assetId = assetIdFromUrl();
  if (!assetId) {
    titleEl.textContent = "Asset detail";
    subtitleEl.textContent = "Missing asset id";
    setEmptyState(overviewEl, "No asset id provided.");
    setEmptyState(statusFlagsEl, "No asset id provided.");
    setEmptyState(lynisPanelEl, "No asset id provided.");
    setEmptyState(servicesEl, "No asset id provided.");
    setEmptyState(lookupEl, "No asset id provided.");
    rescanButton.disabled = true;
    return;
  }

  const detail = await fetchJson(`/api/assets/${assetId}`);
  renderOverview(detail);
  renderStatusFlags(detail);
  renderLynisPanel(detail);
  renderServices(detail);
  renderLookup(detail);
  focusFlagPanel();

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

async function initAssetPage() {
  currentUser = await window.HomelabSecAuth.requireUser();
  window.HomelabSecAuth.mountHeaderNav(document.getElementById("page-nav"), currentUser, "");
  window.HomelabSecAuth.mountProfileMenu(document.getElementById("profile-menu"), currentUser);
  await loadAssetDetail();
}

lynisButton.addEventListener("click", async () => {
  openLynisModal();
  const assetId = assetIdFromUrl();
  if (!assetId) {
    setEmptyState(lynisStatusEl, "Missing asset id.");
    return;
  }
  try {
    await loadLynisStatus(assetId);
  } catch (error) {
    lynisRunStateEl.hidden = false;
    lynisRunStateEl.className = "empty-state auth-error";
    lynisRunStateEl.textContent = `Failed to load Lynis status: ${error.message}`;
    setEmptyState(lynisStatusEl, `Failed to load Lynis status: ${error.message}`);
  }
});

lynisCloseButton.addEventListener("click", closeLynisModal);
lynisModal.addEventListener("click", (event) => {
  if (event.target instanceof HTMLElement && event.target.dataset.closeModal === "true") {
    closeLynisModal();
  }
});

lynisTargetForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const assetId = assetIdFromUrl();
  if (!assetId) {
    return;
  }
  await fetchJson(`/api/assets/${assetId}/lynis_target`, {
    method: "PUT",
    body: JSON.stringify({
      ssh_host: lynisSshHost.value,
      ssh_port: Number(lynisSshPort.value || 22),
      ssh_username: lynisSshUsername.value,
      ssh_password: lynisSshPassword.value || null,
      use_sudo: lynisUseSudo.checked,
      enabled: true,
      notes: lynisNotes.value || null,
    }),
  });
  await loadLynisStatus(assetId);
});

lynisRunButton.addEventListener("click", async () => {
  const assetId = assetIdFromUrl();
  if (!assetId) {
    return;
  }
  lynisRunButton.disabled = true;
  lynisRunButton.textContent = "Queued";
  lynisRunStateEl.hidden = false;
  lynisRunStateEl.className = "empty-state";
  lynisRunStateEl.textContent = "Lynis audit queued. Waiting for runner status.";
  try {
    await fetchJson(`/api/assets/${assetId}/lynis/run`, { method: "POST" });
    await loadLynisStatus(assetId);
    scheduleLynisPolling(assetId, 2000);
  } catch (error) {
    lynisRunButton.textContent = "Run Lynis audit";
    lynisRunButton.disabled = false;
    lynisRunStateEl.hidden = false;
    lynisRunStateEl.className = "empty-state auth-error";
    lynisRunStateEl.textContent = `Failed to queue Lynis audit: ${error.message}`;
    window.alert(`Failed to queue Lynis audit: ${error.message}`);
  }
});

initAssetPage().catch((error) => {
  titleEl.textContent = "Asset detail";
  subtitleEl.textContent = "Failed to load asset";
  setEmptyState(overviewEl, `Failed to load asset: ${error.message}`);
  setEmptyState(statusFlagsEl, "Asset detail unavailable.");
  setEmptyState(lynisPanelEl, "Asset detail unavailable.");
  setEmptyState(servicesEl, "Asset detail unavailable.");
  setEmptyState(lookupEl, "Asset detail unavailable.");
  rescanButton.disabled = true;
});

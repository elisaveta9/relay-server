"use strict";

const apiBase = "/api/v1";
let csrfToken = "";
let domainPage = 1;
let domainTotalPages = 0;
let devicePage = 1;
let deviceTotalPages = 0;
let logAutoRefreshTimer = null;

document.getElementById("connect").addEventListener("click", connect);
document.getElementById("refreshAll").addEventListener("click", loadAll);
document.getElementById("addDomain").addEventListener("click", addDomain);
document.getElementById("deviceFilters").addEventListener("submit", event => {
  event.preventDefault();
  devicePage = 1;
  loadDevices();
});
document.getElementById("resetDeviceFilters").addEventListener("click", resetDeviceFilters);
document.getElementById("previousDevices").addEventListener("click", () => {
  if (devicePage > 1) {
    devicePage -= 1;
    loadDevices();
  }
});
document.getElementById("nextDevices").addEventListener("click", () => {
  if (devicePage < deviceTotalPages) {
    devicePage += 1;
    loadDevices();
  }
});
document.getElementById("sessionFilters").addEventListener("submit", event => {
  event.preventDefault();
  loadSessions();
});
document.getElementById("resetSessionFilters").addEventListener("click", resetSessionFilters);
document.getElementById("domainFilters").addEventListener("submit", event => {
  event.preventDefault();
  domainPage = 1;
  loadDomains();
});
document.getElementById("resetDomainFilters").addEventListener("click", resetDomainFilters);
document.getElementById("previousDomains").addEventListener("click", () => {
  if (domainPage > 1) {
    domainPage -= 1;
    loadDomains();
  }
});
document.getElementById("nextDomains").addEventListener("click", () => {
  if (domainPage < domainTotalPages) {
    domainPage += 1;
    loadDomains();
  }
});
document.getElementById("apiKey").addEventListener("input", () => {
  csrfToken = "";
});
document.getElementById("loadLogs").addEventListener("click", () => loadLogs());
document.getElementById("logAutoRefresh").addEventListener("change", toggleLogAutoRefresh);

function apiKey() {
  return document.getElementById("apiKey").value.trim();
}

function requestHeaders(includeCSRF, hasBody) {
  const result = {
    "Authorization": `Bearer ${apiKey()}`
  };
  if (includeCSRF) result["X-CSRF-Token"] = csrfToken;
  if (hasBody) result["Content-Type"] = "application/json; charset=utf-8";
  return result;
}

async function ensureCSRFToken() {
  if (csrfToken) return;
  const response = await fetch(`${apiBase}/csrf`, {
    headers: requestHeaders(false, false),
    credentials: "same-origin"
  });
  if (!response.ok) throw await responseError(response);
  const payload = await response.json();
  csrfToken = payload.token || "";
  if (!csrfToken) throw new Error("CSRF token is missing");
}

async function apiFetch(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const changesState = !["GET", "HEAD", "OPTIONS"].includes(method);
  if (changesState) await ensureCSRFToken();

  const response = await fetch(`${apiBase}${path}`, {
    ...options,
    headers: requestHeaders(changesState, Boolean(options.body)),
    credentials: "same-origin"
  });
  if (!response.ok) throw await responseError(response);
  if (response.status === 204) return null;
  return response.json();
}

// собираем нормальную ошибку из ответа API
async function responseError(response) {
  let message = `${response.status} ${response.statusText}`;
  try {
    const payload = await response.json();
    if (payload.error) message += ` - ${payload.error}`;
  } catch (_) {
    // не json, оставляем только статус
  }
  return new Error(message);
}

async function connect() {
  csrfToken = "";
  try {
    await ensureCSRFToken();
    await loadAll();
    setStatus("Connected", true);
  } catch (error) {
    setStatus(`Error: ${error.message}`);
  }
}

async function loadAll() {
  if (!apiKey()) {
    setStatus("Error: API key is required");
    return;
  }
  setStatus("Refreshing...");
  try {
    await Promise.all([loadDevices(false), loadSessions(false), loadDomains(false)]);
    setStatus("");
  } catch (error) {
    setStatus(`Error: ${error.message}`);
  }
}

function deviceQuery() {
  const params = new URLSearchParams({
    page: String(devicePage),
    per_page: "50"
  });
  const values = {
    status: document.getElementById("deviceStatus").value,
    connected: document.getElementById("deviceConnected").value,
    last_seen_from: document.getElementById("deviceLastSeenFrom").value,
    last_seen_to: document.getElementById("deviceLastSeenTo").value
  };
  for (const [key, value] of Object.entries(values)) {
    if (value) params.set(key, value);
  }
  return params.toString();
}

async function loadDevices(handleError = true) {
  try {
    const payload = await apiFetch(`/devices?${deviceQuery()}`);
    const tbody = document.getElementById("devices");
    tbody.replaceChildren();
    devicePage = payload.page;
    deviceTotalPages = payload.total_pages;
    document.getElementById("deviceCount").textContent = String(payload.total);
    document.getElementById("devicePage").textContent =
      `Page ${payload.page}${payload.total_pages ? ` of ${payload.total_pages}` : ""}`;
    document.getElementById("previousDevices").disabled = payload.page <= 1;
    document.getElementById("nextDevices").disabled =
      payload.total_pages === 0 || payload.page >= payload.total_pages;

    for (const device of payload.items) {
      const actions = document.createElement("div");
      actions.className = "row-actions";
      const sessions = button("Sessions", "secondary");
      sessions.addEventListener("click", () => showDeviceSessions(device.fingerprint));
      actions.appendChild(sessions);
      if (device.status !== "device_status_revoked") {
        const revoke = button("Revoke", "danger");
        revoke.addEventListener("click", () => revokeDevice(device, revoke));
        actions.appendChild(revoke);
      }

      tbody.appendChild(row([
        codeCell(device.fingerprint),
        badgeCell(device.status, device.status === "device_status_revoked" ? "revoked" : "active"),
        badgeCell(device.connected ? `${device.active_session_count} active` : "offline", device.connected ? "active" : ""),
        textCell(String(device.domain_count)),
        textCell(formatDate(device.last_seen_at)),
        nodeCell(actions)
      ]));
    }
  } catch (error) {
    if (handleError) setStatus(`Error: ${error.message}`);
    else throw error;
  }
}

function resetDeviceFilters() {
  for (const id of ["deviceStatus", "deviceConnected", "deviceLastSeenFrom", "deviceLastSeenTo"]) {
    document.getElementById(id).value = "";
  }
  devicePage = 1;
  loadDevices();
}

function showDeviceSessions(fingerprint) {
  document.getElementById("sessionFingerprint").value = fingerprint;
  loadSessions();
}

async function revokeDevice(device, control) {
  if (!confirm(`Revoke device ${device.fingerprint}?`)) return;
  control.disabled = true;
  try {
    await apiFetch(`/devices/${encodeURIComponent(device.fingerprint)}/revoke`, {
      method: "POST"
    });
    await Promise.all([loadDevices(false), loadSessions(false), loadDomains(false)]);
    setStatus("Device revoked", true);
  } catch (error) {
    setStatus(`Error: ${error.message}`);
  } finally {
    control.disabled = false;
  }
}

async function loadSessions(handleError = true) {
  try {
    const fingerprint = document.getElementById("sessionFingerprint").value.trim();
    const query = fingerprint ? `?fingerprint=${encodeURIComponent(fingerprint)}` : "";
    const sessions = await apiFetch(`/sessions${query}`);
    const tbody = document.getElementById("sessions");
    tbody.replaceChildren();
    document.getElementById("sessionCount").textContent = String(sessions.length);
    document.getElementById("sessionsTitle").textContent = fingerprint ? "Device sessions" : "Active sessions";
    for (const session of sessions) {
      tbody.appendChild(row([
        codeCell(session.id),
        codeCell(session.fingerprint),
        textCell(formatDate(session.opened_at)),
        textCell(formatDate(session.closed_at)),
        badgeCell(session.active ? "active" : "closed", session.active ? "active" : "")
      ]));
    }
  } catch (error) {
    if (handleError) setStatus(`Error: ${error.message}`);
    else throw error;
  }
}

function resetSessionFilters() {
  document.getElementById("sessionFingerprint").value = "";
  loadSessions();
}

function domainQuery() {
  const params = new URLSearchParams({
    page: String(domainPage),
    per_page: "50"
  });
  const values = {
    q: document.getElementById("domainSearch").value.trim(),
    status: document.getElementById("domainStatus").value,
    device: document.getElementById("domainDevice").value.trim(),
    from: document.getElementById("domainFrom").value,
    to: document.getElementById("domainTo").value
  };
  for (const [key, value] of Object.entries(values)) {
    if (value) params.set(key, value);
  }
  return params.toString();
}

async function loadDomains(handleError = true) {
  try {
    const payload = await apiFetch(`/domains?${domainQuery()}`);
    const tbody = document.getElementById("domains");
    tbody.replaceChildren();
    domainPage = payload.page;
    domainTotalPages = payload.total_pages;
    document.getElementById("domainCount").textContent = String(payload.total);
    document.getElementById("domainPage").textContent =
      `Page ${payload.page}${payload.total_pages ? ` of ${payload.total_pages}` : ""}`;
    document.getElementById("previousDomains").disabled = payload.page <= 1;
    document.getElementById("nextDomains").disabled =
      payload.total_pages === 0 || payload.page >= payload.total_pages;

    for (const domain of payload.items) {
      const actions = document.createElement("div");
      actions.className = "row-actions";
      if (domain.status === "domain_status_registered" || domain.status === "domain_status_bound") {
        const disable = button("Disable");
        disable.addEventListener("click", () => setDomainStatus(domain.id, "domain_status_disabled", disable));
        actions.appendChild(disable);
      } else if (domain.status === "domain_status_disabled") {
        const enable = button("Enable");
        enable.addEventListener("click", () => setDomainStatus(domain.id, "domain_status_registered", enable));
        actions.appendChild(enable);
      }
      const remove = button("Delete", "danger");
      remove.addEventListener("click", () => deleteDomain(domain, remove));
      actions.appendChild(remove);

      const fqdn = document.createElement("div");
      fqdn.appendChild(document.createTextNode(domain.fqdn || ""));
      const id = document.createElement("div");
      id.className = "muted";
      id.textContent = domain.id || "";
      fqdn.appendChild(id);

      tbody.appendChild(row([
        nodeCell(fqdn),
        badgeCell(domain.status, domain.status === "domain_status_disabled" ? "disabled" : "active"),
        codeCell(domain.device_fingerprint || domain.device_id),
        textCell(formatDate(domain.created_at)),
        nodeCell(actions)
      ]));
    }
  } catch (error) {
    if (handleError) setStatus(`Error: ${error.message}`);
    else throw error;
  }
}

async function addDomain() {
  const fqdn = document.getElementById("newDomain").value.trim();
  const deviceFingerprint = document.getElementById("ownerFingerprint").value.trim();
  if (!fqdn || !deviceFingerprint) {
    setStatus("Error: FQDN and device fingerprint are required");
    return;
  }
  try {
    await apiFetch("/domains", {
      method: "POST",
      body: JSON.stringify({ fqdn, device_fingerprint: deviceFingerprint })
    });
    document.getElementById("newDomain").value = "";
    domainPage = 1;
    await Promise.all([loadDomains(false), loadDevices(false)]);
    setStatus("Domain added", true);
  } catch (error) {
    setStatus(`Error: ${error.message}`);
  }
}

async function setDomainStatus(id, status, control) {
  control.disabled = true;
  try {
    await apiFetch(`/domains/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify({ status })
    });
    await loadDomains(false);
    setStatus("Domain updated", true);
  } catch (error) {
    setStatus(`Error: ${error.message}`);
  } finally {
    control.disabled = false;
  }
}

async function deleteDomain(domain, control) {
  if (!confirm(`Delete ${domain.fqdn}?`)) return;
  control.disabled = true;
  try {
    await apiFetch(`/domains/${encodeURIComponent(domain.id)}`, { method: "DELETE" });
    await Promise.all([loadDomains(false), loadDevices(false)]);
    setStatus("Domain deleted", true);
  } catch (error) {
    setStatus(`Error: ${error.message}`);
  } finally {
    control.disabled = false;
  }
}

function resetDomainFilters() {
  for (const id of ["domainSearch", "domainStatus", "domainDevice", "domainFrom", "domainTo"]) {
    document.getElementById(id).value = "";
  }
  domainPage = 1;
  loadDomains();
}

function row(cells) {
  const tr = document.createElement("tr");
  for (const cell of cells) tr.appendChild(cell);
  return tr;
}

function textCell(value) {
  const td = document.createElement("td");
  td.textContent = value || "";
  return td;
}

function codeCell(value) {
  const code = document.createElement("code");
  code.textContent = value || "";
  return nodeCell(code);
}

function nodeCell(node) {
  const td = document.createElement("td");
  td.appendChild(node);
  return td;
}

function badgeCell(value, className) {
  const badge = document.createElement("span");
  badge.className = `badge ${className}`.trim();
  badge.textContent = value || "";
  return nodeCell(badge);
}

function button(label, className = "") {
  const result = document.createElement("button");
  result.type = "button";
  result.textContent = label;
  result.className = className;
  return result;
}

function formatDate(value) {
  if (!value) return "";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function setStatus(message, success = false) {
  const status = document.getElementById("status");
  status.textContent = message || "";
  status.className = success ? "status success" : "status";
}

async function loadLogs() {
  const source = document.getElementById("logSource").value;
  const lines = parseInt(document.getElementById("logLines").value, 10) || 200;
  const output = document.getElementById("logOutput");
  try {
    const payload = await apiFetch(`/logs?source=${encodeURIComponent(source)}&lines=${lines}`);
    if (!payload || !payload.lines) {
      output.textContent = "(empty)";
      return;
    }
    output.textContent = payload.lines.join("\n") || "(empty)";
    output.scrollTop = output.scrollHeight;
  } catch (error) {
    output.textContent = `Error: ${error.message}`;
    // Если логи не читаются, не дергаем сервер дальше.
    if (logAutoRefreshTimer !== null) {
      stopLogAutoRefresh();
      setStatus(`Log auto-refresh stopped: ${error.message}`);
    }
  }
}

function stopLogAutoRefresh() {
  clearInterval(logAutoRefreshTimer);
  logAutoRefreshTimer = null;
  document.getElementById("logAutoRefresh").checked = false;
}

function toggleLogAutoRefresh() {
  if (document.getElementById("logAutoRefresh").checked) {
    if (logAutoRefreshTimer !== null) return;
    loadLogs();
    logAutoRefreshTimer = setInterval(loadLogs, 5000);
  } else {
    stopLogAutoRefresh();
  }
}

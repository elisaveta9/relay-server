"use strict";

const apiBase = "/api/v1";

document.getElementById("refreshDomains").addEventListener("click", loadDomains);
document.getElementById("addDomain").addEventListener("click", addDomain);

function headers() {
  return {
    "Authorization": `Bearer ${document.getElementById("apiKey").value}`,
    "Content-Type": "application/json; charset=utf-8"
  };
}

function renderJsonErrorText(payload) {
  if (!payload) return "";
  if (typeof payload === "string") return payload;
  if (payload.error) return payload.error;
  if (payload.message) return payload.message;
  return JSON.stringify(payload);
}

async function loadDomains() {
  setStatus("Refreshing...");
  try {
    const res = await fetch(`${apiBase}/domains`, { headers: headers() });
    if (!res.ok) return showErrorFromResponse(res);

    const list = await res.json();
    const tbody = document.getElementById("domains");
    tbody.innerHTML = "";

    list.forEach(d => {
      const tr = document.createElement("tr");

      const tdFqdn = document.createElement("td");
      const fqdnText = document.createElement("div");
      fqdnText.textContent = d.fqdn || "";

      const idWrap = document.createElement("div");
      idWrap.className = "muted";

      const code = document.createElement("code");
      code.textContent = d.id || "";

      idWrap.appendChild(code);

      tdFqdn.appendChild(fqdnText);
      tdFqdn.appendChild(idWrap);

      const tdStatus = document.createElement("td");
      tdStatus.textContent = d.status || "";

      const tdDevice = document.createElement("td");
      tdDevice.textContent = d.device_id ? d.device_id : "";

      const tdActions = document.createElement("td");
      tdActions.className = "row-actions";

      if (d.status === "domain_status_registered") {
        const disableBtn = document.createElement("button");
        disableBtn.textContent = "Disable";
        disableBtn.addEventListener("click", async () => {
          disableBtn.disabled = true;
          try {
            await setDomainStatus(d.id, "domain_status_disabled");
          } finally {
            disableBtn.disabled = false;
          }
        });
        tdActions.appendChild(disableBtn);
      } else if (d.status === "domain_status_disabled") {
        const enableBtn = document.createElement("button");
        enableBtn.textContent = "Enable";
        enableBtn.addEventListener("click", async () => {
          enableBtn.disabled = true;
          try {
            await setDomainStatus(d.id, "domain_status_registered");
          } finally {
            enableBtn.disabled = false;
          }
        });
        tdActions.appendChild(enableBtn);
      }

      const deleteBtn = document.createElement("button");
      deleteBtn.textContent = "Delete";
      deleteBtn.addEventListener("click", async () => {
        if (!confirm("Delete domain?")) return;
        deleteBtn.disabled = true;
        try {
          const res = await fetch(`${apiBase}/domains/${encodeURIComponent(d.id)}`, {
            method: "DELETE",
            headers: headers()
          });
          if (!res.ok) return showErrorFromResponse(res);
          await loadDomains();
        } catch (err) {
          setStatus(`Error: network failure${err && err.message ? " - " + err.message : ""}`);
        } finally {
          deleteBtn.disabled = false;
        }
      });
      tdActions.appendChild(deleteBtn);

      tbody.appendChild(tr);
      tr.appendChild(tdFqdn);
      tr.appendChild(tdStatus);
      tr.appendChild(tdDevice);
      tr.appendChild(tdActions);
    });

    setStatus("");
  } catch (err) {
    setStatus(`Error: network failure${err && err.message ? " - " + err.message : ""}`);
  }
}

async function addDomain() {
  setStatus("");
  const fqdn = document.getElementById("newDomain").value.trim();
  const deviceFingerprint = document.getElementById("ownerFingerprint").value.trim();
  if (!fqdn) return;

  try {
    const res = await fetch(`${apiBase}/domains`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        fqdn,
        device_fingerprint: deviceFingerprint
      })
    });

    if (!res.ok) return showErrorFromResponse(res);

    document.getElementById("newDomain").value = "";
    await loadDomains();
  } catch (err) {
    setStatus(`Error: network failure${err && err.message ? " - " + err.message : ""}`);
  }
}

async function setDomainStatus(id, status) {
  setStatus("Applying...");
  try {
    const res = await fetch(`${apiBase}/domains/${encodeURIComponent(id)}`, {
      method: "PATCH",
      headers: headers(),
      body: JSON.stringify({ status })
    });

    if (!res.ok) {
      return showErrorFromResponse(res);
    }

    await loadDomains();
  } catch (err) {
    setStatus(`Error: network failure${err && err.message ? " - " + err.message : ""}`);
  }
}

async function showErrorFromResponse(res) {
  let payload = null;
  try {
    payload = await res.json();
  } catch (_) {
    // Ignore non-JSON error responses.
  }
  const text = renderJsonErrorText(payload);
  document.getElementById("status").textContent =
    `Error: ${res.status} ${res.statusText}${text ? " - " + text : ""}`;
}

function setStatus(msg) {
  document.getElementById("status").textContent = msg || "";
}

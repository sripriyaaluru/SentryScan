// Dashboard interactivity: thin fetch() wrappers around the SentryScan REST API.
// All of these simply call /api/* -- the server-side authorization guard is the real
// safety mechanism; this file has no special privileges.

function setStatus(msg, isError = false) {
  const el = document.getElementById("action-status");
  if (!el) return;
  el.textContent = msg;
  el.className = isError ? "badge badge-warn" : "empty";
}

async function createTarget(event) {
  event.preventDefault();
  const name = document.getElementById("t-name").value;
  const host = document.getElementById("t-host").value;
  const description = document.getElementById("t-desc").value;
  const res = await fetch("/api/targets", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, host, description }),
  });
  if (res.ok) {
    location.reload();
  } else {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    alert("Failed to create target: " + (err.detail || res.statusText));
  }
}

async function runRecon(targetId) {
  setStatus("Running recon...");
  try {
    const res = await fetch("/api/recon/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_id: targetId, arguments: "-sV -T4" }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    setStatus(`Recon scan job #${data.id}: ${data.status}`);
    setTimeout(() => location.reload(), 800);
  } catch (e) {
    setStatus("Recon failed: " + e.message, true);
  }
}

async function runVulnAssessment() {
  if (!window.latestJobId) { setStatus("Run Recon first.", true); return; }
  setStatus("Assessing vulnerabilities...");
  try {
    const res = await fetch("/api/vulnerabilities/assess", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_job_id: window.latestJobId, run_nse_scripts: false }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    setStatus(`Found ${data.length} finding(s).`);
    setTimeout(() => location.reload(), 800);
  } catch (e) {
    setStatus("Vulnerability assessment failed: " + e.message, true);
  }
}

async function computeRisk() {
  if (!window.latestJobId) { setStatus("Run Recon first.", true); return; }
  setStatus("Computing risk...");
  try {
    const res = await fetch(`/api/risk/compute/${window.latestJobId}`, { method: "POST" });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    setStatus(`Risk: ${data.severity_level} (${data.overall_score}/10)`);
    setTimeout(() => location.reload(), 800);
  } catch (e) {
    setStatus("Risk computation failed: " + e.message, true);
  }
}

async function generateReport(format) {
  if (!window.latestJobId) { setStatus("Run Recon first.", true); return; }
  setStatus(`Generating ${format.toUpperCase()} report...`);
  try {
    const res = await fetch("/api/reports/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_job_id: window.latestJobId, format }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    setStatus(`Report #${data.id} generated.`);
    window.open(`/api/reports/${data.id}/download`, "_blank");
    setTimeout(() => location.reload(), 500);
  } catch (e) {
    setStatus("Report generation failed: " + e.message, true);
  }
}

"use strict";

// DOM Elements
const form = document.querySelector("#scan-form");
const input = document.querySelector("#url-input");
const clearInputBtn = document.querySelector("#clear-input");
const submitBtn = document.querySelector("#scan-button");
const errorBanner = document.querySelector("#error-message");
const scanHud = document.querySelector("#scan-hud");
const hudStepText = document.querySelector("#hud-step-text");
const report = document.querySelector("#report");
const systemStatusText = document.querySelector("#system-status");
const toast = document.querySelector("#toast");
const toastMessage = document.querySelector("#toast-message");
const presetChips = document.querySelectorAll(".preset-chip");

const toggleJsonBtn = document.querySelector("#toggle-json-btn");
const toggleJsonText = document.querySelector("#toggle-json-text");
const rawJsonPanel = document.querySelector("#raw-json-panel");
const jsonViewer = document.querySelector("#json-viewer");

const copyUrlBtn = document.querySelector("#copy-url-btn");
const copyReportBtn = document.querySelector("#copy-report-btn");
const copyJsonBtn = document.querySelector("#copy-json-btn");

let currentReportData = null;
let hudInterval = null;
let toastTimeout = null;

// Telemetry & Health Check
async function refreshEngineHealth() {
  const startTime = performance.now();
  try {
    const response = await fetch("/api/health");
    const health = await response.json();
    const latency = Math.round(performance.now() - startTime);

    if (health.model_loaded) {
      systemStatusText.textContent = `ONLINE [${latency}ms]`;
    } else {
      systemStatusText.textContent = "MODEL UNTRAINED";
    }
  } catch {
    systemStatusText.textContent = "API OFFLINE";
  }
}

refreshEngineHealth();

// Clear button visibility toggle
input.addEventListener("input", () => {
  clearInputBtn.hidden = input.value.trim().length === 0;
});

clearInputBtn.addEventListener("click", () => {
  input.value = "";
  clearInputBtn.hidden = true;
  input.focus();
  clearError();
});

// Keyboard Shortcuts: '/' to focus, 'Escape' to clear
document.addEventListener("keydown", (event) => {
  if (
    event.key === "/" &&
    document.activeElement !== input &&
    !["input", "textarea"].includes(document.activeElement.tagName.toLowerCase())
  ) {
    event.preventDefault();
    input.focus();
    input.select();
  } else if (event.key === "Escape") {
    if (document.activeElement === input) {
      input.blur();
    }
  }
});

// Preset Chips Quick Audit
presetChips.forEach((chip) => {
  chip.addEventListener("click", () => {
    const targetUrl = chip.getAttribute("data-url");
    if (targetUrl) {
      input.value = targetUrl;
      clearInputBtn.hidden = false;
      clearError();
      executeAudit(targetUrl);
    }
  });
});

// Form Submission
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const rawUrl = input.value.trim();
  if (!rawUrl) {
    showError("Please enter a destination URL or domain to audit.");
    input.focus();
    return;
  }
  executeAudit(rawUrl);
});

// Execute URL Audit
async function executeAudit(url) {
  clearError();
  startScanningHud();

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || "Analysis engine rejected request.");
    }

    currentReportData = payload;
    renderForensicReport(payload);
  } catch (error) {
    showError(error.message || "Could not complete link analysis.");
    report.hidden = true;
  } finally {
    stopScanningHud();
  }
}

// Scanning HUD Animation
const HUD_STEPS = [
  "> DECOMPOSING URI SCHEMA AND NORMALIZING HOSTNAME...",
  "> PARSING TOPOLOGICAL LABELS & ENTROPY RATIO...",
  "> EXAMINING BRAND HOMOGRAPH & IMPERSONATION VECTORS...",
  "> EXTRACTING CHARACTER N-GRAM TF-IDF MATRICES...",
  "> SYNTHESIZING COMPOSITE ZERO-TRUST FORENSIC VERDICT...",
];

function startScanningHud() {
  submitBtn.disabled = true;
  submitBtn.querySelector(".btn-text").textContent = "AUDITING...";
  scanHud.hidden = false;
  report.hidden = true;

  let stepIdx = 0;
  hudStepText.textContent = HUD_STEPS[stepIdx];
  hudInterval = setInterval(() => {
    stepIdx = (stepIdx + 1) % HUD_STEPS.length;
    hudStepText.textContent = HUD_STEPS[stepIdx];
  }, 190);
}

function stopScanningHud() {
  submitBtn.disabled = false;
  submitBtn.querySelector(".btn-text").textContent = "AUDIT LINK";
  scanHud.hidden = true;
  if (hudInterval) {
    clearInterval(hudInterval);
    hudInterval = null;
  }
}

// Render Forensic Report
function renderForensicReport(data) {
  report.hidden = false;

  const isPhishing = data.prediction === "phishing";
  const score = Number(data.phishing_score);

  // Verdict Header & Pill
  const verdictEl = document.querySelector("#verdict");
  const pillEl = document.querySelector("#prediction-pill");

  if (isPhishing) {
    verdictEl.textContent = "MALICIOUS PATTERN IDENTIFIED";
    pillEl.textContent = "THREAT CONFIRMED";
    pillEl.className = "verdict-pill threat";
  } else {
    verdictEl.textContent = "BENIGN VERIFIED SIGNALS";
    pillEl.textContent = "BENIGN VERIFIED";
    pillEl.className = "verdict-pill safe";
  }

  // URL display
  document.querySelector("#result-url").textContent = data.url;

  // Animate Numerical Score Count-up
  animateScoreValue(score);

  // Risk Tier Label
  const tierLabel = document.querySelector("#risk-tier-label");
  if (score >= 75) {
    tierLabel.textContent = "CRITICAL DECEPTION RISK // IMMEDIATE SPOOF HAZARD";
  } else if (score >= 45) {
    tierLabel.textContent = "ELEVATED ANOMALOUS PROFILE // HIGH CAUTION";
  } else if (score >= 15) {
    tierLabel.textContent = "MODERATE / GENERAL REPUTATION PATTERN";
  } else {
    tierLabel.textContent = "AUTHENTIC HIGH-REPUTATION TARGET // ZERO SPOOF";
  }

  // Mechanical Segmented VU Meter (20 segments)
  renderVuMeter(score);

  // Engine Note
  document.querySelector("#score-note").textContent =
    `Model: ${data.model_name}. Composite intelligence combines canonical char n-gram Logistic Regression with active brand spoofing heuristics.`;

  // 4 Diagnostics Cards
  document.querySelector("#diag-host").textContent = data.hostname;
  document.querySelector("#diag-reg").textContent = `ROOT: ${data.registered_domain || data.hostname}`;

  const diag = data.diagnostics || {};
  document.querySelector("#diag-proto").textContent = diag.protocol || "HTTPS";
  document.querySelector("#diag-port").textContent = `PORT: ${diag.port || 443}`;

  document.querySelector("#diag-ml").textContent = `${data.ml_score}%`;
  document.querySelector("#diag-heur").textContent = `HEURISTIC FACTOR: ${data.heuristic_score}%`;

  document.querySelector("#diag-signals-count").textContent = `${data.findings ? data.findings.length : 0}`;
  document.querySelector("#diag-auth").textContent = data.is_top_authority
    ? "AUTHORITY: TOP-TIER"
    : "AUTHORITY: STANDARD";

  // Evidence Ledger
  renderFindings(data.findings || []);

  // Caveat
  document.querySelector("#caveat").textContent = data.caveat;

  // JSON Previewer
  jsonViewer.textContent = JSON.stringify(data, null, 2);

  // Scroll to report smoothly
  report.scrollIntoView({ behavior: "smooth", block: "start" });
}

// Animate Score Counter
function animateScoreValue(targetScore) {
  const scoreEl = document.querySelector("#score");
  const duration = 500;
  const startTime = performance.now();

  function step(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = (targetScore * eased).toFixed(1);
    scoreEl.textContent = current;

    if (progress < 1) {
      requestAnimationFrame(step);
    } else {
      scoreEl.textContent = targetScore.toFixed(1);
    }
  }

  requestAnimationFrame(step);
}

// Render 20-Segment Mechanical VU Meter
function renderVuMeter(score) {
  const meter = document.querySelector("#vu-meter");
  meter.replaceChildren();

  const totalSegments = 20;
  const activeSegments = Math.round((score / 100) * totalSegments);

  for (let i = 0; i < totalSegments; i++) {
    const seg = document.createElement("div");
    seg.className = "vu-segment";
    if (i < activeSegments) {
      seg.classList.add("active");
    }
    meter.appendChild(seg);
  }
}

// Render Findings List
function renderFindings(findings) {
  const list = document.querySelector("#finding-list");
  list.replaceChildren();

  const countBadge = document.querySelector("#finding-count");
  countBadge.textContent = `${findings.length} SIGNAL${findings.length === 1 ? "" : "S"} DETECTED`;

  for (const finding of findings) {
    const item = document.createElement("li");
    const severity = (finding.severity || "info").toLowerCase();
    item.className = `evidence-item ${severity}`;

    const tag = document.createElement("span");
    tag.className = `evidence-severity-tag ${severity}`;
    tag.textContent = `[${severity.toUpperCase()}]`;

    const body = document.createElement("div");
    body.className = "evidence-body";

    const title = document.createElement("span");
    title.className = "evidence-title";
    title.textContent = finding.name;

    const desc = document.createElement("p");
    desc.className = "evidence-desc";
    desc.textContent = finding.detail;

    body.append(title, desc);
    item.append(tag, body);
    list.append(item);
  }
}

// Error Handling
function showError(msg) {
  errorBanner.textContent = `[ERROR] ${msg}`;
  errorBanner.hidden = false;
}

function clearError() {
  errorBanner.textContent = "";
  errorBanner.hidden = true;
}

// Toast Feedback Notification
function showToast(message) {
  if (toastTimeout) {
    clearTimeout(toastTimeout);
  }
  toastMessage.textContent = message;
  toast.hidden = false;
  toastTimeout = setTimeout(() => {
    toast.hidden = true;
  }, 2200);
}

// Copy Handlers
copyUrlBtn.addEventListener("click", () => {
  if (currentReportData && currentReportData.url) {
    navigator.clipboard.writeText(currentReportData.url).then(() => {
      showToast("TARGET URL COPIED");
    });
  }
});

copyJsonBtn.addEventListener("click", () => {
  if (currentReportData) {
    navigator.clipboard.writeText(JSON.stringify(currentReportData, null, 2)).then(() => {
      showToast("TELEMETRY JSON COPIED");
    });
  }
});

copyReportBtn.addEventListener("click", () => {
  if (!currentReportData) return;

  const d = currentReportData;
  const findingsSummary = (d.findings || [])
    .map((f) => `- [${(f.severity || "INFO").toUpperCase()}] ${f.name}: ${f.detail}`)
    .join("\n");

  const reportText = [
    `# PHISH // ZERO FORENSIC AUDIT REPORT`,
    `Target: ${d.url}`,
    `Hostname: ${d.hostname} (Root: ${d.registered_domain})`,
    `Verdict: ${d.prediction.toUpperCase()}`,
    `Phishing Score: ${d.phishing_score} / 100 (ML: ${d.ml_score}%, Heuristic: ${d.heuristic_score}%)`,
    `Authority: ${d.is_top_authority ? "VERIFIED TOP-TIER" : "STANDARD"}`,
    `Model: ${d.model_name}`,
    ``,
    `## Forensic Signals (${(d.findings || []).length})`,
    findingsSummary,
  ].join("\n");

  navigator.clipboard.writeText(reportText).then(() => {
    showToast("AUDIT REPORT COPIED TO CLIPBOARD");
  });
});

// Raw JSON Panel Toggle
toggleJsonBtn.addEventListener("click", () => {
  const isHidden = rawJsonPanel.hidden;
  rawJsonPanel.hidden = !isHidden;
  toggleJsonText.textContent = isHidden
    ? "HIDE RAW TELEMETRY JSON"
    : "VIEW RAW TELEMETRY JSON";
});

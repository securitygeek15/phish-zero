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

// Dissector DOM Elements
const dissectorChain = document.querySelector("#dissector-chain");
const inspectorType = document.querySelector("#inspector-type");
const inspectorVal = document.querySelector("#inspector-val");
const inspectorSeverity = document.querySelector("#inspector-severity");
const inspectorDesc = document.querySelector("#inspector-desc");
const inspectorLen = document.querySelector("#inspector-len");
const inspectorEntropy = document.querySelector("#inspector-entropy");
const inspectorTag = document.querySelector("#inspector-tag");
const copyTokenBtn = document.querySelector("#copy-token-btn");

// Graph Analyzer DOM Elements
const graphTabs = document.querySelectorAll(".graph-tab");
const graphViewport = document.querySelector(".graph-viewport");
const radarContainer = document.querySelector("#radar-container");
const topologyContainer = document.querySelector("#topology-container");
const radarSvg = document.querySelector("#radar-svg");
const vectorCardsGrid = document.querySelector("#vector-cards-grid");
const topologySvg = document.querySelector("#topology-svg");
const routeSummaryText = document.querySelector("#route-summary-text");
const routeVerdictBox = document.querySelector("#route-verdict-box");

let currentReportData = null;
let currentSelectedToken = null;
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

const navQuickFocusBtn = document.querySelector("#nav-quick-focus-btn");
if (navQuickFocusBtn) {
  navQuickFocusBtn.addEventListener("click", () => {
    input.focus();
    input.select();
  });
}

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
async function executeAudit(url, vector = "direct_input") {
  clearError();
  startScanningHud();

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, vector }),
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

  const score = Number(data.phishing_score);
  const threatLevel = data.threat_level || (
    score >= 70 ? "danger" :
    score >= 45 ? "warning" :
    score >= 15 ? "caution" : "safe"
  );

  // Apply 4-tier state theming class to #report container
  report.classList.remove("state-danger", "state-warning", "state-caution", "state-safe");
  report.classList.add(`state-${threatLevel}`);

  // Verdict Header & Pill
  const verdictEl = document.querySelector("#verdict");
  const pillEl = document.querySelector("#prediction-pill");

  if (threatLevel === "danger") {
    verdictEl.textContent = "MALICIOUS PATTERN IDENTIFIED";
    pillEl.textContent = data.threat_label || "DANGEROUS // THREAT CONFIRMED";
    pillEl.className = "verdict-pill danger";
  } else if (threatLevel === "warning") {
    verdictEl.textContent = "POTENTIAL THREAT SUSPECTED";
    pillEl.textContent = data.threat_label || "POTENTIALLY DANGEROUS";
    pillEl.className = "verdict-pill warning";
  } else if (threatLevel === "caution") {
    verdictEl.textContent = "STANDARD DOMAIN / LOW RISK";
    pillEl.textContent = data.threat_label || "POTENTIALLY SAFE";
    pillEl.className = "verdict-pill caution";
  } else {
    verdictEl.textContent = "BENIGN VERIFIED SIGNALS";
    pillEl.textContent = data.threat_label || "SAFE // VERIFIED";
    pillEl.className = "verdict-pill safe";
  }

  // Attack Vector Banner (Quishing / Direct)
  const vectorBanner = document.querySelector("#vector-banner");
  const vectorBannerName = document.querySelector("#vector-banner-name");
  if (vectorBanner && vectorBannerName) {
    if (data.vector === "quishing") {
      vectorBanner.hidden = false;
      vectorBanner.className = "vector-banner";
      if (threatLevel === "safe") {
        vectorBanner.classList.add("safe-vector");
        vectorBannerName.textContent = "QR CODE PAYLOAD (QUISHING AUDIT: BENIGN)";
      } else if (threatLevel === "warning") {
        vectorBanner.classList.add("warning-vector");
        vectorBannerName.textContent = "QR CODE PHISHING VECTOR (QUISHING: ELEVATED RISK)";
      } else {
        vectorBannerName.textContent = "QR CODE PHISHING VECTOR (QUISHING DETECTED)";
      }
    } else {
      vectorBanner.hidden = true;
    }
  }

  // URL display
  document.querySelector("#result-url").textContent = data.url;

  // 1. Render Interactive URL Dissector
  if (data.dissection && Array.isArray(data.dissection)) {
    renderDissector(data.dissection);
  }

  // Animate Numerical Score Count-up
  animateScoreValue(score);

  // Risk Tier Label
  const tierLabel = document.querySelector("#risk-tier-label");
  if (threatLevel === "danger") {
    tierLabel.textContent = "CRITICAL DECEPTION RISK // IMMEDIATE SPOOF HAZARD";
  } else if (threatLevel === "warning") {
    tierLabel.textContent = "ELEVATED ANOMALOUS PROFILE // HIGH CAUTION";
  } else if (threatLevel === "caution") {
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

  // 2. Render Graph Analyzer (Radar & Topology Route)
  if (data.graph_data) {
    renderGraphAnalyzer(data.graph_data, threatLevel);
  }

  // 3. Render Explainable AI (XAI) Attribution Lens
  if (data.xai) {
    renderXaiExplainer(data.xai, threatLevel);
  }

  // Evidence Ledger
  renderFindings(data.findings || []);

  // Caveat
  document.querySelector("#caveat").textContent = data.caveat;

  // JSON Previewer
  jsonViewer.textContent = JSON.stringify(data, null, 2);

  // Scroll to report smoothly
  report.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ==========================================
// INTERACTIVE URL DISSECTOR
// ==========================================
function renderDissector(tokens) {
  dissectorChain.replaceChildren();

  let highestRiskToken = null;
  const severityRank = { critical: 4, high: 3, medium: 2, info: 1, clean: 0 };
  let maxRank = -1;

  tokens.forEach((token) => {
    const tokenEl = document.createElement("button");
    tokenEl.type = "button";
    tokenEl.className = `dissector-token ${token.severity || "clean"}`;
    tokenEl.setAttribute("role", "tab");
    tokenEl.setAttribute("aria-selected", "false");

    const metaRow = document.createElement("div");
    metaRow.className = "token-meta-row";

    const label = document.createElement("span");
    label.className = "token-label";
    label.textContent = token.label;

    const badge = document.createElement("span");
    badge.className = `token-badge ${token.severity || "clean"}`;
    badge.textContent = (token.severity || "clean").toUpperCase();

    metaRow.append(label, badge);

    const val = document.createElement("span");
    val.className = "token-value";
    val.textContent = token.value;

    tokenEl.append(metaRow, val);

    // Event listener
    tokenEl.addEventListener("click", () => {
      selectDissectorToken(token, tokenEl);
    });

    dissectorChain.appendChild(tokenEl);

    const rank = severityRank[token.severity] || 0;
    if (rank > maxRank) {
      maxRank = rank;
      highestRiskToken = { token, element: tokenEl };
    }
  });

  // Default selection: select highest risk token, or apex domain, or first token
  if (highestRiskToken) {
    selectDissectorToken(highestRiskToken.token, highestRiskToken.element);
  } else if (tokens.length > 0) {
    selectDissectorToken(tokens[0], dissectorChain.firstElementChild);
  }
}

function selectDissectorToken(token, tokenEl) {
  currentSelectedToken = token;

  // Update active state in UI
  document.querySelectorAll(".dissector-token").forEach((el) => {
    el.classList.remove("active");
    el.setAttribute("aria-selected", "false");
  });
  if (tokenEl) {
    tokenEl.classList.add("active");
    tokenEl.setAttribute("aria-selected", "true");
  }

  // Update inspector card
  inspectorType.textContent = token.label;
  inspectorVal.textContent = token.value;

  const sev = (token.severity || "clean").toLowerCase();
  inspectorSeverity.textContent = sev.toUpperCase();
  inspectorSeverity.className = `severity-pill ${sev}`;

  inspectorDesc.textContent = token.explanation || "Decomposed URL segment.";
  inspectorLen.textContent = `${token.length} chars`;
  inspectorEntropy.textContent = typeof token.entropy === "number" ? token.entropy.toFixed(2) : "0.00";
  inspectorTag.textContent = token.tag || "URI-TOKEN";
}

copyTokenBtn.addEventListener("click", () => {
  if (currentSelectedToken && currentSelectedToken.value) {
    navigator.clipboard.writeText(currentSelectedToken.value).then(() => {
      showToast(`TOKEN [${currentSelectedToken.label}] COPIED`);
    });
  }
});

// ==========================================
// GRAPH ANALYZER & TOPOLOGY ROUTING
// ==========================================
function renderGraphAnalyzer(graphData, threatLevel = "safe") {
  const riskVectors = graphData.risk_vectors || [];
  const topology = graphData.route_topology || {};

  renderRadarChart(riskVectors, threatLevel);
  renderVectorCards(riskVectors);
  renderTopologyChart(topology, threatLevel);

  // Route verdict summary box
  routeSummaryText.textContent = topology.summary || "Route analysis complete.";
  routeVerdictBox.classList.toggle("diverted", Boolean(topology.is_diverted));
}

// Graph Tab Navigation
graphTabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    const view = tab.getAttribute("data-view");
    graphTabs.forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");

    if (view === "dual") {
      graphViewport.className = "graph-viewport dual";
      radarContainer.classList.add("active");
      topologyContainer.classList.add("active");
    } else if (view === "topology") {
      graphViewport.className = "graph-viewport";
      radarContainer.classList.remove("active");
      topologyContainer.classList.add("active");
    } else {
      graphViewport.className = "graph-viewport";
      radarContainer.classList.add("active");
      topologyContainer.classList.remove("active");
    }
  });
});

// SVG Risk Radar Generator
function renderRadarChart(vectors, threatLevel = "safe") {
  radarSvg.replaceChildren();

  const cx = 230;
  const cy = 190;
  const radius = 125;
  const numAxes = vectors.length || 6;
  const angleStep = (Math.PI * 2) / numAxes;

  const ns = "http://www.w3.org/2000/svg";

  // Concentric Grid Rings (25%, 50%, 75%, 100%)
  const rings = [0.25, 0.50, 0.75, 1.0];
  rings.forEach((level) => {
    const ringPts = [];
    for (let i = 0; i < numAxes; i++) {
      const angle = i * angleStep - Math.PI / 2;
      const x = cx + Math.cos(angle) * (radius * level);
      const y = cy + Math.sin(angle) * (radius * level);
      ringPts.push(`${x.toFixed(1)},${y.toFixed(1)}`);
    }
    const polygon = document.createElementNS(ns, "polygon");
    polygon.setAttribute("points", ringPts.join(" "));
    polygon.setAttribute("fill", level === 1.0 ? "rgba(255, 255, 255, 0.02)" : "none");
    polygon.setAttribute("stroke", "rgba(255, 255, 255, 0.12)");
    polygon.setAttribute("stroke-width", "1");
    if (level === 0.5) {
      polygon.setAttribute("stroke-dasharray", "3,3");
    }
    radarSvg.appendChild(polygon);

    // Percentage Label
    const text = document.createElementNS(ns, "text");
    text.setAttribute("x", cx + 4);
    text.setAttribute("y", cy - (radius * level) - 3);
    text.setAttribute("fill", "rgba(255, 255, 255, 0.25)");
    text.setAttribute("font-family", "JetBrains Mono, monospace");
    text.setAttribute("font-size", "8");
    text.textContent = `${Math.round(level * 100)}%`;
    radarSvg.appendChild(text);
  });

  // 4-Tier Theme Color Palette:
  // Red (danger), Yellow (warning), Blue (caution), Green (safe)
  const themePalette = {
    danger: { stroke: "#ef4444", fill: "rgba(239, 68, 68, 0.24)", ping: "rgba(239, 68, 68, 0.7)", dot: "#ef4444" },
    warning: { stroke: "#f59e0b", fill: "rgba(245, 158, 11, 0.24)", ping: "rgba(245, 158, 11, 0.7)", dot: "#f59e0b" },
    caution: { stroke: "#3b82f6", fill: "rgba(59, 130, 246, 0.24)", ping: "rgba(59, 130, 246, 0.7)", dot: "#60a5fa" },
    safe: { stroke: "#10b981", fill: "rgba(16, 185, 129, 0.24)", ping: "rgba(16, 185, 129, 0.7)", dot: "#10b981" },
  };
  const theme = themePalette[threatLevel] || themePalette.safe;

  // Spokes and Axis Labels
  const dataPoints = [];
  vectors.forEach((v, i) => {
    const angle = i * angleStep - Math.PI / 2;
    const ax = cx + Math.cos(angle) * radius;
    const ay = cy + Math.sin(angle) * radius;

    // Spoke line
    const spoke = document.createElementNS(ns, "line");
    spoke.setAttribute("x1", cx);
    spoke.setAttribute("y1", cy);
    spoke.setAttribute("x2", ax);
    spoke.setAttribute("y2", ay);
    spoke.setAttribute("stroke", "rgba(255, 255, 255, 0.15)");
    spoke.setAttribute("stroke-width", "1");
    radarSvg.appendChild(spoke);

    // Calculate Data Polygon Point
    const scoreFrac = Math.max(0.05, Math.min(1.0, (v.score || 0) / 100));
    const dx = cx + Math.cos(angle) * (radius * scoreFrac);
    const dy = cy + Math.sin(angle) * (radius * scoreFrac);
    dataPoints.push({ x: dx, y: dy, vector: v, angle });

    // Axis Outer Label
    const labelDist = radius + 22;
    const lx = cx + Math.cos(angle) * labelDist;
    const ly = cy + Math.sin(angle) * labelDist;

    const labelText = document.createElementNS(ns, "text");
    labelText.setAttribute("x", lx);
    labelText.setAttribute("y", ly + 4);
    labelText.setAttribute("text-anchor", Math.abs(Math.cos(angle)) < 0.2 ? "middle" : (Math.cos(angle) > 0 ? "start" : "end"));
    labelText.setAttribute("fill", v.status === "critical" ? "#ef4444" : (v.status === "warning" ? "#f59e0b" : "rgba(255, 255, 255, 0.65)"));
    labelText.setAttribute("font-family", "JetBrains Mono, monospace");
    labelText.setAttribute("font-size", "9");
    labelText.setAttribute("font-weight", v.status === "critical" ? "700" : "500");
    labelText.textContent = v.name;
    radarSvg.appendChild(labelText);
  });

  // Draw Data Threat Area Polygon
  const polyPoints = dataPoints.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
  const dataPolygon = document.createElementNS(ns, "polygon");
  dataPolygon.setAttribute("points", polyPoints);
  dataPolygon.setAttribute("fill", theme.fill);
  dataPolygon.setAttribute("stroke", theme.stroke);
  dataPolygon.setAttribute("stroke-width", "2");
  radarSvg.appendChild(dataPolygon);

  // Draw Vertex Dots with Tooltips
  dataPoints.forEach((pt) => {
    const isCrit = pt.vector.status === "critical";

    if (isCrit) {
      const pingRing = document.createElementNS(ns, "circle");
      pingRing.setAttribute("cx", pt.x);
      pingRing.setAttribute("cy", pt.y);
      pingRing.setAttribute("r", "7");
      pingRing.setAttribute("fill", "none");
      pingRing.setAttribute("stroke", theme.ping);
      pingRing.setAttribute("stroke-width", "1.2");
      radarSvg.appendChild(pingRing);
    }

    const dot = document.createElementNS(ns, "circle");
    dot.setAttribute("cx", pt.x);
    dot.setAttribute("cy", pt.y);
    dot.setAttribute("r", isCrit ? "4" : "3");
    dot.setAttribute("fill", isCrit ? theme.dot : (pt.vector.status === "warning" ? "#f59e0b" : (pt.vector.status === "caution" ? "#3b82f6" : "#10b981")));
    dot.setAttribute("stroke", "#09090b");
    dot.setAttribute("stroke-width", "1.5");
    dot.style.cursor = "pointer";

    // Tooltip title
    const title = document.createElementNS(ns, "title");
    title.textContent = `${pt.vector.name}: ${pt.vector.score}% [${pt.vector.status.toUpperCase()}]\n${pt.vector.desc}`;
    dot.appendChild(title);

    dot.addEventListener("click", () => {
      highlightVectorCard(pt.vector.id);
    });

    radarSvg.appendChild(dot);
  });
}

// 6 Vector Cards Grid
function renderVectorCards(vectors) {
  vectorCardsGrid.replaceChildren();

  vectors.forEach((v) => {
    const card = document.createElement("div");
    card.id = `vec-card-${v.id}`;
    card.className = `vector-card ${v.status || "clean"}`;

    const head = document.createElement("div");
    head.className = "vector-card-head";

    const name = document.createElement("span");
    name.className = "vector-name";
    name.textContent = v.name;

    const score = document.createElement("span");
    score.className = "vector-score";
    score.textContent = `${v.score}%`;

    head.append(name, score);

    const track = document.createElement("div");
    track.className = "vector-bar-track";
    const fill = document.createElement("div");
    fill.className = "vector-bar-fill";
    fill.style.width = `${v.score}%`;
    track.appendChild(fill);

    const desc = document.createElement("p");
    desc.className = "vector-desc";
    desc.textContent = v.desc;

    card.append(head, track, desc);
    vectorCardsGrid.appendChild(card);
  });
}

function highlightVectorCard(vectorId) {
  document.querySelectorAll(".vector-card").forEach((c) => c.classList.remove("active"));
  const target = document.querySelector(`#vec-card-${vectorId}`);
  if (target) {
    target.classList.add("active");
    target.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

// SVG Topology Route Flow Generator
function renderTopologyChart(topology) {
  topologySvg.replaceChildren();

  const nodes = topology.nodes || [];
  if (nodes.length === 0) return;

  const ns = "http://www.w3.org/2000/svg";
  const width = 840;
  const height = 220;

  // Arrow marker definition
  const defs = document.createElementNS(ns, "defs");
  const marker = document.createElementNS(ns, "marker");
  marker.setAttribute("id", "topo-arrow");
  marker.setAttribute("viewBox", "0 0 10 10");
  marker.setAttribute("refX", "7");
  marker.setAttribute("refY", "5");
  marker.setAttribute("markerWidth", "6");
  marker.setAttribute("markerHeight", "6");
  marker.setAttribute("orient", "auto-start-reverse");

  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", "M 0 1.5 L 8 5 L 0 8.5 z");
  path.setAttribute("fill", "rgba(255, 255, 255, 0.45)");
  marker.appendChild(path);
  defs.appendChild(marker);
  topologySvg.appendChild(defs);

  // Position nodes evenly along horizontal axis
  const cardWidth = 110;
  const cardHeight = 70;
  const startX = 20;
  const endX = width - cardWidth - 20;
  const stepX = (endX - startX) / (nodes.length - 1);
  const midY = 110;

  // Calculate coordinates for each node
  const nodePositions = nodes.map((node, i) => {
    // If lure node, offset slightly vertically for tactical diversion emphasis
    const offsetY = node.is_lure ? -26 : 0;
    return {
      x: startX + i * stepX,
      y: midY - cardHeight / 2 + offsetY,
      cx: startX + i * stepX + cardWidth / 2,
      cy: midY + offsetY,
      node,
    };
  });

  // Draw Connecting Arrows between hops
  for (let i = 0; i < nodePositions.length - 1; i++) {
    const from = nodePositions[i];
    const to = nodePositions[i + 1];

    const line = document.createElementNS(ns, "line");
    line.setAttribute("x1", from.x + cardWidth + 3);
    line.setAttribute("y1", from.cy);
    line.setAttribute("x2", to.x - 7);
    line.setAttribute("y2", to.cy);
    const arrowColor = to.node.status === "critical"
      ? "#ef4444"
      : (to.node.status === "warning" ? "#f59e0b" : "rgba(255, 255, 255, 0.25)");
    line.setAttribute("stroke", arrowColor);
    line.setAttribute("stroke-width", to.node.status === "critical" ? "2" : "1.2");
    if (to.node.is_lure || from.node.is_lure) {
      line.setAttribute("stroke-dasharray", "4,3");
    }
    line.setAttribute("marker-end", "url(#topo-arrow)");
    topologySvg.appendChild(line);
  }

  // Draw Node Cards
  const nodeColorMap = {
    critical: { stroke: "#ef4444", fill: "rgba(239, 68, 68, 0.08)", accent: "#ef4444" },
    warning: { stroke: "#f59e0b", fill: "rgba(245, 158, 11, 0.08)", accent: "#f59e0b" },
    caution: { stroke: "#3b82f6", fill: "rgba(59, 130, 246, 0.08)", accent: "#3b82f6" },
    clean: { stroke: "#10b981", fill: "rgba(16, 185, 129, 0.08)", accent: "#10b981" },
  };

  nodePositions.forEach((pos) => {
    const g = document.createElementNS(ns, "g");
    g.style.cursor = "pointer";

    const nodeTheme = nodeColorMap[pos.node.status] || {
      stroke: "rgba(255, 255, 255, 0.18)",
      fill: "#09090b",
      accent: "rgba(255, 255, 255, 0.25)",
    };

    // Card background rect
    const rect = document.createElementNS(ns, "rect");
    rect.setAttribute("x", pos.x);
    rect.setAttribute("y", pos.y);
    rect.setAttribute("width", cardWidth);
    rect.setAttribute("height", cardHeight);
    rect.setAttribute("rx", "4");
    rect.setAttribute("fill", nodeTheme.fill);
    rect.setAttribute("stroke", nodeTheme.stroke);
    rect.setAttribute("stroke-width", pos.node.status === "critical" ? "1.5" : "1");
    g.appendChild(rect);

    // Left status accent bar
    const accent = document.createElementNS(ns, "line");
    accent.setAttribute("x1", pos.x + 2);
    accent.setAttribute("y1", pos.y + 2);
    accent.setAttribute("x2", pos.x + 2);
    accent.setAttribute("y2", pos.y + cardHeight - 2);
    accent.setAttribute("stroke", nodeTheme.accent);
    accent.setAttribute("stroke-width", "3");
    g.appendChild(accent);

    // Step index label
    const step = document.createElementNS(ns, "text");
    step.setAttribute("x", pos.x + 10);
    step.setAttribute("y", pos.y + 16);
    step.setAttribute("fill", "rgba(255, 255, 255, 0.4)");
    step.setAttribute("font-family", "JetBrains Mono, monospace");
    step.setAttribute("font-size", "8");
    step.setAttribute("font-weight", "600");
    step.textContent = `[${pos.node.step}]`;
    g.appendChild(step);

    // Node main label
    const label = document.createElementNS(ns, "text");
    label.setAttribute("x", pos.x + 10);
    label.setAttribute("y", pos.y + 36);
    label.setAttribute("fill", pos.node.status === "critical" ? "#ffffff" : "#ededed");
    label.setAttribute("font-family", "JetBrains Mono, monospace");
    label.setAttribute("font-size", "11");
    label.setAttribute("font-weight", "700");
    label.textContent = pos.node.label;
    g.appendChild(label);

    // Subtitle
    const sub = document.createElementNS(ns, "text");
    sub.setAttribute("x", pos.x + 10);
    sub.setAttribute("y", pos.y + 54);
    sub.setAttribute("fill", "rgba(255, 255, 255, 0.5)");
    sub.setAttribute("font-family", "Inter, sans-serif");
    sub.setAttribute("font-size", "8");
    sub.textContent = pos.node.sub;
    g.appendChild(sub);

    // Tooltip
    const title = document.createElementNS(ns, "title");
    title.textContent = `${pos.node.label} (${pos.node.sub})\nStatus: [${pos.node.status.toUpperCase()}]`;
    g.appendChild(title);

    topologySvg.appendChild(g);
  });
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

// ==========================================
// 04 // EXPLAINABLE AI (XAI) ATTRIBUTION LENS
// ==========================================
function renderXaiExplainer(xai, threatLevel) {
  const xaiSection = document.querySelector("#xai-section");
  if (!xaiSection || !xai || xai.status !== "ready") return;

  // 1. Narrative text
  const narrativeEl = document.querySelector("#xai-narrative-text");
  if (narrativeEl) {
    narrativeEl.textContent = xai.narrative;
  }

  // 2. Character Heatmap Stream
  const heatmapStream = document.querySelector("#xai-heatmap-stream");
  const hoverChar = document.querySelector("#xai-hover-char");
  const hoverToken = document.querySelector("#xai-hover-token");
  const hoverImpact = document.querySelector("#xai-hover-impact");
  const hoverIntensity = document.querySelector("#xai-hover-intensity");
  const hoverTier = document.querySelector("#xai-hover-tier");

  function updateHoverDetail(item) {
    if (!item) return;
    if (hoverChar) hoverChar.textContent = item.char;
    if (hoverToken) hoverToken.textContent = `PRIMARY N-GRAM: ${item.top_token ? "'" + item.top_token + "'" : "—"}`;
    if (hoverImpact) {
      const imp = item.token_impact !== undefined ? item.token_impact : item.risk_score;
      hoverImpact.textContent = `${imp > 0 ? "+" : ""}${imp.toFixed(3)}`;
      hoverImpact.style.color = imp > 0 ? "#f87171" : "#34d399";
    }
    if (hoverIntensity) {
      hoverIntensity.textContent = `${Math.round(item.intensity * 100)}%`;
    }
    if (hoverTier) {
      hoverTier.textContent = item.tier.toUpperCase();
      hoverTier.className = `detail-val tier-${item.tier}`;
      if (item.tier === "critical") hoverTier.style.color = "#ef4444";
      else if (item.tier === "high") hoverTier.style.color = "#f59e0b";
      else if (item.tier === "medium") hoverTier.style.color = "#fde047";
      else hoverTier.style.color = "#34d399";
    }
  }

  if (heatmapStream && Array.isArray(xai.char_heatmap)) {
    heatmapStream.replaceChildren();

    let maxCharItem = null;
    let maxIntensity = -1;

    xai.char_heatmap.forEach((item, idx) => {
      const span = document.createElement("span");
      span.className = `xai-char ${item.tier || "low"}`;
      span.textContent = item.char;
      span.setAttribute("data-index", idx);
      span.title = `Char '${item.char}' | Pattern: ${item.top_token || "—"} | Impact: ${item.token_impact}`;

      span.addEventListener("mouseenter", () => {
        document.querySelectorAll(".xai-char.active").forEach((el) => el.classList.remove("active"));
        span.classList.add("active");
        updateHoverDetail(item);
      });

      span.addEventListener("click", () => {
        document.querySelectorAll(".xai-char.active").forEach((el) => el.classList.remove("active"));
        span.classList.add("active");
        updateHoverDetail(item);
      });

      heatmapStream.appendChild(span);

      if (item.intensity > maxIntensity) {
        maxIntensity = item.intensity;
        maxCharItem = item;
      }
    });

    // Default focus to the highest risk character or first character
    const defaultFocus = maxCharItem || xai.char_heatmap[0];
    if (defaultFocus) {
      updateHoverDetail(defaultFocus);
      const firstEl = heatmapStream.querySelector(`[data-index="${defaultFocus.index}"]`);
      if (firstEl) firstEl.classList.add("active");
    }
  }

  // 3. Top Phishing Attribution Tokens (Threat Drivers)
  const riskList = document.querySelector("#xai-risk-tokens-list");
  if (riskList) {
    riskList.replaceChildren();
    const riskTokens = xai.top_risk_tokens || [];
    if (riskTokens.length === 0) {
      const emptyNote = document.createElement("p");
      emptyNote.className = "token-empty-note";
      emptyNote.textContent = "No significant adversarial sub-tokens detected.";
      riskList.appendChild(emptyNote);
    } else {
      riskTokens.forEach((t) => {
        const row = document.createElement("div");
        row.className = "token-bar-row";

        const name = document.createElement("span");
        name.className = "token-name";
        name.textContent = t.ngram;
        name.title = `N-Gram '${t.ngram}' (Impact: +${t.contrib})`;

        const track = document.createElement("div");
        track.className = "token-track";
        const fill = document.createElement("div");
        fill.className = "token-fill risk";
        fill.style.width = `${Math.max(10, Math.min(100, t.pct || 50))}%`;
        track.appendChild(fill);

        const weight = document.createElement("span");
        weight.className = "token-weight risk";
        weight.textContent = `+${t.weight.toFixed(2)}`;

        row.append(name, track, weight);
        riskList.appendChild(row);
      });
    }
  }

  // 4. Top Benign Attribution Tokens (Trust Anchors)
  const safeList = document.querySelector("#xai-safe-tokens-list");
  if (safeList) {
    safeList.replaceChildren();
    const safeTokens = xai.top_safe_tokens || [];
    if (safeTokens.length === 0) {
      const emptyNote = document.createElement("p");
      emptyNote.className = "token-empty-note";
      emptyNote.textContent = "No benign structural anchors detected.";
      safeList.appendChild(emptyNote);
    } else {
      safeTokens.forEach((t) => {
        const row = document.createElement("div");
        row.className = "token-bar-row";

        const name = document.createElement("span");
        name.className = "token-name";
        name.textContent = t.ngram;
        name.title = `N-Gram '${t.ngram}' (Impact: ${t.contrib})`;

        const track = document.createElement("div");
        track.className = "token-track";
        const fill = document.createElement("div");
        fill.className = "token-fill safe";
        fill.style.width = `${Math.max(10, Math.min(100, t.pct || 50))}%`;
        track.appendChild(fill);

        const weight = document.createElement("span");
        weight.className = "token-weight safe";
        weight.textContent = `${t.weight.toFixed(2)}`;

        row.append(name, track, weight);
        safeList.appendChild(row);
      });
    }
  }

  // 5. Mathematical Formula Terms
  const termIntercept = document.querySelector("#xai-term-intercept");
  const termRisk = document.querySelector("#xai-term-risk");
  const termSafe = document.querySelector("#xai-term-safe");
  const termLogit = document.querySelector("#xai-term-logit");
  const termActivation = document.querySelector("#xai-term-activation");

  if (termIntercept) termIntercept.textContent = `${xai.intercept > 0 ? "+" : ""}${xai.intercept.toFixed(2)}`;
  if (termRisk) termRisk.textContent = `+${xai.net_risk_evidence.toFixed(2)}`;
  if (termSafe) termSafe.textContent = `-${xai.net_safe_evidence.toFixed(2)}`;
  if (termLogit) {
    termLogit.textContent = `${xai.decision_logit > 0 ? "+" : ""}${xai.decision_logit.toFixed(2)}`;
    termLogit.style.color = xai.decision_logit > 0 ? "#f87171" : "#34d399";
  }
  if (termActivation) {
    termActivation.textContent = `${xai.ml_probability.toFixed(1)}%`;
    termActivation.style.color = xai.ml_probability >= 50 ? "#f87171" : "#34d399";
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

  const xaiSummary = d.xai && d.xai.status === "ready"
    ? `\n## Explainable AI (XAI) Attribution\nLogit: ${d.xai.decision_logit > 0 ? "+" : ""}${d.xai.decision_logit} | P(Phish): ${d.xai.ml_probability}%\nTop Phishing Tokens: ${(d.xai.top_risk_tokens || []).map(t => `'${t.ngram}' (+${t.weight})`).join(', ') || 'None'}\nSynthesis: ${d.xai.narrative}\n`
    : "";

  const reportText = [
    `# PHISH-ZERO FORENSIC AUDIT REPORT`,
    `Target: ${d.url}`,
    `Hostname: ${d.hostname} (Root: ${d.registered_domain})`,
    `Verdict: ${d.prediction.toUpperCase()}`,
    `Phishing Score: ${d.phishing_score} / 100 (ML: ${d.ml_score}%, Heuristic: ${d.heuristic_score}%)`,
    `Authority: ${d.is_top_authority ? "VERIFIED TOP-TIER" : "STANDARD"}`,
    `Model: ${d.model_name}`,
    xaiSummary,
    `## Forensic Signals (${(d.findings || []).length})`,
    findingsSummary,
  ].filter(Boolean).join("\n");

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

// ==========================================
// QUISHING (QR CODE) FORENSICS & DECODER
// 100% Client-Side / Zero-Egress Forensics
// ==========================================
const qrTriggerBtn = document.querySelector("#qr-trigger-btn");
const quishModal = document.querySelector("#quish-modal");
const quishBackdrop = document.querySelector("#quish-backdrop");
const quishCloseBtn = document.querySelector("#quish-close-btn");
const quishDropzone = document.querySelector("#quish-dropzone");
const quishFileInput = document.querySelector("#quish-file-input");
const quishStatus = document.querySelector("#quish-status");
const quishStatusText = document.querySelector("#quish-status-text");
const quishSampleBtns = document.querySelectorAll(".quish-sample-btn");

function openQuishModal() {
  if (!quishModal) return;
  quishModal.hidden = false;
  resetQuishStatus("STATUS: AWAITING QR IMAGE INPUT");
  quishDropzone.focus();
}

function closeQuishModal() {
  if (!quishModal) return;
  quishModal.hidden = true;
  quishDropzone.classList.remove("scanning", "dragover");
}

function resetQuishStatus(text) {
  if (!quishStatus || !quishStatusText) return;
  quishStatus.className = "quish-status";
  quishStatusText.textContent = text;
}

function setQuishStatus(type, text) {
  if (!quishStatus || !quishStatusText) return;
  quishStatus.className = `quish-status ${type}`;
  quishStatusText.textContent = text;
}

if (qrTriggerBtn) {
  qrTriggerBtn.addEventListener("click", () => {
    openQuishModal();
  });
}

if (quishCloseBtn) {
  quishCloseBtn.addEventListener("click", closeQuishModal);
}

if (quishBackdrop) {
  quishBackdrop.addEventListener("click", closeQuishModal);
}

window.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && quishModal && !quishModal.hidden) {
    closeQuishModal();
  }
});

if (quishDropzone && quishFileInput) {
  quishDropzone.addEventListener("click", () => {
    quishFileInput.click();
  });

  quishFileInput.addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (file) {
      handleQrFile(file);
    }
    quishFileInput.value = "";
  });

  quishDropzone.addEventListener("dragenter", (e) => {
    e.preventDefault();
    quishDropzone.classList.add("dragover");
  });

  quishDropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    quishDropzone.classList.add("dragover");
  });

  quishDropzone.addEventListener("dragleave", (e) => {
    e.preventDefault();
    quishDropzone.classList.remove("dragover");
  });

  quishDropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    quishDropzone.classList.remove("dragover");
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) {
      handleQrFile(file);
    }
  });
}

// Global Clipboard Paste Listener (Ctrl+V)
window.addEventListener("paste", (e) => {
  const items = e.clipboardData && e.clipboardData.items;
  if (!items) return;

  for (let i = 0; i < items.length; i++) {
    if (items[i].type.indexOf("image") !== -1) {
      const file = items[i].getAsFile();
      if (file) {
        e.preventDefault();
        openQuishModal();
        handleQrFile(file);
        break;
      }
    }
  }
});

// Process image file
function handleQrFile(file) {
  if (!file.type.startsWith("image/")) {
    setQuishStatus("error", "ERROR: Selected file is not an image.");
    return;
  }

  const reader = new FileReader();
  reader.onload = (event) => {
    decodeQrImageSource(event.target.result, file.name);
  };
  reader.onerror = () => {
    setQuishStatus("error", "ERROR: Could not read image file.");
  };
  reader.readAsDataURL(file);
}

// Sample QR preset buttons
quishSampleBtns.forEach((btn) => {
  btn.addEventListener("click", () => {
    const src = btn.getAttribute("data-src");
    const name = btn.getAttribute("data-name") || "Preset QR";
    if (src) {
      decodeQrImageSource(src, name);
    }
  });
});

// Core Zero-Egress QR Decoder using vendored jsQR
function decodeQrImageSource(imgSrc, label = "Image") {
  quishDropzone.classList.add("scanning");
  setQuishStatus("scanning", `ANALYZING QR MATRIX: ${label}...`);

  const img = new Image();
  img.crossOrigin = "anonymous";

  img.onload = () => {
    try {
      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d");
      canvas.width = img.naturalWidth || img.width;
      canvas.height = img.naturalHeight || img.height;

      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      let decodedText = null;

      // 1. Primary: jsQR (offline, local, zero egress)
      if (typeof jsQR === "function") {
        const qrResult = jsQR(imgData.data, canvas.width, canvas.height, {
          inversionAttempts: "attemptBoth",
        });
        if (qrResult && qrResult.data) {
          decodedText = qrResult.data.trim();
        }
      }

      // 2. Secondary fallback: Native BarcodeDetector if available
      if (!decodedText && "BarcodeDetector" in window) {
        const detector = new BarcodeDetector({ formats: ["qr_code"] });
        detector.detect(img)
          .then((barcodes) => {
            if (barcodes.length > 0 && barcodes[0].rawValue) {
              handleDecodedPayload(barcodes[0].rawValue.trim());
            } else {
              handleQrNotFound();
            }
          })
          .catch(() => handleQrNotFound());
        return;
      }

      if (decodedText) {
        handleDecodedPayload(decodedText);
      } else {
        handleQrNotFound();
      }
    } catch (err) {
      quishDropzone.classList.remove("scanning");
      setQuishStatus("error", `DECODE FAILED: ${err.message}`);
    }
  };

  img.onerror = () => {
    quishDropzone.classList.remove("scanning");
    setQuishStatus("error", "ERROR: Failed to render image source.");
  };

  img.src = imgSrc;
}

function handleDecodedPayload(payload) {
  quishDropzone.classList.remove("scanning");
  setQuishStatus("success", `SUCCESS: PAYLOAD EXTRACTED [${payload.length > 36 ? payload.slice(0, 34) + "..." : payload}]`);

  // Populate into input bar
  input.value = payload;
  clearInputBtn.hidden = false;

  showToast(`QUISHING PAYLOAD DECODED: ${payload}`);

  // Automatically close modal after brief visual feedback and execute audit
  setTimeout(() => {
    closeQuishModal();
    executeAudit(payload, "quishing");
  }, 420);
}

function handleQrNotFound() {
  quishDropzone.classList.remove("scanning");
  setQuishStatus("error", "SCAN FAILED: No valid QR code pattern found in this image.");
}

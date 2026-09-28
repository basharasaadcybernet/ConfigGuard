"use strict";

const requestToken = document.querySelector('meta[name="configguard-token"]').content;
const maxBytes = 2 * 1024 * 1024;
const state = { file: null, response: null, filter: "all" };

const elements = {
  uploadView: document.getElementById("upload-view"),
  resultsView: document.getElementById("results-view"),
  dropZone: document.getElementById("drop-zone"),
  fileInput: document.getElementById("file-input"),
  selectionPanel: document.getElementById("selection-panel"),
  selectedName: document.getElementById("selected-name"),
  selectedSize: document.getElementById("selected-size"),
  scanButton: document.getElementById("scan-button"),
  chooseButton: document.getElementById("choose-button"),
  loadingState: document.getElementById("loading-state"),
  errorMessage: document.getElementById("error-message"),
  resultFilename: document.getElementById("result-filename"),
  overviewGrid: document.getElementById("overview-grid"),
  partialExplanation: document.getElementById("partial-explanation"),
  partialExplanationText: document.getElementById("partial-explanation-text"),
  outcomeCounts: document.getElementById("outcome-counts"),
  severityCounts: document.getElementById("severity-counts"),
  filters: document.getElementById("filters"),
  visibleCount: document.getElementById("visible-count"),
  resultsList: document.getElementById("results-list"),
  diagnosticsSection: document.getElementById("diagnostics-section"),
  diagnosticCount: document.getElementById("diagnostic-count"),
  diagnosticsList: document.getElementById("diagnostics-list"),
  limitationsList: document.getElementById("limitations-list"),
  downloadJson: document.getElementById("download-json"),
  downloadHtml: document.getElementById("download-html"),
  newScan: document.getElementById("new-scan"),
};

const outcomeLabels = {
  confirmed_insecure: "Confirmed Weakness",
  potential_risk: "Potential Risk",
  hardening: "Hardening",
  secure: "Secure",
  unknown: "Unknown",
  unsupported_syntax: "Unsupported",
  not_evaluated: "Evaluation Failure",
  not_applicable: "Not Applicable",
};

const outcomeOrder = [
  "confirmed_insecure", "potential_risk", "hardening", "unknown",
  "unsupported_syntax", "not_evaluated", "secure", "not_applicable",
];

const severityOrder = ["critical", "high", "medium", "low", "info"];
const findingOutcomes = new Set(["confirmed_insecure", "potential_risk", "hardening"]);
const unknownOutcomes = new Set(["unknown", "unsupported_syntax", "not_evaluated"]);

elements.fileInput.addEventListener("change", () => {
  if (elements.fileInput.files.length) selectFile(elements.fileInput.files[0]);
});
elements.chooseButton.addEventListener("click", () => elements.fileInput.click());
elements.scanButton.addEventListener("click", scanSelectedFile);
elements.newScan.addEventListener("click", resetApplication);
elements.downloadJson.addEventListener("click", () => downloadExport("json"));
elements.downloadHtml.addEventListener("click", () => downloadExport("html"));
elements.filters.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-filter]");
  if (!button || !state.response) return;
  state.filter = button.dataset.filter;
  for (const item of elements.filters.querySelectorAll("button")) {
    item.classList.toggle("active", item === button);
  }
  renderResults(state.response.assessment.findings);
});

for (const eventName of ["dragenter", "dragover"]) {
  elements.dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropZone.classList.add("drag-active");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  elements.dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropZone.classList.remove("drag-active");
  });
}
elements.dropZone.addEventListener("drop", (event) => {
  const file = event.dataTransfer.files[0];
  if (file) selectFile(file);
});

function selectFile(file) {
  clearError();
  state.file = file;
  elements.selectedName.textContent = file.name || "configuration";
  elements.selectedSize.textContent = formatBytes(file.size);
  elements.selectionPanel.hidden = false;
  if (file.size > maxBytes) {
    showError("This file exceeds the 2 MiB input limit.");
    elements.scanButton.disabled = true;
  } else {
    elements.scanButton.disabled = false;
  }
}

async function scanSelectedFile() {
  if (!state.file || elements.scanButton.disabled) return;
  setLoading(true);
  clearError();
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-ConfigGuard-Filename": encodeURIComponent(state.file.name || "configuration.txt"),
        "X-ConfigGuard-Token": requestToken,
      },
      body: state.file,
      cache: "no-store",
      credentials: "same-origin",
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok || !payload || payload.error) {
      throw new Error(payload?.error?.message || "The local assessment could not be completed.");
    }
    state.response = payload;
    state.filter = "all";
    renderAssessment(payload);
  } catch (error) {
    showError(error instanceof Error ? error.message : "The local assessment could not be completed.");
  } finally {
    setLoading(false);
  }
}

function setLoading(active) {
  elements.loadingState.hidden = !active;
  elements.scanButton.disabled = active || !state.file || state.file.size > maxBytes;
  elements.chooseButton.disabled = active;
}

function showError(message) {
  elements.errorMessage.textContent = message;
  elements.errorMessage.hidden = false;
}

function clearError() {
  elements.errorMessage.textContent = "";
  elements.errorMessage.hidden = true;
}

function renderAssessment(payload) {
  const assessment = payload.assessment;
  elements.uploadView.hidden = true;
  elements.resultsView.hidden = false;
  elements.resultFilename.textContent = state.file ? state.file.name : "Selected configuration";
  renderOverview(assessment);
  renderPartialExplanation(payload.presentation.partial_status);
  renderFilterCounts(assessment.findings);
  renderResults(assessment.findings);
  renderDiagnostics(assessment.operational_diagnostics);
  renderLimitations(assessment.assessment_limitations);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function renderPartialExplanation(message) {
  elements.partialExplanationText.textContent = message || "";
  elements.partialExplanation.hidden = !message;
}

function renderOverview(assessment) {
  elements.overviewGrid.replaceChildren();
  const findingCount = assessment.findings.filter((item) => findingOutcomes.has(item.outcome)).length;
  const platform = platformLabel(assessment.platform.family);
  const metrics = [
    ["Assessment status", titleCase(assessment.assessment_status), null],
    ["Platform", platform, `Confidence ${assessment.platform.confidence.toFixed(2)}`],
    ["Parser completeness", titleCase(assessment.parser.status), null],
    ["Implemented rules", String(assessment.evaluated_rule_ids.length), "No numerical score"],
    ["Security findings", String(findingCount), "Weakness, risk, or hardening"],
    ["Diagnostics", String(assessment.operational_diagnostics.length), "Operational, not vulnerabilities"],
  ];
  for (const [label, value, note] of metrics) {
    const card = createElement("div", "metric-card");
    card.append(createElement("span", "metric-label", label));
    card.append(createElement("strong", "", value));
    if (note) card.append(createElement("small", "", note));
    elements.overviewGrid.append(card);
  }
  renderCountChips(elements.outcomeCounts, outcomeOrder.map((key) => [outcomeLabels[key], assessment.outcome_summary[key]]));
  renderCountChips(elements.severityCounts, severityOrder.map((key) => [titleCase(key), assessment.severity_summary[key]]));
}

function renderCountChips(container, values) {
  container.replaceChildren();
  for (const [label, count] of values) {
    const chip = createElement("span", "count-chip");
    chip.append(document.createTextNode(`${label} `));
    chip.append(createElement("strong", "", String(count)));
    container.append(chip);
  }
}

function renderFilterCounts(findings) {
  const counts = {
    all: findings.length,
    findings: findings.filter((item) => findingOutcomes.has(item.outcome)).length,
    secure: findings.filter((item) => item.outcome === "secure").length,
    unknown: findings.filter((item) => unknownOutcomes.has(item.outcome)).length,
    not_applicable: findings.filter((item) => item.outcome === "not_applicable").length,
  };
  for (const button of elements.filters.querySelectorAll("button[data-filter]")) {
    button.classList.toggle("active", button.dataset.filter === state.filter);
    button.querySelector("span").textContent = String(counts[button.dataset.filter]);
  }
}

function renderResults(findings) {
  elements.resultsList.replaceChildren();
  const visible = findings.filter(matchesFilter);
  elements.visibleCount.textContent = `${visible.length} of ${findings.length} results`;
  if (!visible.length) {
    elements.resultsList.append(createElement("div", "empty-filter", "No results match this filter."));
    return;
  }
  for (const finding of visible) elements.resultsList.append(createResultCard(finding));
}

function matchesFilter(finding) {
  if (state.filter === "all") return true;
  if (state.filter === "findings") return findingOutcomes.has(finding.outcome);
  if (state.filter === "unknown") return unknownOutcomes.has(finding.outcome);
  return finding.outcome === state.filter;
}

function createResultCard(finding) {
  const card = createElement("article", `result-card outcome-${finding.outcome}`);
  const header = createElement("div", "result-card-header");
  const identity = document.createElement("div");
  identity.append(createElement("p", "rule-id", finding.rule_id));
  identity.append(createElement("h4", "", finding.title));
  const badges = createElement("div", "badges");
  badges.append(createElement("span", "badge", outcomeLabels[finding.outcome] || titleCase(finding.outcome)));
  badges.append(createElement("span", `badge severity-${finding.severity || "none"}`, `Severity: ${finding.severity || "none"}`));
  header.append(identity, badges);
  card.append(header);
  card.append(createElement("p", "result-summary", finding.description));
  const metadata = createElement("div", "result-metadata");
  metadata.append(createElement("span", "", `Outcome: ${finding.outcome}`));
  metadata.append(createElement("span", "", `Confidence: ${finding.confidence}`));
  card.append(metadata);

  const detailsContent = createDetailsContent(finding);
  if (detailsContent) {
    const details = document.createElement("details");
    details.append(createElement("summary", "", "View sanitized details"));
    details.append(detailsContent);
    card.append(details);
  }
  return card;
}

function createDetailsContent(finding) {
  const content = createElement("div", "detail-content");
  addTextBlock(content, "Security impact", finding.impact);
  addTextBlock(content, "Recommendation", finding.recommendation);
  const guidance = state.response?.presentation?.additional_evidence?.[finding.rule_id];
  addTextBlock(content, "Additional evidence needed", guidance);
  addEvidenceBlock(content, finding.evidence);
  addListBlock(content, "Limitations", finding.limitations);
  addListBlock(content, "Technical references", finding.technical_references);
  return content.childElementCount ? content : null;
}

function addTextBlock(container, label, value) {
  if (!value) return;
  const block = createElement("section", "detail-block");
  block.append(createElement("h5", "", label));
  block.append(createElement("p", "", value));
  container.append(block);
}

function addEvidenceBlock(container, evidence) {
  if (!evidence?.length) return;
  const block = createElement("section", "detail-block");
  block.append(createElement("h5", "", "Safe technical evidence"));
  const list = createElement("ul", "evidence-list");
  for (const item of evidence) {
    const lines = item.line_start === item.line_end ? `line ${item.line_start}` : `lines ${item.line_start}-${item.line_end}`;
    const provenance = item.target_interface ? ` [target: ${item.target_interface}${item.resolution_origin ? `, ${item.resolution_origin}` : ""}]` : "";
    list.append(createElement("li", "", `${lines}${provenance}: ${item.excerpt}`));
  }
  block.append(list);
  container.append(block);
}

function addListBlock(container, label, values) {
  if (!values?.length) return;
  const block = createElement("section", "detail-block");
  block.append(createElement("h5", "", label));
  const list = document.createElement("ul");
  for (const value of values) list.append(createElement("li", "", value));
  block.append(list);
  container.append(block);
}

function renderDiagnostics(diagnostics) {
  elements.diagnosticsList.replaceChildren();
  elements.diagnosticsSection.hidden = diagnostics.length === 0;
  elements.diagnosticCount.textContent = `${diagnostics.length} diagnostic${diagnostics.length === 1 ? "" : "s"}`;
  for (const diagnostic of diagnostics) {
    const item = createElement("article", "diagnostic-item");
    item.append(createElement("strong", "", diagnostic.code));
    const context = [titleCase(diagnostic.source)];
    if (diagnostic.rule_id) context.push(diagnostic.rule_id);
    if (diagnostic.line_start) context.push(`line ${diagnostic.line_start}`);
    item.append(createElement("p", "", `${context.join(" | ")} - ${diagnostic.message}`));
    elements.diagnosticsList.append(item);
  }
}

function renderLimitations(limitations) {
  elements.limitationsList.replaceChildren();
  for (const limitation of limitations) {
    elements.limitationsList.append(createElement("li", "", limitation));
  }
}

function downloadExport(kind) {
  if (!state.response) return;
  const exports = state.response.exports;
  const content = exports[kind];
  const filename = exports[`${kind}_filename`];
  const type = kind === "json" ? "application/json;charset=utf-8" : "text/html;charset=utf-8";
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function resetApplication() {
  state.file = null;
  state.response = null;
  state.filter = "all";
  elements.fileInput.value = "";
  elements.selectionPanel.hidden = true;
  elements.resultsView.hidden = true;
  elements.uploadView.hidden = false;
  elements.resultsList.replaceChildren();
  elements.diagnosticsList.replaceChildren();
  elements.overviewGrid.replaceChildren();
  elements.partialExplanation.hidden = true;
  elements.partialExplanationText.textContent = "";
  clearError();
  elements.scanButton.disabled = false;
  elements.chooseButton.disabled = false;
  for (const button of elements.filters.querySelectorAll("button[data-filter]")) {
    button.classList.toggle("active", button.dataset.filter === "all");
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function createElement(tag, className = "", text = null) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== null) element.textContent = text;
  return element;
}

function formatBytes(value) {
  if (value < 1024) return `${value} bytes`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MiB`;
}

function platformLabel(value) {
  return {
    cisco_ios: "Cisco IOS",
    cisco_ios_xe: "Cisco IOS XE",
    unknown: "Compatible IOS-style",
    unsupported: "Unsupported",
  }[value] || "Unknown platform";
}

function titleCase(value) {
  return String(value).replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

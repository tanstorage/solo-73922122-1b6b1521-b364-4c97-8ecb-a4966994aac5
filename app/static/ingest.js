"use strict";

const byId = (id) => document.getElementById(id);

const state = {
  probes: [],
  meta: {
    max_file_bytes: 32 * 1024 * 1024,
    max_line_bytes: 4096,
    salt_length: 32,
  },
  eventsFile: null,
  signatureFile: null,
  busy: false,
  alerts: { page: 1, pageSize: 20, probeId: "", total: 0, pages: 0 },
  imports: { page: 1, pageSize: 8, total: 0, pages: 0 },
};

const MAX_SIGNATURE_BYTES = 64 * 1024;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB"];
  const index = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1
  );
  const value = bytes / 1024 ** index;
  return `${value >= 10 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

function formatUtc(epochSeconds) {
  if (!Number.isInteger(epochSeconds)) return "—";
  try {
    return new Date(epochSeconds * 1000).toISOString().slice(0, 19).replace("T", " ") + " UTC";
  } catch (_error) {
    return String(epochSeconds);
  }
}

function formatLocal(epochSeconds) {
  try {
    return new Date(epochSeconds * 1000).toLocaleString("zh-CN", {
      hour12: false,
    });
  } catch (_error) {
    return "";
  }
}

async function getJson(url) {
  const response = await fetch(url, {
    method: "GET",
    headers: { Accept: "application/json" },
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) throw describeHttpDetail(payload);
  if (!payload) throw { code: "invalid_response", message: "服务返回了无法识别的响应。" };
  return payload;
}

function describeHttpDetail(payload) {
  const detail = payload && payload.detail;
  if (!detail) {
    return { code: "request_failed", message: "服务返回了无法识别的错误。" };
  }
  if (typeof detail === "string") {
    return { code: "request_failed", message: detail };
  }
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => item && (item.msg || item.message))
      .filter(Boolean);
    return {
      code: "validation_error",
      message: messages.join("；") || "请求参数无效。",
    };
  }
  return {
    code: detail.code || "request_failed",
    message: detail.message || "请求失败。",
    line: detail.line,
  };
}

function setGlobalNotice(message) {
  const notice = byId("global-notice");
  if (!message) {
    notice.hidden = true;
    notice.textContent = "";
    return;
  }
  notice.hidden = false;
  notice.textContent = message;
}

function setError(error) {
  const box = byId("ingest-error");
  if (!error) {
    box.hidden = true;
    return;
  }
  byId("error-code").textContent = `导入失败 · ${error.code || "request_failed"}`;
  byId("error-message").textContent = error.message || "无法完成导入。";
  const meta = byId("error-meta");
  const parts = [];
  if (error.line !== undefined && error.line !== null) parts.push(`第 ${error.line} 行`);
  if (error.code) parts.push(`错误码 ${error.code}`);
  if (parts.length) {
    meta.hidden = false;
    meta.textContent = parts.join(" · ");
  } else {
    meta.hidden = true;
    meta.textContent = "";
  }
  box.hidden = false;
  byId("ingest-success").hidden = true;
  byId("intake-state").className = "badge badge-revoked";
  byId("intake-state").textContent = "REJECTED";
}

function clearError() {
  byId("ingest-error").hidden = true;
}

function setSuccess(result) {
  byId("ingest-success").hidden = false;
  byId("ingest-error").hidden = true;
  byId("ingest-success-message").textContent = result.message || "整批已提交。";
  byId("result-total").textContent = String(result.total_lines ?? 0);
  byId("result-imported").textContent = String(result.imported_lines ?? 0);
  byId("result-skipped").textContent = String(result.skipped_lines ?? 0);
  byId("result-bytes").textContent = formatBytes(result.size_bytes || 0);
  byId("result-batch").textContent = `batch ${result.batch_id || ""}`;
  byId("intake-state").className = "badge badge-ready";
  byId("intake-state").textContent = "COMMITTED";
}

function setBusy(nextBusy) {
  state.busy = nextBusy;
  const button = byId("ingest-button");
  button.classList.toggle("is-busy", nextBusy);
  button.querySelector(".button-label").textContent = nextBusy
    ? "流式校验中…"
    : "流式校验并提交";
  byId("intake-state").className = nextBusy
    ? "badge badge-busy"
    : byId("intake-state").className;
  if (nextBusy) {
    byId("intake-state").textContent = "VERIFYING";
  }
  updateSubmitState();
}

function selectedProbe() {
  const id = byId("probe-select").value;
  return state.probes.find((probe) => probe.probe_id === id) || null;
}

function updateSubmitState() {
  const probe = selectedProbe();
  const ready =
    !state.busy &&
    probe !== null &&
    !probe.revoked &&
    state.eventsFile !== null &&
    state.signatureFile !== null;
  byId("ingest-button").disabled = !ready;
}

function updateProbeHint() {
  const probe = selectedProbe();
  const hint = byId("probe-hint");
  if (!probe) {
    hint.textContent = "请选择一台未撤销的探针。";
    return;
  }
  if (probe.revoked) {
    hint.textContent = "该探针已被不可恢复地撤销，不能接收新告警。";
    return;
  }
  hint.textContent =
    `授权主机：${probe.authorized_hosts.join("、")} · ` +
    `公钥指纹 ${probe.key_fingerprint}`;
}

function renderProbeSelect() {
  const select = byId("probe-select");
  const previous = select.value;
  select.replaceChildren();

  if (!state.probes.length) {
    select.append(new Option("没有可用探针", ""));
    select.disabled = true;
    return;
  }

  for (const probe of state.probes) {
    const label = probe.revoked
      ? `${probe.probe_id} · 已撤销`
      : `${probe.probe_id} · 可用`;
    select.append(new Option(label, probe.probe_id, false, false));
    const option = select.lastElementChild;
    option.disabled = probe.revoked;
  }

  const previousProbe = state.probes.find((probe) => probe.probe_id === previous);
  if (previousProbe && !previousProbe.revoked) {
    select.value = previous;
  } else {
    const firstActive = state.probes.find((probe) => !probe.revoked);
    select.value = firstActive ? firstActive.probe_id : "";
  }
  select.disabled = !state.probes.some((probe) => !probe.revoked);
  updateProbeHint();
}

function renderProbeCards() {
  const container = byId("probe-list");
  container.replaceChildren();

  for (const probe of state.probes) {
    const card = el("article", `probe-card${probe.revoked ? " is-revoked" : ""}`);
    const head = el("div", "probe-card-head");
    const titleBlock = el("div");
    titleBlock.append(el("h3", "probe-id", probe.probe_id));
    const fingerprint = el("span", "probe-fingerprint", probe.key_fingerprint);
    fingerprint.title = probe.key_fingerprint;
    titleBlock.append(fingerprint);
    head.append(titleBlock);
    head.append(
      el(
        "span",
        `badge ${probe.revoked ? "badge-revoked" : "badge-ready"}`,
        probe.revoked ? "REVOKED" : "TRUSTED"
      )
    );
    card.append(head);

    const hosts = el("div", "probe-hosts");
    for (const host of probe.authorized_hosts) hosts.append(el("span", "host-chip", host));
    card.append(hosts);

    const foot = el("div", "probe-card-foot");
    const note = el(
      "p",
      "probe-revoke-note",
      probe.revoked
        ? `撤销于 ${formatUtc(probe.revoked_at)}`
        : "撤销后不可恢复，并立即拦截未提交导入"
    );
    foot.append(note);

    const button = el(
      "button",
      "button button-danger button-small",
      probe.revoked ? "已撤销" : "撤销探针"
    );
    button.type = "button";
    button.disabled = probe.revoked || state.busy;
    if (!probe.revoked) {
      button.addEventListener("click", () => revokeProbe(probe.probe_id));
    }
    foot.append(button);
    card.append(foot);
    container.append(card);
  }

  if (!state.probes.length) {
    container.append(el("p", "muted-line", "本地配置未登记探针。"));
  }
}

function renderAlertFilter() {
  const select = byId("alert-filter");
  const previous = select.value;
  select.replaceChildren(new Option("全部探针", ""));
  for (const probe of state.probes) {
    select.append(new Option(`${probe.probe_id}${probe.revoked ? " · 已撤销" : ""}`, probe.probe_id));
  }
  select.value = state.probes.some((probe) => probe.probe_id === previous) ? previous : "";
  state.alerts.probeId = select.value;
}

async function loadProbes() {
  const payload = await getJson("/api/probes");
  state.probes = payload.probes || [];
  if (payload.limits && payload.limits.max_file_bytes) {
    state.meta.max_file_bytes = payload.limits.max_file_bytes;
    state.meta.max_line_bytes = payload.limits.max_line_bytes || 4096;
    state.meta.salt_length = payload.limits.salt_length || 32;
  }
  renderProbeSelect();
  renderProbeCards();
  renderAlertFilter();

  const active = state.probes.filter((probe) => !probe.revoked);
  if (!active.length) {
    setGlobalNotice("所有探针均已撤销。系统仍可审计历史告警，但不能接收新批次。");
  }
  updateSubmitState();
}

async function revokeProbe(probeId) {
  if (state.busy) return;
  const confirmed = window.confirm(
    `确认撤销探针 ${probeId}？\n\n撤销不可恢复；撤销成功后，所有尚未提交的导入都必须失败。`
  );
  if (!confirmed) return;

  clearError();
  setGlobalNotice(`正在撤销 ${probeId}…`);
  try {
    const response = await fetch(`/api/probes/${encodeURIComponent(probeId)}/revoke`, {
      method: "POST",
      headers: { Accept: "application/json" },
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) throw describeHttpDetail(payload);
    setGlobalNotice(
      payload.already_revoked
        ? `探针 ${probeId} 此前已经撤销；状态保持不变。`
        : `探针 ${probeId} 已不可恢复地撤销，新的导入会被立即拒绝。`
    );
    await loadProbes();
    updateSubmitState();
  } catch (error) {
    setGlobalNotice(`撤销失败：${(error && error.message) || "请求失败"}`);
  }
}

function setFile(kind, file) {
  const isEvents = kind === "events";
  const zone = byId(isEvents ? "events-drop" : "signature-drop");
  const input = byId(isEvents ? "events-input" : "signature-input");
  const title = byId(isEvents ? "events-drop-title" : "signature-drop-title");
  const meta = byId(isEvents ? "events-drop-meta" : "signature-drop-meta");
  const defaultTitle = isEvents ? "拖入 JSONL，或点击选择" : "拖入签名，或点击选择";
  const defaultMeta = isEvents
    ? "每行最多 4 KiB，整文件流式读取"
    : "原始二进制或 base64/PEM 文本";

  zone.classList.remove("is-invalid");
  if (!file) {
    state[isEvents ? "eventsFile" : "signatureFile"] = null;
    zone.classList.remove("is-selected");
    title.textContent = defaultTitle;
    meta.textContent = defaultMeta;
    input.value = "";
    updateSubmitState();
    return;
  }

  const limit = isEvents ? state.meta.max_file_bytes : MAX_SIGNATURE_BYTES;
  if (file.size > limit) {
    state[isEvents ? "eventsFile" : "signatureFile"] = null;
    zone.classList.add("is-invalid");
    title.textContent = "文件超过上限";
    meta.textContent = `${file.name} · ${formatBytes(file.size)} > ${formatBytes(limit)}`;
    input.value = "";
    setError({
      code: "file_too_large",
      message: isEvents
        ? `JSONL 文件超过 ${formatBytes(limit)} 上限。`
        : "签名文件超过 64 KiB 上限。",
    });
    updateSubmitState();
    return;
  }

  state[isEvents ? "eventsFile" : "signatureFile"] = file;
  zone.classList.add("is-selected");
  title.textContent = file.name;
  meta.textContent = `${formatBytes(file.size)} · 已选择`;
  clearError();
  updateSubmitState();
}

function setupDropZone(kind, zoneId, inputId) {
  const zone = byId(zoneId);
  const input = byId(inputId);

  input.addEventListener("change", () => setFile(kind, input.files && input.files[0]));

  for (const eventName of ["dragenter", "dragover"]) {
    zone.addEventListener(eventName, (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (!state.busy) zone.classList.add("is-dragging");
    });
  }
  for (const eventName of ["dragleave", "drop"]) {
    zone.addEventListener(eventName, (event) => {
      event.preventDefault();
      event.stopPropagation();
      zone.classList.remove("is-dragging");
    });
  }
  zone.addEventListener("drop", (event) => {
    if (state.busy) return;
    const files = event.dataTransfer && event.dataTransfer.files;
    if (files && files.length) setFile(kind, files[0]);
  });
}

async function submitBatch(event) {
  event.preventDefault();
  if (state.busy) return;
  const probe = selectedProbe();
  if (!probe) {
    setError({ code: "probe_missing", message: "请选择一台探针。" });
    return;
  }
  if (probe.revoked) {
    setError({ code: "probe_revoked", message: "该探针已被撤销，不能接收告警。" });
    return;
  }
  if (!state.eventsFile) {
    setError({ code: "events_missing", message: "请选择 UTF-8 JSONL 文件。" });
    return;
  }
  if (!state.signatureFile) {
    setError({ code: "signature_missing", message: "请选择独立签名文件。" });
    return;
  }

  clearError();
  byId("ingest-success").hidden = true;
  setBusy(true);

  const body = new FormData();
  body.append("probe_id", probe.probe_id);
  body.append("events", state.eventsFile, state.eventsFile.name);
  body.append("signature", state.signatureFile, state.signatureFile.name);

  try {
    const response = await fetch("/api/ingest", {
      method: "POST",
      body,
      headers: { Accept: "application/json" },
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) throw describeHttpDetail(payload);
    if (!payload) throw { code: "invalid_response", message: "服务没有返回有效 JSON。" };

    const wasImported = Number(payload.imported_lines || 0);
    setSuccess(payload);
    setGlobalNotice(
      payload.skipped_lines
        ? `批次已提交：新增 ${wasImported} 条，跳过 ${payload.skipped_lines} 条完全一致的重复事件。`
        : `批次已提交：新增 ${wasImported} 条告警。`
    );
    setFile("events", null);
    setFile("signature", null);
    await Promise.allSettled([loadAlerts(1), loadImports(1)]);
  } catch (error) {
    const normalized =
      error && typeof error === "object" && "message" in error
        ? error
        : { code: "network_error", message: "网络请求失败，请确认服务正在运行。" };
    setError(normalized);
    await Promise.allSettled([loadImports(1)]);
  } finally {
    setBusy(false);
    updateSubmitState();
  }
}

function makeAlertRow(alert) {
  const tr = el("tr");

  const timeCell = el("td", "time-cell", formatUtc(alert.time));
  timeCell.title = `${formatLocal(alert.time)} · epoch ${alert.time}`;
  tr.append(timeCell);

  tr.append(el("td", "mono-cell", alert.probe_id));
  tr.append(el("td", "mono-cell", alert.event_id));
  tr.append(el("td", null, alert.host));

  const ruleCell = el("td", "rule-cell");
  ruleCell.append(el("code", null, alert.rule));
  tr.append(ruleCell);
  return tr;
}

async function loadAlerts(page) {
  state.alerts.page = page;
  const query = new URLSearchParams({
    page: String(state.alerts.page),
    page_size: String(state.alerts.pageSize),
  });
  if (state.alerts.probeId) query.set("probe_id", state.alerts.probeId);

  try {
    const payload = await getJson(`/api/alerts?${query.toString()}`);
    state.alerts.total = Number(payload.total || 0);
    state.alerts.pages = Number(payload.pages || 0);
    state.alerts.page = Number(payload.page || page);

    const body = byId("alerts-body");
    body.replaceChildren();
    for (const alert of payload.items || []) body.append(makeAlertRow(alert));

    const hasItems = (payload.items || []).length > 0;
    byId("alerts-table-wrap").hidden = !hasItems;
    byId("alerts-empty").hidden = hasItems;

    const filterText = state.alerts.probeId
      ? `探针 ${state.alerts.probeId}`
      : "全部探针";
    byId("alerts-summary").textContent = state.alerts.total
      ? `${filterText} · 共 ${state.alerts.total.toLocaleString("zh-CN")} 条可见告警`
      : `${filterText} · 暂无可见告警`;

    const pager = byId("alerts-pager");
    pager.hidden = state.alerts.total === 0;
    byId("alerts-page-info").textContent = state.alerts.pages
      ? `第 ${state.alerts.page} / ${state.alerts.pages} 页`
      : "第 0 / 0 页";
    byId("alerts-prev").disabled = state.alerts.page <= 1;
    byId("alerts-next").disabled =
      state.alerts.pages === 0 || state.alerts.page >= state.alerts.pages;
  } catch (error) {
    byId("alerts-summary").textContent = `告警读取失败：${error.message || "请求失败"}`;
    byId("alerts-table-wrap").hidden = true;
    byId("alerts-empty").hidden = false;
    byId("alerts-pager").hidden = true;
  }
}

function makeImportRow(batch) {
  const tr = el("tr");

  const timeCell = el("td", "time-cell", formatUtc(batch.finished_at));
  timeCell.title = formatLocal(batch.finished_at);
  tr.append(timeCell);
  tr.append(el("td", "mono-cell", batch.probe_id));

  const statusCell = el("td");
  const failed = batch.status === "failed";
  statusCell.append(
    el(
      "span",
      `status-badge ${failed ? "status-failed" : "status-committed"}`,
      failed ? "失败" : "已提交"
    )
  );
  tr.append(statusCell);

  const counts = el(
    "td",
    "count-cell",
    `${batch.total_lines ?? 0} / ${batch.imported_lines ?? 0} / ${batch.skipped_lines ?? 0}`
  );
  counts.title = "总行数 / 新写入 / 跳过重复";
  tr.append(counts);

  const reasonCell = el("td", "reason-cell");
  if (failed) {
    const head = el("span", "reason-title", batch.failure_message || "导入失败");
    reasonCell.append(head);
    reasonCell.append(el("span", "reason-code", batch.failure_code || "failed"));
    if (batch.failure_line !== null && batch.failure_line !== undefined) {
      reasonCell.append(el("span", "reason-text", `失败位置：第 ${batch.failure_line} 行`));
    } else if (batch.file_name) {
      reasonCell.append(el("span", "reason-text", `文件：${batch.file_name}`));
    }
  } else {
    reasonCell.append(el("span", "reason-text", "验签与全文件校验通过，已原子提交。"));
  }
  tr.append(reasonCell);
  return tr;
}

async function loadImports(page) {
  state.imports.page = page;
  const query = new URLSearchParams({
    page: String(page),
    page_size: String(state.imports.pageSize),
  });

  try {
    const payload = await getJson(`/api/imports?${query.toString()}`);
    state.imports.total = Number(payload.total || 0);
    state.imports.pages = Number(payload.pages || 0);
    state.imports.page = Number(payload.page || page);

    const body = byId("imports-body");
    body.replaceChildren();
    for (const batch of payload.items || []) body.append(makeImportRow(batch));

    const hasItems = (payload.items || []).length > 0;
    byId("imports-table-wrap").hidden = !hasItems;
    byId("imports-empty").hidden = hasItems;

    const pager = byId("imports-pager");
    pager.hidden = state.imports.total === 0;
    byId("imports-page-info").textContent = state.imports.pages
      ? `第 ${state.imports.page} / ${state.imports.pages} 页`
      : "第 0 / 0 页";
    byId("imports-prev").disabled = state.imports.page <= 1;
    byId("imports-next").disabled =
      state.imports.pages === 0 || state.imports.page >= state.imports.pages;
  } catch (error) {
    byId("imports-table-wrap").hidden = true;
    byId("imports-empty").hidden = false;
    byId("imports-pager").hidden = true;
  }
}

async function loadMeta() {
  try {
    const meta = await getJson("/api/meta");
    state.meta = { ...state.meta, ...meta };
    byId("limit-file").textContent = formatBytes(state.meta.max_file_bytes);
    byId("limit-line").textContent = `${Math.round(state.meta.max_line_bytes / 1024)} KiB`;
    byId("limit-salt").textContent = `${state.meta.salt_length} B`;
  } catch (_error) {
    // The visible defaults already match the server contract.
  }
}

function bindEvents() {
  byId("ingest-form").addEventListener("submit", submitBatch);
  byId("probe-select").addEventListener("change", () => {
    updateProbeHint();
    updateSubmitState();
  });

  byId("alert-filter").addEventListener("change", () => {
    state.alerts.probeId = byId("alert-filter").value;
    loadAlerts(1);
  });
  byId("alerts-prev").addEventListener("click", () => {
    if (state.alerts.page > 1) loadAlerts(state.alerts.page - 1);
  });
  byId("alerts-next").addEventListener("click", () => {
    if (state.alerts.page < state.alerts.pages) loadAlerts(state.alerts.page + 1);
  });

  byId("imports-prev").addEventListener("click", () => {
    if (state.imports.page > 1) loadImports(state.imports.page - 1);
  });
  byId("imports-next").addEventListener("click", () => {
    if (state.imports.page < state.imports.pages) loadImports(state.imports.page + 1);
  });

  setupDropZone("events", "events-drop", "events-input");
  setupDropZone("signature", "signature-drop", "signature-input");

  window.addEventListener("dragover", (event) => event.preventDefault());
  window.addEventListener("drop", (event) => event.preventDefault());
}

async function init() {
  bindEvents();
  await loadMeta();
  try {
    await loadProbes();
  } catch (error) {
    setGlobalNotice(`无法读取探针配置：${error.message || "请求失败"}`);
    byId("probe-select").replaceChildren(new Option("探针配置不可用", ""));
    byId("probe-select").disabled = true;
  }
  await Promise.allSettled([loadAlerts(1), loadImports(1)]);
  updateSubmitState();
}

init();

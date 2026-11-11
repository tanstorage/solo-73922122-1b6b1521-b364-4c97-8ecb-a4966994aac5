"use strict";

const byId = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

async function getJson(url) {
  const response = await fetch(url, {
    method: "GET",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function renderProbes(probes) {
  const container = byId("home-probes");
  container.replaceChildren();
  for (const probe of probes) {
    const row = el("div", "home-probe-row");
    row.append(el("span", null, probe.probe_id));
    const state = el(
      "span",
      `state-pill ${probe.revoked ? "is-revoked" : "is-active"}`,
      probe.revoked ? "REVOKED" : "TRUSTED"
    );
    state.title = probe.revoked
      ? "该探针已不可恢复地撤销"
      : `授权主机：${probe.authorized_hosts.join("、")}`;
    row.append(state);
    container.append(row);
  }
  if (!probes.length) {
    container.append(el("p", "muted-line", "本地配置未登记任何探针。"));
  }
}

async function loadHome() {
  const [probeResult, summaryResult] = await Promise.allSettled([
    getJson("/api/probes"),
    getJson("/api/summary"),
  ]);

  if (probeResult.status === "fulfilled") {
    renderProbes(probeResult.value.probes || []);
  } else {
    const container = byId("home-probes");
    container.replaceChildren(el("p", "muted-line", "无法读取探针状态，请打开接收台检查服务。"));
  }

  if (summaryResult.status === "fulfilled") {
    const total = Number(summaryResult.value.alerts_total || 0);
    byId("home-total").textContent = total.toLocaleString("zh-CN");
  } else {
    byId("home-total").textContent = "—";
  }
}

loadHome();

/* 审批追踪工作台（运营审计）—— 独立时间线查询 + 截面锁定报表 */
"use strict";

const Audit = {
  principal: null,       // 登录主体
  principals: [],
  cursor: null,          // 当前游标
  nextCursor: null,      // 服务端颁发的下一段游标
  filters: {},           // 当前生效过滤（与游标绑定，分页中不可改）
  pages: [],             // 已读取分段（只追加展示）
  pageMeta: null,
};

const RESULT_LABEL = {
  submitted: "申请", approved: "批准", rejected: "拒绝",
  expired: "失效", exec_failed: "执行失败",
};
const ACTION_LABEL = {
  order_submit: "撤离令申请", order_approve: "批准发布", order_reject: "拒绝发布",
  batch_depart: "批次离场", batch_expire: "批次失效", relay_receipt: "中继回执",
  manual_note: "人工备注",
};

function auditHeaders() {
  return Audit.principal ? { "X-Audit-User": Audit.principal.login } : {};
}

async function auditApi(path, body) {
  const opt = body === undefined
    ? { headers: auditHeaders() }
    : { method: "POST",
        headers: { "Content-Type": "application/json", ...auditHeaders() },
        body: JSON.stringify(body) };
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const err = new Error(data.error || `HTTP ${r.status}`);
    err.payload = data;
    err.status = r.status;
    throw err;
  }
  return data;
}

function auditParams(extra = {}) {
  const p = new URLSearchParams();
  if (Audit.filters.request_id) p.set("request_id", Audit.filters.request_id);
  if (Audit.filters.actor) p.set("actor", Audit.filters.actor);
  if (Audit.filters.reviewer) p.set("reviewer", Audit.filters.reviewer);
  if (Audit.filters.action) p.set("action", Audit.filters.action);
  if (Audit.filters.result) p.set("result", Audit.filters.result);
  if (Audit.filters.time_from != null) p.set("time_from", Audit.filters.time_from);
  if (Audit.filters.time_to != null) p.set("time_to", Audit.filters.time_to);
  if (Audit.filters.limit) p.set("limit", Audit.filters.limit);
  for (const [k, v] of Object.entries(extra)) p.set(k, v);
  return p.toString();
}

function localToEpoch(v) {
  if (!v) return null;
  const t = new Date(v).getTime() / 1000;
  return Number.isFinite(t) ? t : null;
}

function readAuditFilterForm() {
  const f = {
    request_id: document.getElementById("afRequest").value.trim(),
    actor: document.getElementById("afActor").value.trim(),
    reviewer: document.getElementById("afReviewer").value.trim(),
    action: document.getElementById("afAction").value,
    result: document.getElementById("afResult").value,
    time_from: localToEpoch(document.getElementById("afFrom").value),
    time_to: localToEpoch(document.getElementById("afTo").value),
    limit: parseInt(document.getElementById("afLimit").value, 10) || 20,
  };
  return f;
}

function showAuditError(e) {
  const box = document.getElementById("auditErr");
  const code = e.payload?.code ? `[${e.payload.code}] ` : "";
  box.textContent = "⚠ " + code + (e.message || e);
  box.hidden = false;
  box.dataset.code = e.payload?.code || "";
  // 游标过期/失配：自动作废旧游标，提示重新查询
  if (["cursor_expired", "cursor_filter_mismatch"].includes(e.payload?.code)) {
    Audit.cursor = null;
    Audit.nextCursor = null;
    document.getElementById("auditNextBtn").disabled = true;
  }
}

function clearAuditError() {
  const box = document.getElementById("auditErr");
  box.hidden = true;
  box.textContent = "";
}

async function loadPrincipals() {
  const data = await auditApi("/api/audit/principals");
  Audit.principals = data.principals;
  const sel = document.getElementById("auditPrincipal");
  const saved = sessionStorage.getItem("audit_principal");
  sel.innerHTML = data.principals
    .map(p => `<option value="${esc(p.login)}">${esc(p.name)}（${esc(p.role)}）</option>`)
    .join("");
  if (saved && data.principals.some(p => p.login === saved)) sel.value = saved;
  onPrincipalChange();
}

function onPrincipalChange() {
  const login = document.getElementById("auditPrincipal").value;
  Audit.principal = Audit.principals.find(p => p.login === login) || null;
  sessionStorage.setItem("audit_principal", login);
  const tag = document.getElementById("auditPermTag");
  if (!Audit.principal) {
    tag.textContent = "";
    return;
  }
  if (Audit.principal.can_observe) {
    tag.textContent = "✓ 有观察权限";
    tag.className = "perm-tag ok";
  } else {
    tag.textContent = "✗ 无观察权限";
    tag.className = "perm-tag no";
  }
  Audit.pages = [];
  Audit.cursor = null;
  Audit.nextCursor = null;
  renderAuditRows();
  loadReports();
}

async function auditSearch(append = false) {
  clearAuditError();
  try {
    if (!append) {
      Audit.filters = readAuditFilterForm();
      Audit.cursor = null;
      Audit.pages = [];
    }
    const qs = auditParams(Audit.cursor ? { cursor: Audit.cursor } : {});
    const data = await auditApi("/api/audit/decisions?" + qs);
    Audit.pageMeta = data;
    Audit.nextCursor = data.next_cursor;
    Audit.pages.push(data.decisions);
    Audit.cursor = data.next_cursor;
    document.getElementById("auditNextBtn").disabled = !data.next_cursor;
    renderAuditRows();
  } catch (e) { showAuditError(e); }
}

function renderAuditRows() {
  const meta = Audit.pageMeta;
  const table = document.getElementById("auditTable");
  const all = Audit.pages.flat();
  if (!Audit.principal || !Audit.principal.can_observe) {
    document.getElementById("auditPageMeta").textContent =
      Audit.principal ? "当前身份没有审批观察权限，请在右上角切换为审计/复核身份。"
                      : "请选择审计身份后查询。";
    table.innerHTML = "";
    return;
  }
  if (meta) {
    document.getElementById("auditPageMeta").textContent =
      `命中 ${meta.total_matching} 条 · 已加载 ${all.length} 条`
      + (meta.next_cursor || Audit.cursor
         ? ` · 游标 ${Audit.cursor ? "有效" : "—"}（${meta.cursor_expires_in}s 过期）`
         : " · 已到末尾");
  } else {
    document.getElementById("auditPageMeta").textContent =
      "选择过滤条件后点击「查询时间线」。";
  }
  if (!all.length) {
    table.innerHTML = `<tr><td colspan="10" class="muted">无匹配审批决策</td></tr>`;
    return;
  }
  // request_id 相同的相邻行视觉归组
  let lastReq = null;
  const rows = all.map(d => {
    const group = d.request_id !== lastReq ? " req-start" : "";
    lastReq = d.request_id;
    let detail = "";
    try { detail = esc(JSON.stringify(JSON.parse(d.detail))); }
    catch { detail = esc(d.detail); }
    return `<tr class="res-${esc(d.result)}${group}">
      <td>${d.seq}</td>
      <td>${esc(fmtTime(Date.parse(d.ts) / 1000 || d.ts))}</td>
      <td class="mono">${esc(d.request_id)}</td>
      <td>${esc(d.actor)}</td>
      <td>${esc(d.reviewer)}</td>
      <td>${esc(ACTION_LABEL[d.action_kind] || d.action_kind)}</td>
      <td><span class="res-badge ${esc(d.result)}">${esc(RESULT_LABEL[d.result] || d.result)}</span></td>
      <td>${esc(d.target_type)} <span class="mono muted">${esc(d.target_ref)}</span></td>
      <td class="detail-cell">${detail}</td></tr>`;
  }).join("");
  table.innerHTML =
    `<tr><th>#</th><th>时刻</th><th>申请编号</th><th>操作者</th><th>复核者</th>
      <th>动作种类</th><th>结果</th><th>对象</th><th>明细</th></tr>` + rows;
}

async function createReport() {
  clearAuditError();
  const msg = document.getElementById("reportMsg");
  msg.textContent = "";
  try {
    // 当前过滤 + 稳定幂等键：重复点击只会取回同一份报表
    const body = { ...readAuditFilterForm() };
    delete body.limit;
    body.idem_key = "rpt_" + await hashFilters(body);
    const rep = await auditApi("/api/audit/reports", body);
    msg.innerHTML = rep.idempotent_replay
      ? `该过滤的报表此前已生成，返回同一份：<b>${esc(rep.id)}</b>（截面 r${rep.snapshot_seq}，${rep.row_count} 行）`
      : `已锁定截面：<b>${esc(rep.id)}</b>（r${rep.snapshot_seq}，${rep.row_count} 行）`;
    msg.className = "report-msg ok";
    loadReports();
  } catch (e) {
    showAuditError(e);
    msg.textContent = "⚠ " + (e.payload?.code ? `[${e.payload.code}] ` : "") + (e.message || e);
    msg.className = "report-msg err";
  }
}

async function hashFilters(f) {
  const s = JSON.stringify(f, Object.keys(f).sort());
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 24);
}

async function loadReports() {
  const box = document.getElementById("reportList");
  if (!Audit.principal || !Audit.principal.can_observe) {
    box.innerHTML = '<p class="muted">无观察权限。</p>';
    return;
  }
  try {
    const data = await auditApi("/api/audit/reports");
    if (!data.reports.length) {
      box.innerHTML = '<p class="muted">尚未生成报表。</p>';
      return;
    }
    box.innerHTML = data.reports.map(r => `
      <div class="report-item">
        <div class="report-head">
          <b class="mono">${esc(r.id)}</b>
          <span class="snap-tag">截面 r${r.snapshot_seq}</span>
          <span>${r.row_count} 行</span>
          <span class="mono muted">sha256:${esc(r.sha256.slice(0, 12))}…</span>
          <span class="muted">${fmtTime(r.snapshot_ts)} 锁定</span>
          <span class="spacer"></span>
          <a href="${r.download.json}" data-rid="${esc(r.id)}" data-fmt="json">下载 JSON</a>
          <a href="${r.download.csv}" data-rid="${esc(r.id)}" data-fmt="csv">下载 CSV</a>
        </div>
        <div class="muted report-filters">过滤：${esc(JSON.stringify(r.filters))} · 创建人 ${esc(r.created_by)}</div>
      </div>`).join("");
    box.querySelectorAll("a[data-rid]").forEach(a => a.addEventListener("click", (ev) => {
      ev.preventDefault();
      downloadReport(a.dataset.rid, a.dataset.fmt);
    }));
  } catch (e) {
    box.innerHTML = `<p class="muted">报表列表加载失败：${esc(e.message)}</p>`;
  }
}

function downloadReport(rid, fmt) {
  // 用 XHR 带头下载并保存为文件，保证下载也经过观察权限校验
  fetch(`/api/audit/reports/${rid}/content?format=${fmt}`, { headers: auditHeaders() })
    .then(async (r) => {
      if (!r.ok) {
        const data = await r.json().catch(() => ({}));
        throw new Error((data.code ? `[${data.code}] ` : "") + (data.error || r.status));
      }
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${rid}.${fmt}`;
      a.click();
      URL.revokeObjectURL(url);
    })
    .catch(e => showAuditError(e));
}

function initAuditTab() {
  const actSel = document.getElementById("afAction");
  actSel.innerHTML = `<option value="">全部动作</option>`
    + Object.entries(ACTION_LABEL).map(([k, v]) =>
      `<option value="${k}">${v}</option>`).join("");
  const resSel = document.getElementById("afResult");
  resSel.innerHTML = `<option value="">全部结果</option>`
    + Object.entries(RESULT_LABEL).map(([k, v]) =>
      `<option value="${k}">${v}</option>`).join("");

  document.getElementById("auditPrincipal").addEventListener("change", onPrincipalChange);
  document.getElementById("auditSearchBtn").addEventListener("click", () => auditSearch(false));
  document.getElementById("auditNextBtn").addEventListener("click", () => auditSearch(true));
  document.getElementById("auditResetBtn").addEventListener("click", () => {
    ["afRequest", "afActor", "afReviewer", "afFrom", "afTo"].forEach(i => document.getElementById(i).value = "");
    actSel.value = ""; resSel.value = "";
    document.getElementById("afLimit").value = "20";
    Audit.cursor = null; Audit.nextCursor = null; Audit.pages = [];
    Audit.pageMeta = null;
    document.getElementById("auditNextBtn").disabled = true;
    clearAuditError();
    renderAuditRows();
  });
  document.getElementById("reportCreateBtn").addEventListener("click", createReport);
  loadPrincipals().catch(e => toast("审计身份加载失败：" + e.message, "err"));
}

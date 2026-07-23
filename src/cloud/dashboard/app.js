/* ScopeGate Cloud panel — dependency-free vanilla JS (no build step).
 *
 * Tabs: Overview, Fleet, Approvals, Capabilities, Audit, Policy, Billing,
 * Settings. Auth: the admin token is kept in localStorage and sent as
 * `Authorization: Bearer <token>` to the same-origin /v1 API.
 */
"use strict";

const LS_TOKEN = "scopegate.cloud.adminToken";
const LS_TEAM = "scopegate.cloud.teamId";
const REFRESH_MS = 15_000;

const state = {
  token: localStorage.getItem(LS_TOKEN) || null,
  teamId: localStorage.getItem(LS_TEAM) || null,
  teams: [],
  activeTab: "overview",
  policyVersions: [],
};

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

const $ = (sel) => document.querySelector(sel);

function showError(el, err) {
  el.textContent = err && err.message ? err.message : String(err);
  el.classList.remove("hidden");
}

function clearError(el) {
  el.textContent = "";
  el.classList.add("hidden");
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || "GET",
    headers: {
      authorization: "Bearer " + state.token,
      ...(opts.body !== undefined ? { "content-type": "application/json" } : {}),
    },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok) {
    const msg = data && data.error ? data.error : "HTTP " + res.status;
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return data;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function fmtTs(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
}

function fmtAgo(ts) {
  if (!ts) return "—";
  const ms = Date.now() - new Date(ts).getTime();
  if (Number.isNaN(ms)) return String(ts);
  return fmtDuration(ms) + " ago";
}

function fmtDuration(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return s + "s";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m" + (s % 60 ? (s % 60) + "s" : "");
  const h = Math.floor(m / 60);
  if (h < 24) return h + "h" + (m % 60 ? (m % 60) + "m" : "");
  return Math.floor(h / 24) + "d" + (h % 24 ? (h % 24) + "h" : "");
}

function shortJson(obj, max = 90) {
  const s = JSON.stringify(obj);
  return s.length > max ? s.slice(0, max) + "…" : s;
}

/* ------------------------------------------------------------------ */
/* login / logout                                                      */
/* ------------------------------------------------------------------ */

async function login(token) {
  state.token = token;
  try {
    await api("/v1/admin/teams");
  } catch (e) {
    state.token = null;
    throw e;
  }
  localStorage.setItem(LS_TOKEN, token);
  await boot();
}

function logout() {
  localStorage.removeItem(LS_TOKEN);
  state.token = null;
  location.reload();
}

/* ------------------------------------------------------------------ */
/* boot & team selection                                               */
/* ------------------------------------------------------------------ */

async function boot() {
  const { teams } = await api("/v1/admin/teams");
  state.teams = teams;

  if (!state.teamId || !teams.some((t) => t.teamId === state.teamId)) {
    state.teamId = teams.length > 0 ? teams[0].teamId : null;
  }
  if (state.teamId) localStorage.setItem(LS_TEAM, state.teamId);

  $("#login").classList.add("hidden");

  if (teams.length === 0) {
    // First-run onboarding wizard (EPIC-10 H10.5: first gateway in < 2 min).
    $("#app").classList.add("hidden");
    $("#topbar").classList.add("hidden");
    $("#onboarding").classList.remove("hidden");
    return;
  }

  $("#onboarding").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#topbar").classList.remove("hidden");
  $("#who").textContent = "admin";

  const sel = $("#team-select");
  sel.innerHTML = "";
  for (const t of teams) {
    const opt = document.createElement("option");
    opt.value = t.teamId;
    opt.textContent = t.name + " (" + t.teamId + ")";
    if (t.teamId === state.teamId) opt.selected = true;
    sel.appendChild(opt);
  }

  await reloadActiveTab();
  await Promise.all([loadFingerprint(), renderSettings()]);
}

async function createTeam(name) {
  const created = await api("/v1/admin/teams", { method: "POST", body: { name: name.trim() } });
  state.teamId = created.teamId;
  localStorage.setItem(LS_TEAM, created.teamId);
  return created;
}

async function reloadActiveTab() {
  clearError($("#global-error"));
  const loaders = {
    overview: loadOverview,
    fleet: loadAgents,
    approvals: loadApprovals,
    capabilities: loadCapabilities,
    audit: runAuditQuery,
    policy: loadPolicy,
    billing: () => {},
    settings: renderSettings,
  };
  const loader = loaders[state.activeTab] || (() => {});
  await loader().catch((e) => showError($("#global-error"), e));
  await refreshApprovalsBadge().catch(() => {});
}

/* ------------------------------------------------------------------ */
/* overview                                                            */
/* ------------------------------------------------------------------ */

async function loadOverview() {
  if (!state.teamId) return;
  const ov = await api("/v1/admin/overview?teamId=" + encodeURIComponent(state.teamId));

  const cards = [
    { num: ov.agents.online, lbl: "agents online", cls: ov.agents.online > 0 ? "ok" : "" },
    { num: ov.agents.total, lbl: "agents enrolled" },
    { num: ov.approvals.pending, lbl: "pending approvals", cls: ov.approvals.pending > 0 ? "warn" : "" },
    { num: ov.audit.last24h, lbl: "events (24 h)" },
    { num: ov.policy ? "v" + ov.policy.version : "—", lbl: "team policy" },
    {
      num: Object.values(ov.security24h).reduce((a, b) => a + b, 0),
      lbl: "security events (24 h)",
      cls: Object.values(ov.security24h).reduce((a, b) => a + b, 0) > 0 ? "danger-text" : "",
    },
  ];
  $("#overview-cards").innerHTML = cards
    .map(
      (c) =>
        `<div class="card"><div class="num ${c.cls || ""}">${esc(c.num)}</div>` +
        `<div class="lbl">${esc(c.lbl)}</div></div>`,
    )
    .join("");

  const tbody = $("#health-table tbody");
  tbody.innerHTML = "";
  $("#health-empty").classList.toggle("hidden", ov.agents.health.length > 0);
  for (const h of ov.agents.health) {
    const tr = document.createElement("tr");
    const status = h.revoked
      ? '<span class="pill pill-bad">revoked</span>'
      : h.online
        ? '<span class="pill pill-ok">online</span>'
        : '<span class="pill pill-dim">offline</span>';
    tr.innerHTML =
      "<td class=mono>" + esc(h.agentId) + "</td>" +
      "<td title='" + esc(fmtTs(h.lastSeen)) + "'>" + esc(fmtAgo(h.lastSeen)) + "</td>" +
      "<td>" + status + "</td>";
    tbody.appendChild(tr);
  }

  const stbody = $("#security-table tbody");
  stbody.innerHTML = "";
  $("#security-empty").classList.toggle("hidden", ov.recentSecurityEvents.length > 0);
  for (const e of ov.recentSecurityEvents) {
    const tr = document.createElement("tr");
    const detail = shortJson(e.detail);
    tr.innerHTML =
      "<td class=mono>" + esc(e.ts.slice(0, 19).replace("T", " ")) + "</td>" +
      "<td class=mono>" + esc(e.agentId) + "</td>" +
      "<td class=mono>" + esc(e.kind) + "</td>" +
      "<td class=mono title='" + esc(JSON.stringify(e.detail)) + "'>" + esc(detail) + "</td>";
    stbody.appendChild(tr);
  }
}

/* ------------------------------------------------------------------ */
/* fleet (agents + revocation with blast radius)                       */
/* ------------------------------------------------------------------ */

async function loadAgents() {
  const tbody = $("#agents-table tbody");
  tbody.innerHTML = "";
  if (!state.teamId) { $("#agents-empty").classList.remove("hidden"); return; }
  const { agents } = await api("/v1/admin/agents?teamId=" + encodeURIComponent(state.teamId));
  $("#agents-empty").classList.toggle("hidden", agents.length > 0);
  const team = state.teams.find((t) => t.teamId === state.teamId);
  $("#fleet-enroll-snippet").textContent = team ? enrollSnippet(team) : "";
  for (const a of agents) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td class=mono>" + esc(a.agentId) + "</td>" +
      "<td class=mono title='" + esc(a.fingerprint) + "'>" + esc(a.fingerprint.slice(0, 23)) + "…</td>" +
      "<td>" + esc(fmtTs(a.enrolledAt)) + "</td>" +
      "<td>" + esc(fmtAgo(a.lastSeen)) + "</td>" +
      "<td>" + (a.revoked ? "<span class='pill pill-bad'>revoked</span>" : "<span class='pill pill-ok'>active</span>") + "</td>" +
      "<td></td>";
    if (!a.revoked) {
      const btn = document.createElement("button");
      btn.className = "danger small";
      btn.textContent = "Revoke…";
      btn.onclick = () => openRevokeModal({ scope: "agent", agentId: a.agentId });
      tr.lastChild.appendChild(btn);
    }
    tbody.appendChild(tr);
  }
}

/* ---------------- revocation modal (blast radius) ------------------ */

const revokeState = { scope: null, agentId: null };

function openRevokeModal(opts) {
  const team = state.teams.find((t) => t.teamId === state.teamId);
  revokeState.scope = opts.scope;
  revokeState.agentId = opts.agentId || null;

  if (opts.scope === "team") {
    const n = team ? team.agentCount : 0;
    $("#revoke-title").textContent = "Revoke the whole team";
    $("#revoke-blast").innerHTML =
      "<strong>Blast radius:</strong> this revokes <strong>ALL " + esc(n) +
      " agent(s)</strong> of team <strong>" + esc(team ? team.name : "") + "</strong> — every grant purged, every request denied fail-closed.";
    $("#revoke-confirm-wrap").style.display = "block";
    $("#revoke-confirm-word").textContent = team ? team.name : "";
    $("#revoke-confirm-input").value = "";
  } else {
    $("#revoke-title").textContent = "Revoke agent";
    $("#revoke-blast").innerHTML =
      "<strong>Blast radius:</strong> this revokes <strong>1 agent</strong>: <span class=mono>" +
      esc(opts.agentId) + "</span>. Other agents are not affected.";
    $("#revoke-confirm-wrap").style.display = "none";
  }
  $("#revoke-reason").value = "";
  $("#revoke-confirm").disabled = true;
  $("#revoke-modal").classList.remove("hidden");
  $("#revoke-reason").focus();
}

function closeRevokeModal() {
  $("#revoke-modal").classList.add("hidden");
  revokeState.scope = null;
  revokeState.agentId = null;
}

function revokeModalValid() {
  const reason = $("#revoke-reason").value.trim();
  if (!reason) return false;
  if (revokeState.scope === "team") {
    const team = state.teams.find((t) => t.teamId === state.teamId);
    return $("#revoke-confirm-input").value.trim() === (team ? team.name : "\0");
  }
  return true;
}

async function confirmRevoke() {
  const reason = $("#revoke-reason").value.trim();
  const agentId = revokeState.scope === "team" ? "*" : revokeState.agentId;
  await api("/v1/admin/revocations", {
    method: "POST",
    body: { teamId: state.teamId, agentId, reason },
  });
  closeRevokeModal();
  await Promise.all([loadAgents(), loadOverview().catch(() => {})]);
}

/* ------------------------------------------------------------------ */
/* approvals                                                           */
/* ------------------------------------------------------------------ */

async function refreshApprovalsBadge() {
  if (!state.teamId) return;
  const { approvals } = await api(
    "/v1/admin/approvals?teamId=" + encodeURIComponent(state.teamId) + "&status=pending",
  );
  const badge = $("#approvals-badge");
  badge.classList.toggle("hidden", approvals.length === 0);
  badge.textContent = String(approvals.length);
}

async function loadApprovals() {
  if (!state.teamId) return;
  const { approvals } = await api("/v1/admin/approvals?teamId=" + encodeURIComponent(state.teamId));

  const pending = approvals.filter((a) => a.status === "pending");
  const resolved = approvals.filter((a) => a.status !== "pending");

  const tbody = $("#approvals-table tbody");
  tbody.innerHTML = "";
  $("#approvals-empty").classList.toggle("hidden", pending.length > 0);
  for (const a of pending) {
    const tr = document.createElement("tr");
    const expiresIn = a.expiresAt ? fmtDuration(new Date(a.expiresAt).getTime() - Date.now()) : "—";
    tr.innerHTML =
      "<td title='" + esc(fmtTs(a.requestedAt)) + "'>" + esc(fmtAgo(a.requestedAt)) + "</td>" +
      "<td class=mono>" + esc(a.agentId) + "</td>" +
      "<td class=mono>" + esc(a.capability) + "</td>" +
      "<td class=mono>" + esc(a.ttl || "(none)") + "</td>" +
      "<td>" + esc(a.reason || "—") + "</td>" +
      "<td class=countdown>" + esc(expiresIn) + "</td>" +
      "<td></td>";

    const approveBtn = document.createElement("button");
    approveBtn.className = "small";
    approveBtn.textContent = "Approve";
    approveBtn.onclick = () => resolveApprovalFlow(a, "approve");
    const denyBtn = document.createElement("button");
    denyBtn.className = "danger small";
    denyBtn.textContent = "Deny";
    denyBtn.onclick = () => resolveApprovalFlow(a, "deny");
    const cell = tr.lastChild;
    cell.appendChild(approveBtn);
    cell.appendChild(document.createTextNode(" "));
    cell.appendChild(denyBtn);
    tbody.appendChild(tr);
  }

  const rtbody = $("#approvals-resolved-table tbody");
  rtbody.innerHTML = "";
  $("#approvals-resolved-empty").classList.toggle("hidden", resolved.length > 0);
  for (const a of resolved.slice(0, 50)) {
    const tr = document.createElement("tr");
    const pill =
      a.status === "approved"
        ? '<span class="pill pill-ok">approved</span>'
        : a.status === "denied"
          ? '<span class="pill pill-bad">denied</span>'
          : '<span class="pill pill-dim">expired</span>';
    tr.innerHTML =
      "<td title='" + esc(fmtTs(a.requestedAt)) + "'>" + esc(fmtAgo(a.requestedAt)) + "</td>" +
      "<td class=mono>" + esc(a.agentId) + "</td>" +
      "<td class=mono>" + esc(a.capability) + "</td>" +
      "<td>" + pill + "</td>" +
      "<td class=mono>" + esc(a.decidedBy || "—") + "</td>" +
      "<td>" + (a.resolution ? esc(a.resolution) : "—") + "</td>";
    rtbody.appendChild(tr);
  }
}

async function resolveApprovalFlow(a, decision) {
  const body = { teamId: state.teamId, approvalId: a.approvalId, decision };
  if (decision === "approve") {
    const ttl = window.prompt(
      "Approve “" + a.capability + "” for " + a.agentId + ".\n\n" +
      "Optional: shorten the TTL (e.g. 5m — must be ≤ the asked " + (a.ttl || "unbounded") + ").\n" +
      "Leave empty to keep the agent's ask.",
    );
    if (ttl === null) return; // cancelled
    if (ttl.trim()) body.ttl = ttl.trim();
  } else {
    let reason = null;
    while (reason === null || reason.trim() === "") {
      reason = window.prompt("Deny “" + a.capability + "” for " + a.agentId + ".\nReason (MANDATORY — the agent sees it):");
      if (reason === null) return;
    }
    body.reason = reason.trim();
  }
  try {
    await api("/v1/admin/approvals/resolve", { method: "POST", body });
  } catch (e) {
    showError($("#global-error"), e);
    return;
  }
  await loadApprovals();
}

/* ------------------------------------------------------------------ */
/* capabilities                                                        */
/* ------------------------------------------------------------------ */

async function loadCapabilities() {
  if (!state.teamId) return;
  const { capabilities } = await api(
    "/v1/admin/capabilities?teamId=" + encodeURIComponent(state.teamId),
  );
  const tbody = $("#capabilities-table tbody");
  tbody.innerHTML = "";
  $("#capabilities-empty").classList.toggle("hidden", capabilities.length > 0);
  for (const c of capabilities) {
    const tr = document.createElement("tr");
    const low = c.remainingMs < 60_000;
    tr.innerHTML =
      "<td class=mono>" + esc(c.agentId) + "</td>" +
      "<td class=mono>" + esc(c.capability) + "</td>" +
      "<td title='" + esc(fmtTs(c.issuedAt)) + "'>" + esc(fmtAgo(c.issuedAt)) + "</td>" +
      "<td class='countdown " + (low ? "warn" : "") + "' title='expires " + esc(fmtTs(c.expiresAt)) + "'>" +
        esc(fmtDuration(c.remainingMs)) + "</td>" +
      "<td class=mono>" + esc(c.rule || "—") + "</td>" +
      "<td>" + (c.via === "human_approval" ? '<span class="pill pill-warn">human approval</span>' : '<span class="pill pill-dim">auto</span>') + "</td>";
    tbody.appendChild(tr);
  }
}

/* ------------------------------------------------------------------ */
/* audit                                                               */
/* ------------------------------------------------------------------ */

async function runAuditQuery() {
  if (!state.teamId) return;
  const params = new URLSearchParams({ teamId: state.teamId });
  const agent = $("#audit-agent").value.trim();
  const kind = $("#audit-kind").value;
  const since = $("#audit-since").value;
  if (agent) params.set("agentId", agent);
  if (kind) params.set("kind", kind);
  if (since) params.set("since", new Date(since).toISOString());
  const { events } = await api("/v1/admin/audit?" + params.toString());
  const tbody = $("#audit-table tbody");
  tbody.innerHTML = "";
  $("#audit-empty").classList.toggle("hidden", events.length > 0);
  for (const e of events) {
    const tr = document.createElement("tr");
    const detail = shortJson(e.detail);
    tr.innerHTML =
      "<td class=mono>" + esc(e.ts.slice(0, 19).replace("T", " ")) + "</td>" +
      "<td class=mono>" + esc(e.agentId) + "</td>" +
      "<td class=mono>" + esc(e.kind) + "</td>" +
      "<td class=mono>" + esc(e.seq) + "</td>" +
      "<td class=mono title='" + esc(JSON.stringify(e.detail)) + "'>" + esc(detail) + "</td>" +
      "<td>" + (e._cloud && e._cloud.sigVerified ? '<span class="pill pill-ok">✓</span>' : '<span class="pill pill-bad">✗</span>') + "</td>";
    tbody.appendChild(tr);
  }
}

async function exportAudit() {
  if (!state.teamId) return;
  const res = await fetch("/v1/admin/audit/export?teamId=" + encodeURIComponent(state.teamId), {
    headers: { authorization: "Bearer " + state.token },
  });
  if (!res.ok) {
    showError($("#global-error"), new Error("export failed (HTTP " + res.status + ")"));
    return;
  }
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "scopegate-audit-" + state.teamId + ".jsonl";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

/* ------------------------------------------------------------------ */
/* policy (editor + versions + diff)                                   */
/* ------------------------------------------------------------------ */

async function loadPolicy() {
  if (!state.teamId) return;
  try {
    const p = await api("/v1/policy?teamId=" + encodeURIComponent(state.teamId));
    $("#policy-yaml").value = p.yaml;
    $("#policy-version").textContent =
      "v" + p.version + " · signed " + fmtTs(p.signedAt) + " · " + p.signature.slice(0, 24) + "…";
  } catch (e) {
    if (e.status === 404) {
      $("#policy-yaml").value = "";
      $("#policy-version").textContent = "none published yet";
    } else {
      throw e;
    }
  }
  await loadPolicyVersions();
}

async function loadPolicyVersions() {
  const { versions } = await api("/v1/admin/policy/versions?teamId=" + encodeURIComponent(state.teamId));
  state.policyVersions = versions;
  const sel = $("#policy-version-select");
  sel.innerHTML = "";
  $("#policy-versions-empty").classList.toggle("hidden", versions.length > 0);
  for (const v of [...versions].reverse()) {
    const opt = document.createElement("option");
    opt.value = String(v.version);
    opt.textContent = "v" + v.version + " — " + fmtTs(v.signedAt);
    sel.appendChild(opt);
  }
  if (versions.length > 0) renderPolicyDiff();
}

function renderPolicyDiff() {
  const sel = $("#policy-version-select");
  const v = state.policyVersions.find((x) => String(x.version) === sel.value);
  if (!v) { $("#policy-diff").innerHTML = ""; $("#policy-version-meta").textContent = ""; return; }
  $("#policy-version-meta").textContent = "signed " + fmtTs(v.signedAt) + " · " + v.signature.slice(0, 20) + "…";
  const prev = state.policyVersions.find((x) => x.version === v.version - 1);
  $("#policy-diff").innerHTML = prev
    ? diffLines(prev.yaml, v.yaml)
    : '<span class="ctx">(first published version — full document)</span>\n' +
      v.yaml.split("\n").map((l) => '<span class="add">+ ' + esc(l) + "</span>").join("\n");
}

/** Minimal LCS line diff → HTML with add/del/ctx spans. */
function diffLines(oldText, newText) {
  const a = oldText.split("\n");
  const b = newText.split("\n");
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  let i = 0, j = 0;
  const out = [];
  while (i < m && j < n) {
    if (a[i] === b[j]) { out.push('<span class="ctx">  ' + esc(a[i]) + "</span>"); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push('<span class="del">- ' + esc(a[i]) + "</span>"); i++; }
    else { out.push('<span class="add">+ ' + esc(b[j]) + "</span>"); j++; }
  }
  while (i < m) { out.push('<span class="del">- ' + esc(a[i]) + "</span>"); i++; }
  while (j < n) { out.push('<span class="add">+ ' + esc(b[j]) + "</span>"); j++; }
  return out.join("\n");
}

async function savePolicy() {
  const yaml = $("#policy-yaml").value;
  const status = $("#policy-status");
  status.textContent = "signing…";
  try {
    const p = await api("/v1/admin/policy", {
      method: "PUT",
      body: { teamId: state.teamId, yaml },
    });
    status.textContent = "published v" + p.version + " at " + fmtTs(p.signedAt) + " — gateways pick it up on their next sync tick";
    await loadPolicy();
  } catch (e) {
    status.textContent = "";
    showError($("#global-error"), e);
  }
}

/* ------------------------------------------------------------------ */
/* billing                                                             */
/* ------------------------------------------------------------------ */

async function runBilling() {
  const params = new URLSearchParams({ teamId: state.teamId });
  if ($("#billing-month").value) params.set("month", $("#billing-month").value);
  const u = await api("/v1/billing/usage?" + params.toString());
  $("#billing-result").innerHTML =
    "<div class=kv>Period: <span class=mono>" + esc(u.period) + "</span> " +
    "<span class=dim>(" + esc(u.start) + " → " + esc(u.end) + ")</span></div>" +
    "<div class=kv>Active agents: <strong>" + esc(u.activeAgents) + "</strong></div>" +
    (u.agents.length
      ? "<div class=kv>" + u.agents.map((a) => "<span class=mono>" + esc(a) + "</span>").join(", ") + "</div>"
      : "<div class='kv dim'>No active agents this period.</div>");
}

/* ------------------------------------------------------------------ */
/* settings                                                            */
/* ------------------------------------------------------------------ */

async function loadFingerprint() {
  try {
    const { fingerprint } = await api("/v1/pubkey");
    $("#cloud-fp").textContent = fingerprint;
  } catch { /* informational only */ }
}

function enrollSnippet(team) {
  return [
    "# enroll this gateway into team " + team.name,
    "scopegate cloud enroll \\",
    "  --cloud " + location.origin + " \\",
    "  --token " + team.enrollToken,
  ].join("\n");
}

async function renderSettings() {
  const team = state.teams.find((t) => t.teamId === state.teamId);
  $("#settings-team").textContent = team ? team.name + " (" + team.teamId + ")" : "—";
  $("#enroll-snippet").textContent = team ? enrollSnippet(team) : "# create a team first";
  $("#webhook-url").value = "";
  $("#webhook-status").textContent = team && team.slackWebhookConfigured
    ? "A Slack webhook is configured for this team."
    : "No webhook configured — approval alerts are off.";
}

async function saveWebhook() {
  const url = $("#webhook-url").value.trim();
  if (!url) return;
  await api("/v1/admin/alerts", {
    method: "POST",
    body: { teamId: state.teamId, webhookUrl: url },
  });
  const team = state.teams.find((t) => t.teamId === state.teamId);
  if (team) team.slackWebhookConfigured = true;
  $("#webhook-status").textContent = "Webhook saved.";
}

/* ------------------------------------------------------------------ */
/* wiring                                                              */
/* ------------------------------------------------------------------ */

document.addEventListener("DOMContentLoaded", () => {
  $("#login-btn").onclick = async () => {
    clearError($("#login-error"));
    try {
      await login($("#token-input").value.trim());
    } catch (e) {
      showError($("#login-error"), "Sign-in failed: " + (e.message || e));
    }
  };
  $("#token-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#login-btn").click();
  });
  $("#logout").onclick = logout;

  $("#new-team").onclick = async () => {
    const name = window.prompt("Team name:");
    if (!name || !name.trim()) return;
    try {
      const created = await createTeam(name);
      alert(
        "Team created: " + created.teamId +
        "\n\nEnroll token (store it safely — it is the team root credential):\n" + created.enrollToken,
      );
      await boot();
    } catch (e) {
      showError($("#global-error"), e);
    }
  };

  // Onboarding wizard.
  $("#onboard-create-team").onclick = async () => {
    const name = $("#onboard-team-name").value.trim();
    if (!name) return;
    try {
      const created = await createTeam(name);
      $("#onboard-enroll-snippet").textContent =
        "# enroll this gateway into team " + name + "\n" +
        "scopegate cloud enroll \\\n  --cloud " + location.origin + " \\\n  --token " + created.enrollToken;
      $("#onboard-waiting").textContent =
        "Team created. Enroll token (shown once): " + created.enrollToken +
        " — waiting for the first agent…";
      // Poll until the first agent enrolls, then boot into the app.
      const timer = setInterval(async () => {
        try {
          const { agents } = await api("/v1/admin/agents?teamId=" + encodeURIComponent(created.teamId));
          if (agents.length > 0) {
            clearInterval(timer);
            await boot();
          }
        } catch { /* keep polling */ }
      }, 4000);
    } catch (e) {
      showError($("#global-error"), e);
    }
  };

  $("#team-select").onchange = async (e) => {
    state.teamId = e.target.value;
    localStorage.setItem(LS_TEAM, state.teamId);
    await reloadActiveTab();
    await renderSettings();
  };

  $("#reload-overview").onclick = () => loadOverview().catch((e) => showError($("#global-error"), e));
  $("#reload-agents").onclick = () => loadAgents().catch((e) => showError($("#global-error"), e));
  $("#reload-approvals").onclick = () => loadApprovals().catch((e) => showError($("#global-error"), e));
  $("#reload-capabilities").onclick = () => loadCapabilities().catch((e) => showError($("#global-error"), e));
  $("#revoke-team").onclick = () => openRevokeModal({ scope: "team" });
  $("#revoke-cancel").onclick = closeRevokeModal;
  $("#revoke-reason").oninput = () => { $("#revoke-confirm").disabled = !revokeModalValid(); };
  $("#revoke-confirm-input").oninput = () => { $("#revoke-confirm").disabled = !revokeModalValid(); };
  $("#revoke-confirm").onclick = () => confirmRevoke().catch((e) => {
    closeRevokeModal();
    showError($("#global-error"), e);
  });
  $("#policy-save").onclick = savePolicy;
  $("#policy-version-select").onchange = renderPolicyDiff;
  $("#audit-run").onclick = () => runAuditQuery().catch((e) => showError($("#global-error"), e));
  $("#audit-export").onclick = () => exportAudit().catch((e) => showError($("#global-error"), e));
  $("#billing-run").onclick = () => runBilling().catch((e) => showError($("#global-error"), e));
  $("#webhook-save").onclick = () => saveWebhook().catch((e) => showError($("#global-error"), e));

  document.querySelectorAll(".tabs button").forEach((btn) => {
    btn.onclick = () => {
      document.querySelectorAll(".tabs button").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      document.querySelectorAll("main section").forEach((s) => s.classList.add("hidden"));
      $("#tab-" + btn.dataset.tab).classList.remove("hidden");
      state.activeTab = btn.dataset.tab;
      if (btn.dataset.tab === "billing" && !$("#billing-month").value) {
        const now = new Date();
        $("#billing-month").value =
          now.getUTCFullYear() + "-" + String(now.getUTCMonth() + 1).padStart(2, "0");
      }
      reloadActiveTab();
    };
  });

  // Default month on the billing input.
  const now = new Date();
  $("#billing-month").value =
    now.getUTCFullYear() + "-" + String(now.getUTCMonth() + 1).padStart(2, "0");

  // Auto-refresh: overview, approvals, capabilities and the badge stay fresh.
  setInterval(() => {
    if (document.hidden || !state.token || $("#app").classList.contains("hidden")) return;
    if (["overview", "approvals", "capabilities"].includes(state.activeTab)) {
      reloadActiveTab();
    } else {
      refreshApprovalsBadge().catch(() => {});
    }
  }, REFRESH_MS);

  if (state.token) {
    boot().catch((e) => {
      localStorage.removeItem(LS_TOKEN);
      state.token = null;
      showError($("#login-error"), "Session rejected: " + (e.message || e));
    });
  }
});

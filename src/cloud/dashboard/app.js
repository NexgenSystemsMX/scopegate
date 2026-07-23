/* ScopeGate Cloud dashboard — dependency-free vanilla JS (EPIC-10, H10.5).
 *
 * Auth: the admin token is kept in localStorage and sent as
 * `Authorization: Bearer <token>` to the same-origin /v1 API. No cookies,
 * no frameworks, no build step.
 */
"use strict";

const LS_TOKEN = "scopegate.cloud.adminToken";
const LS_TEAM = "scopegate.cloud.teamId";

const state = {
  token: localStorage.getItem(LS_TOKEN) || null,
  teamId: localStorage.getItem(LS_TEAM) || null,
  teams: [],
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
  if (teams.length === 0) {
    const opt = document.createElement("option");
    opt.textContent = "(create a team first)";
    sel.appendChild(opt);
  }

  await Promise.all([loadAgents(), loadPolicy(), loadFingerprint(), renderSettings()]);
}

async function createTeam() {
  const name = window.prompt("Team name:");
  if (!name || !name.trim()) return;
  const created = await api("/v1/admin/teams", { method: "POST", body: { name: name.trim() } });
  state.teamId = created.teamId;
  localStorage.setItem(LS_TEAM, created.teamId);
  await boot();
  alert(
    "Team created: " + created.teamId +
    "\n\nEnroll token (store it safely — it is the team root credential):\n" + created.enrollToken
  );
}

/* ------------------------------------------------------------------ */
/* agents                                                              */
/* ------------------------------------------------------------------ */

async function loadAgents() {
  clearError($("#global-error"));
  const tbody = $("#agents-table tbody");
  tbody.innerHTML = "";
  if (!state.teamId) { $("#agents-empty").classList.remove("hidden"); return; }
  const { agents } = await api("/v1/admin/agents?teamId=" + encodeURIComponent(state.teamId));
  $("#agents-empty").classList.toggle("hidden", agents.length > 0);
  for (const a of agents) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td class=mono>" + esc(a.agentId) + "</td>" +
      "<td class=mono title='" + esc(a.fingerprint) + "'>" + esc(a.fingerprint.slice(0, 23)) + "…</td>" +
      "<td>" + esc(fmtTs(a.enrolledAt)) + "</td>" +
      "<td>" + esc(fmtTs(a.lastSeen)) + "</td>" +
      "<td>" + (a.revoked ? "<span class=danger-text>revoked</span>" : "<span class=ok>active</span>") + "</td>" +
      "<td></td>";
    if (!a.revoked) {
      const btn = document.createElement("button");
      btn.className = "danger";
      btn.textContent = "Revoke";
      btn.onclick = () => revokeAgent(a.agentId);
      tr.lastChild.appendChild(btn);
    }
    tbody.appendChild(tr);
  }
}

async function revokeAgent(agentId) {
  let reason = null;
  // Motivo obligatorio — la revocación por flota sin motivo no es auditable.
  while (reason === null || reason.trim() === "") {
    reason = window.prompt(
      "Revoke agent “" + agentId + "”.\nReason (MANDATORY — goes to the audit feed):"
    );
    if (reason === null) return; // cancelled
  }
  await api("/v1/admin/revocations", {
    method: "POST",
    body: { teamId: state.teamId, agentId, reason: reason.trim() },
  });
  await loadAgents();
}

/* ------------------------------------------------------------------ */
/* policy                                                              */
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
    status.textContent = "published v" + p.version + " at " + fmtTs(p.signedAt);
    await loadPolicy();
  } catch (e) {
    status.textContent = "";
    showError($("#global-error"), e);
  }
}

/* ------------------------------------------------------------------ */
/* audit                                                               */
/* ------------------------------------------------------------------ */

async function runAuditQuery() {
  clearError($("#global-error"));
  const params = new URLSearchParams({ teamId: state.teamId });
  const agent = $("#audit-agent").value.trim();
  const kind = $("#audit-kind").value.trim();
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
    const detail = JSON.stringify(e.detail);
    tr.innerHTML =
      "<td class=mono>" + esc(e.ts) + "</td>" +
      "<td class=mono>" + esc(e.agentId) + "</td>" +
      "<td class=mono>" + esc(e.kind) + "</td>" +
      "<td class=mono>" + esc(e.seq) + "</td>" +
      "<td class=mono title='" + esc(detail) + "'>" + esc(detail.length > 90 ? detail.slice(0, 90) + "…" : detail) + "</td>" +
      "<td>" + (e._cloud && e._cloud.sigVerified ? "<span class=ok>✓</span>" : "<span class=danger-text>✗</span>") + "</td>";
    tbody.appendChild(tr);
  }
}

/* ------------------------------------------------------------------ */
/* billing                                                             */
/* ------------------------------------------------------------------ */

async function runBilling() {
  clearError($("#global-error"));
  const params = new URLSearchParams({ teamId: state.teamId });
  if ($("#billing-month").value) params.set("month", $("#billing-month").value);
  const u = await api("/v1/billing/usage?" + params.toString());
  $("#billing-result").innerHTML =
    "<div class=kv>Period: <span class=mono>" + esc(u.period) + "</span> " +
    "<span class=dim>(" + esc(u.start) + " → " + esc(u.end) + ")</span></div>" +
    "<div class=kv>Active agents: <strong>" + esc(u.activeAgents) + "</strong></div>" +
    (u.agents.length
      ? "<div class=kv class=mono>" + u.agents.map((a) => "<span class=mono>" + esc(a) + "</span>").join(", ") + "</div>"
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

async function renderSettings() {
  const team = state.teams.find((t) => t.teamId === state.teamId);
  $("#settings-team").textContent = team ? team.name + " (" + team.teamId + ")" : "—";
  $("#enroll-snippet").textContent = team
    ? [
        "# enroll this gateway into team " + team.name,
        "scopegate cloud enroll \\",
        "  --cloud " + location.origin + " \\",
        "  --token " + team.enrollToken,
      ].join("\n")
    : "# create a team first";
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
  $("#new-team").onclick = () => createTeam().catch((e) => showError($("#global-error"), e));
  $("#team-select").onchange = async (e) => {
    state.teamId = e.target.value;
    localStorage.setItem(LS_TEAM, state.teamId);
    await Promise.all([loadAgents(), loadPolicy(), renderSettings()]);
  };
  $("#reload-agents").onclick = () => loadAgents().catch((e) => showError($("#global-error"), e));
  $("#policy-save").onclick = savePolicy;
  $("#audit-run").onclick = () => runAuditQuery().catch((e) => showError($("#global-error"), e));
  $("#billing-run").onclick = () => runBilling().catch((e) => showError($("#global-error"), e));
  $("#webhook-save").onclick = () => saveWebhook().catch((e) => showError($("#global-error"), e));

  document.querySelectorAll(".tabs button").forEach((btn) => {
    btn.onclick = () => {
      document.querySelectorAll(".tabs button").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      document.querySelectorAll("main section").forEach((s) => s.classList.add("hidden"));
      $("#tab-" + btn.dataset.tab).classList.remove("hidden");
      if (btn.dataset.tab === "billing" && !$("#billing-month").value) {
        const now = new Date();
        $("#billing-month").value =
          now.getUTCFullYear() + "-" + String(now.getUTCMonth() + 1).padStart(2, "0");
      }
    };
  });

  // Default month on the billing input.
  const now = new Date();
  $("#billing-month").value =
    now.getUTCFullYear() + "-" + String(now.getUTCMonth() + 1).padStart(2, "0");

  if (state.token) {
    boot().catch((e) => {
      localStorage.removeItem(LS_TOKEN);
      state.token = null;
      showError($("#login-error"), "Session rejected: " + (e.message || e));
    });
  }
});

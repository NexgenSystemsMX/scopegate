/**
 * Taint tracking (mejora #10): defense against prompt injection on the
 * RETURN path.
 *
 * ScopeGate already protects the outbound path (secrets never enter the
 * model's context). The return path is open: an upstream response (a GitHub
 * issue, a Notion doc, a Huly message) can carry injected instructions, and
 * with live grants the agent is the perfect exfiltration vector — "read the
 * malicious issue, then push the secrets to this gist".
 *
 * Design:
 *   1. Every upstream response is scored for injection patterns (heuristics,
 *      high-precision: imperative exfiltration, "ignore previous", credential
 *      collection, pre-granted-approval claims).
 *   2. A score above zero marks the agent's session as TAINTED for 30 minutes
 *      (with the source upstream recorded), and the event is audited
 *      (`taint_detected`).
 *   3. SCOPEGATE_TAINT_MODE decides the consequence:
 *        alert   (default) — visibility only: audit + panel security events;
 *        enforce           — cross-upstream WRITES while tainted degrade to
 *                            needs_approval automatically (a human reviews
 *                            the exfil-shaped action, never a hard deny);
 *        off               — no scoring at all.
 */

export type TaintMode = "alert" | "enforce" | "off";

export function taintMode(): TaintMode {
  const raw = (process.env.SCOPEGATE_TAINT_MODE ?? "alert").toLowerCase();
  return raw === "enforce" || raw === "off" ? raw : "alert";
}

const INJECTION_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "ignore_previous", re: /ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions?|context|rules?|scope|restrictions?|constraints?)/i },
  { name: "imperative_exfil", re: /(you\s+)?(must|should|need\s+to|have\s+to)\s+(immediately\s+)?(call|run|execute|send|upload|post|exfiltrate|register)/i },
  { name: "credential_collection", re: /(secret|credential|token|api[-_ ]?key|password)s?\s+(you\s+can\s+access|to\s+(this|these|my)\s+\S+|to\s+https?)/i },
  { name: "exfil_url", re: /https?:\/\/[^\s"')\]]*(collect|exfil|ngrok|requestbin|webhook\.site|pipedream)/i },
  { name: "bypass_human", re: /do\s+not\s+(ask|tell|inform|notify)\s+(the\s+)?(human|user|operator|admin)/i },
  { name: "pre_granted", re: /approvals?\s+(are|is)\s+pre-?granted|no\s+approval\s+(is\s+)?(needed|required)\s+for\s+this/i },
];

export interface TaintScore {
  score: number;
  hits: string[];
}

/** Score a text payload for injection patterns (0 = clean). */
export function scoreTaint(text: string): TaintScore {
  const hits: string[] = [];
  for (const p of INJECTION_PATTERNS) {
    if (p.re.test(text)) hits.push(p.name);
  }
  return { score: hits.length, hits };
}

/* ------------------------------------------------------------------------ */
/* Session taint state (per agent, 30 min decay)                             */
/* ------------------------------------------------------------------------ */

const TAINT_DECAY_MS = 30 * 60 * 1000;

interface TaintRecord {
  until: number;
  source: string;
  score: number;
  hits: string[];
}

const taintedAgents = new Map<string, TaintRecord>();

/** Mark an agent tainted (source upstream + score, for the audit + gate). */
export function markTainted(agentId: string, source: string, score: TaintScore): void {
  taintedAgents.set(agentId, {
    until: Date.now() + TAINT_DECAY_MS,
    source,
    score: score.score,
    hits: score.hits,
  });
}

/** The live taint record for an agent, or null when clean/decayed. */
export function taintOf(agentId: string): TaintRecord | null {
  const rec = taintedAgents.get(agentId);
  if (!rec) return null;
  if (rec.until <= Date.now()) {
    taintedAgents.delete(agentId);
    return null;
  }
  return rec;
}

/** Human clearing after an incident review (mirrors the revocation process). */
export function clearTaint(agentId: string): void {
  taintedAgents.delete(agentId);
}

/** Test helper: wipe all state. */
export function _resetTaintForTests(): void {
  taintedAgents.clear();
}

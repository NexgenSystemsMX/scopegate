/**
 * Billing metering (EPIC-10, H10.8).
 *
 *   GET /v1/billing/usage?teamId=[&month=YYYY-MM] → { activeAgents, period }
 *
 * Pricing unit per the product plan: an ACTIVE agent = an enrolled agent
 * with ≥1 audit event ingested in the calendar month (UTC). Installations,
 * enrolled-but-idle agents and revoked-but-idle agents are NOT billed; an
 * agent that was active and later revoked still counts for the months it was
 * active (usage is historical fact).
 *
 * `month` is `YYYY-MM` (default: current UTC month). The response period is
 * echoed back in the same format; `start`/`end` (ISO, end exclusive) are the
 * exact window used, so a Stripe-reporting job can reconcile ±0 against the
 * stored audit (EPIC-10 acceptance criterion).
 *
 * Stripe itself is intentionally NOT integrated in this dev-grade control
 * plane — this endpoint is the metering source of truth a billing job polls.
 */
import { badRequest, notFound } from "./model.js";
import type { Store } from "./store.js";

export interface BillingUsage {
  teamId: string;
  /** "YYYY-MM" (UTC). */
  period: string;
  /** Inclusive window start (ISO). */
  start: string;
  /** Exclusive window end (ISO). */
  end: string;
  activeAgents: number;
  /** Which agents were active (sorted) — for invoice reconciliation. */
  agents: string[];
}

const MONTH_RE = /^(\d{4})-(\d{2})$/;

export function billingUsage(store: Store, teamId: string, month?: string): BillingUsage {
  if (!store.getTeam(teamId)) throw notFound(`no such team: ${teamId}`);

  let year: number;
  let monthIdx: number; // 0-based
  if (month === undefined) {
    const now = new Date();
    year = now.getUTCFullYear();
    monthIdx = now.getUTCMonth();
  } else {
    const m = MONTH_RE.exec(month);
    if (!m) throw badRequest("month must be YYYY-MM (UTC)");
    year = Number(m[1]);
    monthIdx = Number(m[2]) - 1;
    if (monthIdx < 0 || monthIdx > 11) throw badRequest("month must be YYYY-MM (UTC)");
  }

  const start = new Date(Date.UTC(year, monthIdx, 1));
  const end = new Date(Date.UTC(year, monthIdx + 1, 1));
  const agents = store.activeAgentsInWindow(
    teamId,
    start.toISOString(),
    end.toISOString(),
  );

  return {
    teamId,
    period: `${year}-${String(monthIdx + 1).padStart(2, "0")}`,
    start: start.toISOString(),
    end: end.toISOString(),
    activeAgents: agents.length,
    agents,
  };
}

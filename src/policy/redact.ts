/**
 * PII redaction for proxied tool responses (EPIC-04 H-04.6).
 *
 * A policy rule may carry `redact: ["pii"]` (or individual categories). The
 * grant issued from that rule records the categories, and server.ts applies
 * `redactToolResult()` to the tool result AFTER proxy.call() returns — never
 * inside proxy.ts — so masking is a policy-enforcement concern, not a
 * transport concern.
 *
 * THIS IS A BEST-EFFORT HEURISTIC, NOT A DLP GUARANTEE. The matchers are
 * deliberately conservative (cards must pass Luhn, phones must look like
 * E.164) to keep false positives low; audit only ever receives COUNTS per
 * category, never the matched content (coherent with input hashing in the
 * audit log).
 *
 * Off by default: only rules with an explicit `redact` array mask anything.
 * Unknown categories are rejected at policy load time (fail-closed schema
 * validation in engine.ts).
 */

/** Categories a rule may list. "pii" expands to every concrete category. */
export const REDACT_CATEGORIES = [
  "pii",
  "email",
  "phone",
  "card",
  "aws_access_key",
] as const;

export type RedactCategory = (typeof REDACT_CATEGORIES)[number];

export interface RedactionOutcome {
  text: string;
  /** Replacements per concrete category (only categories that were active). */
  counts: Record<string, number>;
}

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
/** 13–19 digits, optionally separated by single spaces or dashes. */
const CARD_CANDIDATE_RE = /\b(?:\d[ -]?){13,19}\b/g;
/** Leading '+', digits with common separators; digit count validated 8..15. */
const PHONE_CANDIDATE_RE = /\+[1-9][\d(). -]{6,18}\d/g;
const AWS_KEY_ID_RE = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g;

/** Luhn checksum — the card matcher only masks candidates that pass it. */
function luhnValid(digits: string): boolean {
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

function mask(
  text: string,
  re: RegExp,
  tag: string,
  counts: Record<string, number>,
  validate?: (candidate: string) => boolean,
): string {
  return text.replace(re, (candidate) => {
    if (validate && !validate(candidate)) return candidate;
    counts[tag] = (counts[tag] ?? 0) + 1;
    return `[REDACTED:${tag}]`;
  });
}

function expandCategories(categories: string[]): RedactCategory[] {
  const active = new Set<RedactCategory>();
  for (const c of categories) {
    if (c === "pii") {
      active.add("email");
      active.add("phone");
      active.add("card");
      active.add("aws_access_key");
    } else if ((REDACT_CATEGORIES as readonly string[]).includes(c)) {
      active.add(c as RedactCategory);
    }
    // Unknown categories are rejected at policy load; ignore defensively here.
  }
  active.delete("pii");
  return [...active];
}

/**
 * Mask PII in a plain-text string. Returns the (possibly unchanged) text and
 * per-category replacement counts.
 */
export function redactText(text: string, categories: string[]): RedactionOutcome {
  const active = expandCategories(categories);
  const counts: Record<string, number> = {};
  let out = text;
  for (const cat of active) {
    switch (cat) {
      case "aws_access_key":
        out = mask(out, AWS_KEY_ID_RE, cat, counts);
        break;
      case "card":
        out = mask(out, CARD_CANDIDATE_RE, cat, counts, (c) => {
          const digits = c.replace(/\D/g, "");
          return digits.length >= 13 && digits.length <= 19 && luhnValid(digits);
        });
        break;
      case "phone":
        out = mask(out, PHONE_CANDIDATE_RE, cat, counts, (c) => {
          const digits = c.replace(/\D/g, "");
          return digits.length >= 8 && digits.length <= 15;
        });
        break;
      case "email":
        out = mask(out, EMAIL_RE, cat, counts);
        break;
    }
  }
  return { text: out, counts };
}

function mergeCounts(
  into: Record<string, number>,
  from: Record<string, number>,
): void {
  for (const [k, v] of Object.entries(from)) into[k] = (into[k] ?? 0) + v;
}

/**
 * Apply redaction to an MCP tool result: every `content` item of type "text"
 * is masked. Non-text items and non-object results pass through untouched.
 * The input object is NOT mutated; a shallow copy with masked text items is
 * returned (identical reference when nothing matched).
 */
export function redactToolResult(
  result: unknown,
  categories: string[],
): { result: unknown; counts: Record<string, number> } {
  const counts: Record<string, number> = {};
  if (
    !result ||
    typeof result !== "object" ||
    !Array.isArray((result as { content?: unknown }).content)
  ) {
    return { result, counts };
  }
  const content = (result as { content: unknown[] }).content.map((item) => {
    if (
      !item ||
      typeof item !== "object" ||
      (item as { type?: unknown }).type !== "text" ||
      typeof (item as { text?: unknown }).text !== "string"
    ) {
      return item;
    }
    const { text, counts: c } = redactText(
      (item as { text: string }).text,
      categories,
    );
    mergeCounts(counts, c);
    return { ...(item as Record<string, unknown>), text };
  });
  return { result: { ...(result as Record<string, unknown>), content }, counts };
}

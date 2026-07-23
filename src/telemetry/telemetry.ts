/**
 * ScopeGate telemetry — STRICTLY OPT-IN, anonymous, fail-silent.
 *
 * Purpose: measure the public-beta gate (installs, agent-driven onboarding,
 * time-to-first-tool-call). This is a security product, so the rules are:
 *
 *   1. OFF by default. Enabled only when the user explicitly sets
 *      SCOPEGATE_TELEMETRY=1 (or "true") or writes { "enabled": true } to
 *      <SCOPEGATE_HOME>/telemetry.json (scopegate init --telemetry writes it).
 *   2. Nothing identifying ever leaves the machine. No agentId, no paths, no
 *      upstream names/URLs, no tool names, no args, no inputs, no config
 *      hashes. Props are filtered through a per-event ALLOWLIST; unknown keys
 *      are dropped. Anything potentially identifying that must be correlated
 *      goes through sha256() first — and the only persistent identifier is a
 *      random anonymous install id generated locally.
 *   3. Fail-silent. Telemetry NEVER blocks, throws, or changes exit codes.
 *      Any error (network, fs, JSON) is swallowed; the gateway flow continues.
 *   4. One endpoint, configurable. Default TELEMETRY_DEFAULT_ENDPOINT below;
 *      override with SCOPEGATE_TELEMETRY_ENDPOINT or telemetry.json's
 *      "endpoint". Self-hosters can point it at their own collector.
 *
 * Wiring (done by the CLI, not by this module):
 *   - "install"         → after a successful global install / first run.
 *   - "init_completed"  → end of `scopegate init`, props: { harnesses: string[] }.
 *   - "first_tool_call" → first proxied tool call of a session,
 *                         props: { latency_ms: number } (ms since gateway start).
 *
 * Transparency: what is sent is documented in README.md ("Telemetry") and
 * docs-site/security-model.md. The payload is inspectable at
 * SCOPEGATE_LOG_LEVEL=debug.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** Public collector. Documented; self-hosters override via env/config. */
export const TELEMETRY_DEFAULT_ENDPOINT =
  "https://telemetry.scopegate.dev/v1/event";

/** Events the CLI wires today. Kept as a type, not enforced at runtime. */
export type TelemetryEventName =
  | "install"
  | "init_completed"
  | "first_tool_call"
  | (string & {});

/**
 * Per-event allowlist of property keys that are safe to send. Anything not
 * listed here is silently dropped — this is the guarantee that no secret,
 * arg, input, path or upstream name can leak through a future call site.
 */
const SAFE_PROPS: Record<string, ReadonlySet<string>> = {
  install: new Set(["version", "os", "arch", "node"]),
  init_completed: new Set(["version", "os", "arch", "node", "harnesses"]),
  first_tool_call: new Set(["version", "os", "arch", "node", "latency_ms"]),
};

/** Keys allowed for events without a dedicated allowlist. */
const GENERIC_SAFE_PROPS = new Set(["version", "os", "arch", "node"]);

const CONFIG_FILE = "telemetry.json";
const REQUEST_TIMEOUT_MS = 2_000;

interface TelemetryConfig {
  enabled?: boolean;
  /** Random anonymous id generated on first enable. Never derived from PII. */
  installId?: string;
  endpoint?: string;
}

/** sha256 hex — for anything identifying that must be correlated, never raw. */
export function sha256(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function scopegateDir(): string {
  return process.env.SCOPEGATE_HOME
    ? path.resolve(process.env.SCOPEGATE_HOME)
    : path.join(os.homedir(), ".scopegate");
}

function readConfig(): TelemetryConfig {
  try {
    const raw = fs.readFileSync(path.join(scopegateDir(), CONFIG_FILE), "utf8");
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === "object") return parsed as TelemetryConfig;
  } catch {
    // missing/corrupt config → telemetry stays off
  }
  return {};
}

function writeConfig(cfg: TelemetryConfig): void {
  try {
    fs.mkdirSync(scopegateDir(), { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      path.join(scopegateDir(), CONFIG_FILE),
      JSON.stringify(cfg, null, 2) + "\n",
      { mode: 0o600 },
    );
  } catch {
    // fail-silent: never break the CLI over telemetry persistence
  }
}

/** True only on explicit opt-in: env SCOPEGATE_TELEMETRY=1/true, or config. */
export function telemetryEnabled(): boolean {
  try {
    const env = (process.env.SCOPEGATE_TELEMETRY ?? "").toLowerCase();
    if (env === "1" || env === "true" || env === "yes") return true;
    return readConfig().enabled === true;
  } catch {
    return false;
  }
}

/**
 * Persist opt-in (called by an explicit user action, e.g. `init --telemetry`).
 * Generates the anonymous install id on first enable. Fail-silent.
 */
export function enableTelemetry(): void {
  try {
    const cfg = readConfig();
    cfg.enabled = true;
    cfg.installId ??= crypto.randomUUID();
    writeConfig(cfg);
  } catch {
    // fail-silent
  }
}

/** Disable telemetry and forget the anonymous install id. Fail-silent. */
export function disableTelemetry(): void {
  try {
    writeConfig({ enabled: false });
  } catch {
    // fail-silent
  }
}

function resolveEndpoint(cfg: TelemetryConfig): string {
  return (
    process.env.SCOPEGATE_TELEMETRY_ENDPOINT ??
    cfg.endpoint ??
    TELEMETRY_DEFAULT_ENDPOINT
  );
}

function filterProps(
  name: string,
  props: Record<string, unknown>,
): Record<string, unknown> {
  const allow = SAFE_PROPS[name] ?? GENERIC_SAFE_PROPS;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(props)) {
    if (!allow.has(key)) continue;
    const v = props[key];
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
      out[key] = v;
    } else if (Array.isArray(v) && v.every((x) => typeof x === "string")) {
      out[key] = v;
    }
  }
  return out;
}

function debugLog(msg: string): void {
  if ((process.env.SCOPEGATE_LOG_LEVEL ?? "").toLowerCase() === "debug") {
    console.error(`[scopegate:telemetry] ${msg}`);
  }
}

/**
 * Send one anonymous event. Fire-and-forget: returns immediately, never
 * throws, never rejects. Safe to call from anywhere in the CLI.
 *
 * Base props (os/arch/node) are added here; callers pass only event-specific
 * allowlisted props. Anything identifying must be pre-hashed with sha256().
 */
export function trackEvent(
  name: TelemetryEventName,
  props: Record<string, unknown> = {},
): void {
  try {
    if (!telemetryEnabled()) return;
    const cfg = readConfig();
    cfg.installId ??= crypto.randomUUID();
    writeConfig(cfg); // persist the id so events correlate to one install
    const body = JSON.stringify({
      event: name,
      installId: cfg.installId,
      timestamp: new Date().toISOString(),
      props: filterProps(name, {
        os: process.platform,
        arch: process.arch,
        node: process.version,
        ...props,
      }),
    });
    debugLog(`→ ${resolveEndpoint(cfg)} ${body}`);
    void fetch(resolveEndpoint(cfg), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    }).catch((e: unknown) => {
      debugLog(`dropped (network): ${e instanceof Error ? e.message : e}`);
    });
  } catch (e) {
    debugLog(`dropped (local): ${e instanceof Error ? e.message : e}`);
  }
}

/**
 * Registry loader (EPIC-12): resolves the registry source, fetches the signed
 * index + manifests, and verifies EVERYTHING fail-closed before any manifest
 * is turned into an UpstreamConfig.
 *
 * Source resolution order (no config-schema changes — env vars only):
 *   1. SCOPEGATE_REGISTRY_PATH — local directory (or file:// URL). No cache.
 *   2. SCOPEGATE_REGISTRY_URL  — http(s) base URL. Fetched files are cached
 *      in ~/.scopegate/registry-cache/; when the URL is unreachable the cache
 *      is used INSTEAD — still fully signature/hash verified before use.
 *   3. Default: the bundled registry/ directory shipped with the package
 *      (works from both src/ and dist/ layouts).
 *
 * Nothing in this module ever logs to stdout (the MCP channel) and nothing
 * here ever sees a secret VALUE — manifests carry ref names only.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";
import { SCOPEGATE_DIR, type UpstreamConfig } from "../config/config.js";
import {
  assertStdioCommandAllowed,
  sha256Hex,
  verifyIndexSignature,
  verifyManifestSha256,
} from "./verify.js";
import type { RegistryIndex, RegistryManifest } from "./types.js";

export const REGISTRY_CACHE_DIR = path.join(SCOPEGATE_DIR, "registry-cache");

type Source = { kind: "path"; dir: string } | { kind: "url"; base: string };

/** Where the registry is read from. Env vars are read per call (test-friendly). */
export function resolveRegistrySource(): Source {
  const p = process.env.SCOPEGATE_REGISTRY_PATH;
  if (p && p.trim()) {
    const v = p.trim();
    if (v.startsWith("file://")) return { kind: "path", dir: fileURLToPath(v) };
    return { kind: "path", dir: path.resolve(v) };
  }
  const u = process.env.SCOPEGATE_REGISTRY_URL;
  if (u && u.trim()) {
    const base = u.trim().replace(/\/+$/, "");
    if (!/^https?:\/\//.test(base)) {
      throw new Error(
        `SCOPEGATE_REGISTRY_URL must be an http(s) URL (got '${base}') — refusing to use it (fail-closed)`,
      );
    }
    return { kind: "url", base };
  }
  // Bundled default: <pkg>/registry from both src/registry and dist/registry.
  const here = path.dirname(fileURLToPath(import.meta.url));
  return { kind: "path", dir: path.resolve(here, "..", "..", "registry") };
}

/* ------------------------------------------------------------------------ */
/* Raw byte fetching (path source reads directly; URL source caches).        */
/* ------------------------------------------------------------------------ */

function readPathBytes(dir: string, file: string): Buffer {
  const full = path.join(dir, file);
  // Defense in depth: never let a registry file reference escape the root.
  if (path.dirname(full) !== dir) {
    throw new Error(`registry entry '${file}' escapes the registry root — rejected (fail-closed)`);
  }
  return fs.readFileSync(full);
}

function cachePath(file: string): string {
  return path.join(REGISTRY_CACHE_DIR, file);
}

function writeCache(file: string, bytes: Buffer): void {
  try {
    fs.mkdirSync(REGISTRY_CACHE_DIR, { recursive: true, mode: 0o700 });
    const tmp = cachePath(file) + ".tmp";
    fs.writeFileSync(tmp, bytes, { mode: 0o600 });
    fs.renameSync(tmp, cachePath(file));
  } catch {
    // Cache is best-effort: the network copy was already verified in memory.
  }
}

async function fetchUrlBytes(base: string, file: string): Promise<Buffer> {
  try {
    const res = await fetch(`${base}/${file}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const bytes = Buffer.from(await res.arrayBuffer());
    writeCache(file, bytes);
    return bytes;
  } catch (e) {
    // Offline fallback: serve the cached copy if we have one. It is NOT
    // trusted — the caller still verifies signature/hash before any use.
    let cached: Buffer | null = null;
    try {
      cached = fs.readFileSync(cachePath(file));
    } catch {
      cached = null;
    }
    if (cached) return cached;
    throw new Error(
      `cannot fetch registry file '${file}' from ${base} (${e instanceof Error ? e.message : String(e)}) and no local cache exists`,
    );
  }
}

async function readRegistryBytes(source: Source, file: string): Promise<Buffer> {
  return source.kind === "path" ? readPathBytes(source.dir, file) : fetchUrlBytes(source.base, file);
}

/* ------------------------------------------------------------------------ */
/* Verified loads                                                            */
/* ------------------------------------------------------------------------ */

/** Load, verify (signature fail-closed) and parse the registry index. */
export async function loadRegistryIndex(): Promise<RegistryIndex> {
  const source = resolveRegistrySource();
  let indexBytes: Buffer;
  let sigRaw: string;
  try {
    indexBytes = await readRegistryBytes(source, "index.json");
    sigRaw = (await readRegistryBytes(source, "index.sig")).toString("utf8");
  } catch (e) {
    throw new Error(
      `registry index unavailable: ${e instanceof Error ? e.message : String(e)} (fail-closed)`,
    );
  }
  verifyIndexSignature(indexBytes, sigRaw);
  let index: RegistryIndex;
  try {
    index = JSON.parse(indexBytes.toString("utf8")) as RegistryIndex;
  } catch {
    throw new Error("registry index is not valid JSON (fail-closed)");
  }
  if (
    !index ||
    typeof index !== "object" ||
    typeof index.version !== "number" ||
    typeof index.updatedAt !== "string" ||
    !index.manifests ||
    typeof index.manifests !== "object"
  ) {
    throw new Error("registry index has an unsupported or corrupt shape (fail-closed)");
  }
  for (const [name, entry] of Object.entries(index.manifests)) {
    if (!/^[a-z0-9][a-z0-9_-]*$/i.test(name)) {
      throw new Error(`registry index carries an invalid manifest name '${name}' (fail-closed)`);
    }
    if (
      !entry ||
      typeof entry.file !== "string" ||
      entry.file !== path.basename(entry.file) ||
      entry.file.includes("..") ||
      typeof entry.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/i.test(entry.sha256)
    ) {
      throw new Error(`registry index entry for '${name}' is malformed (fail-closed)`);
    }
  }
  return index;
}

const KNOWN_AUTH_TYPES = new Set(["none", "bearer", "env", "oauth2", "jwt", "github_app", "aws_sts", "huly", "google_sa"]);

function assertManifestShape(raw: unknown, expectedName: string): RegistryManifest {
  const m = raw as RegistryManifest;
  if (!m || typeof m !== "object") throw new Error("manifest is not a YAML mapping (fail-closed)");
  if (m.version !== "registry/v1") {
    throw new Error(`manifest '${expectedName}' has unsupported version '${String(m.version)}' (fail-closed)`);
  }
  if (m.name !== expectedName) {
    throw new Error(
      `manifest name '${String(m.name)}' does not match the index entry '${expectedName}' (fail-closed)`,
    );
  }
  if (typeof m.description !== "string" || !m.description) {
    throw new Error(`manifest '${expectedName}' is missing a description (fail-closed)`);
  }
  const t = m.transport;
  if (!t || (t.kind !== "http" && t.kind !== "stdio")) {
    throw new Error(`manifest '${expectedName}' has an invalid transport.kind (fail-closed)`);
  }
  if (t.kind === "http" && !/^https:\/\//.test(String(t.url))) {
    throw new Error(`manifest '${expectedName}' must use an https:// transport URL (fail-closed)`);
  }
  if (t.kind === "stdio") {
    if (typeof t.command !== "string" || !t.command) {
      throw new Error(`manifest '${expectedName}' is missing transport.command (fail-closed)`);
    }
    assertStdioCommandAllowed(t.command);
  }
  if (!m.auth || typeof m.auth !== "object" || !KNOWN_AUTH_TYPES.has(String(m.auth.type))) {
    throw new Error(`manifest '${expectedName}' has an unknown auth.type (fail-closed)`);
  }
  // M14.4: optional passthrough knobs, validated like scopegate.yaml.
  if (m.exposeTools !== undefined) {
    if (!Array.isArray(m.exposeTools) || m.exposeTools.some((t) => typeof t !== "string")) {
      throw new Error(`manifest '${expectedName}' has a malformed exposeTools (fail-closed)`);
    }
  }
  if (m.attestation !== undefined && typeof m.attestation !== "boolean") {
    throw new Error(`manifest '${expectedName}' has a malformed attestation (fail-closed)`);
  }
  if (m.pool !== undefined) {
    const p = m.pool as Record<string, unknown>;
    const numOk = (v: unknown) => v === undefined || (typeof v === "number" && Number.isFinite(v) && v >= 0);
    if (!p || typeof p !== "object" || !numOk(p.min) || !numOk(p.max) || !numOk(p.idleMs)) {
      throw new Error(`manifest '${expectedName}' has a malformed pool (fail-closed)`);
    }
  }
  for (const s of m.setup?.secrets ?? []) {
    if (typeof s?.ref !== "string" || typeof s?.hint !== "string") {
      throw new Error(`manifest '${expectedName}' has a malformed setup.secrets entry (fail-closed)`);
    }
  }
  return m;
}

/**
 * Load a manifest by registry name, verifying the signed index, the manifest
 * sha256 and the stdio allowlist. Throws (fail-closed) on ANY problem.
 */
export async function loadRegistryManifest(name: string): Promise<RegistryManifest> {
  if (!/^[a-z0-9][a-z0-9_-]*$/i.test(name)) {
    throw new Error(`invalid registry name '${name}' (fail-closed)`);
  }
  const index = await loadRegistryIndex();
  const entry = index.manifests[name];
  if (!entry) {
    throw new Error(
      `no manifest named '${name}' in the registry (available: ${Object.keys(index.manifests).sort().join(", ")})`,
    );
  }
  const source = resolveRegistrySource();
  const bytes = await readRegistryBytes(source, entry.file);
  verifyManifestSha256(bytes, entry.sha256, entry.file);
  let raw: unknown;
  try {
    raw = YAML.parse(bytes.toString("utf8"));
  } catch (e) {
    throw new Error(
      `manifest '${entry.file}' is not valid YAML (${e instanceof Error ? e.message : String(e)}) — fail-closed`,
    );
  }
  return assertManifestShape(raw, name);
}

/** Map a verified manifest 1:1 onto an UpstreamConfig. */
export function manifestToUpstream(manifest: RegistryManifest): UpstreamConfig {
  return {
    name: manifest.name,
    transport: manifest.transport,
    auth: manifest.auth,
    // M14.4: passthrough knobs (undefined keys are dropped by the config writer).
    ...(manifest.exposeTools ? { exposeTools: manifest.exposeTools } : {}),
    ...(manifest.attestation !== undefined ? { attestation: manifest.attestation } : {}),
    ...(manifest.pool ? { pool: manifest.pool } : {}),
  };
}

/** Test/diagnostic helper: hex sha256 of the current index.json on disk/source. */
export async function registryIndexFingerprint(): Promise<string> {
  const source = resolveRegistrySource();
  return sha256Hex(await readRegistryBytes(source, "index.json"));
}

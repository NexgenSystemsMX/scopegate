/**
 * M11.2: OpenAPI→MCP importer.
 *
 * Turns any REST API with an OpenAPI spec into a governed upstream in
 * minutes — no bridge to write. The gateway IS the MCP server of the API:
 * one tool per spec operation, executed as direct HTTP calls (there is no
 * intermediate MCP server and no spawned process).
 *
 *   - loadOpenApiSpec(specRef): https fetch or local file read (JSON or
 *     YAML), 5 MB size cap, on-disk cache under
 *     SCOPEGATE_HOME/openapi-cache/<sha256(specRef)>.json with a 24 h TTL —
 *     a failed fetch falls back to a fresh-enough cache entry.
 *   - toolsFromSpec(spec, upstreamName): one ToolDefinition per operation
 *     (operationId, or `<method>_<sanitized path>` when missing), with a
 *     JSON Schema built from path/query/header parameters + the
 *     application/json requestBody. `required` is honored.
 *   - callOperation(spec, op, args, { authHeaders, baseUrl }): builds the
 *     URL (path params substituted, query params appended), executes fetch
 *     with a 30 s timeout and returns { status, body }. HTTP errors come
 *     back as a structured { error: true, status, body } so the proxy can
 *     classify them in-band; network/timeout failures throw.
 *
 * Security invariants:
 *   - SSRF: the final baseUrl must be https (http only for
 *     localhost/127.0.0.1/::1) and carries no embedded credentials.
 *   - Redirects are followed ONLY within the same origin (max 3 hops);
 *     a redirect to another host is returned as the final response.
 *   - Spec size cap: 5 MB (fetched and local).
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { SCOPEGATE_DIR } from "../config/config.js";

/** Hard cap on the spec document, fetched or read from disk. */
export const SPEC_SIZE_CAP_BYTES = 5 * 1024 * 1024;
/** Spec cache freshness window; a failed fetch falls back within it. */
export const SPEC_CACHE_TTL_MS = 24 * 3600 * 1000;
/** Per-call HTTP timeout. */
export const CALL_TIMEOUT_MS = 30_000;
/** Spec fetch timeout (races the proxy's connect timeout upstream). */
export const SPEC_FETCH_TIMEOUT_MS = 30_000;
/** Redirects are followed only same-origin, at most this many hops. */
const MAX_REDIRECTS = 3;

/* ------------------------------------------------------------------------ */
/* Loose OpenAPI 3.x typing (forward-compatible: unknown keys pass through)  */
/* ------------------------------------------------------------------------ */

export type JsonSchema = Record<string, unknown>;

export interface OpenApiParameter {
  name: string;
  in: "path" | "query" | "header" | "cookie" | string;
  required?: boolean;
  description?: string;
  schema?: JsonSchema;
}

export interface OpenApiRequestBody {
  required?: boolean;
  content?: Record<string, { schema?: JsonSchema }>;
}

export interface OpenApiOperationObject {
  operationId?: string;
  summary?: string;
  description?: string;
  deprecated?: boolean;
  parameters?: unknown[];
  requestBody?: unknown;
}

export interface OpenApiSpec {
  openapi?: string;
  swagger?: string;
  info?: { title?: string; description?: string; version?: string };
  servers?: {
    url: string;
    description?: string;
    variables?: Record<string, { default?: string; enum?: string[] }>;
  }[];
  paths?: Record<string, Record<string, unknown>>;
  components?: Record<string, unknown>;
}

/** MCP-facing tool definition generated from one spec operation. */
export interface ToolDefinition {
  name: string;
  description?: string;
  inputSchema: JsonSchema;
}

/** One operation resolved for execution (parameters merged, refs resolved). */
export interface ResolvedOperation {
  /** Sanitized tool name (`<upstream>__<name>` on the MCP surface). */
  name: string;
  method: string; // uppercase
  path: string;
  description?: string;
  /** Path-item + operation parameters, merged (operation wins), refs resolved. */
  parameters: OpenApiParameter[];
  /** application/json (or first available) request body, if any. */
  requestBody?: { required: boolean; contentType: string; schema?: JsonSchema };
  /** Args property carrying the request body ("body", or "requestBody" on collision). */
  bodyProp: string;
  inputSchema: JsonSchema;
}

export interface OpenApiCallResult {
  status: number;
  /** Parsed JSON body, or raw text when the response is not JSON. */
  body: unknown;
  /** Set on HTTP errors (status >= 400) — classified in-band by the proxy. */
  error?: true;
}

/* ------------------------------------------------------------------------ */
/* URL safety (SSRF)                                                         */
/* ------------------------------------------------------------------------ */

const LOCAL_HOSTNAMES = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/**
 * Fail-closed URL validation: https always; http only for loopback hosts;
 * embedded credentials are refused (they would live in the config file).
 */
export function assertSafeHttpUrl(raw: string, what: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(
      `openapi: ${what} '${raw}' is not an absolute URL ` +
        `(set transport.baseUrl when the spec's servers[0].url is relative)`,
    );
  }
  if (u.username || u.password) {
    throw new Error(`openapi: ${what} must not embed credentials ('${u.origin}')`);
  }
  if (u.protocol === "https:") return u;
  if (u.protocol === "http:" && LOCAL_HOSTNAMES.has(u.hostname)) return u;
  throw new Error(
    `openapi: refusing insecure ${what} '${raw}' — https is required ` +
      `(http is allowed only for localhost/127.0.0.1)`,
  );
}

/* ------------------------------------------------------------------------ */
/* Spec loading + disk cache                                                 */
/* ------------------------------------------------------------------------ */

function isHttpUrl(ref: string): boolean {
  return /^https?:\/\//i.test(ref);
}

function cacheFileFor(specRef: string): string {
  const hash = crypto.createHash("sha256").update(specRef).digest("hex").slice(0, 32);
  return path.join(SCOPEGATE_DIR, "openapi-cache", `${hash}.json`);
}

function writeSpecCache(specRef: string, spec: OpenApiSpec): void {
  try {
    const file = cacheFileFor(specRef);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const tmp = file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify({ fetchedAt: Date.now(), spec }), { mode: 0o600 });
    fs.renameSync(tmp, file);
  } catch {
    /* a cache that cannot be written never breaks a load */
  }
}

function readSpecCache(specRef: string): OpenApiSpec | null {
  try {
    const raw = JSON.parse(fs.readFileSync(cacheFileFor(specRef), "utf8")) as {
      fetchedAt?: number;
      spec?: OpenApiSpec;
    };
    if (!raw.spec || typeof raw.fetchedAt !== "number") return null;
    if (Date.now() - raw.fetchedAt > SPEC_CACHE_TTL_MS) return null;
    return raw.spec;
  } catch {
    return null;
  }
}

function parseSpecText(text: string, source: string): OpenApiSpec {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    try {
      parsed = YAML.parse(text);
    } catch (e) {
      throw new Error(
        `openapi: spec at '${source}' is neither valid JSON nor YAML (${(e as Error).message})`,
      );
    }
  }
  const spec = parsed as OpenApiSpec | null;
  if (!spec || typeof spec !== "object" || typeof spec.paths !== "object" || !spec.paths) {
    throw new Error(
      `openapi: spec at '${source}' has no 'paths' object — not an OpenAPI document`,
    );
  }
  return spec;
}

/**
 * GET a text document with a byte cap, following redirects ONLY within the
 * same origin (max 3 hops). Throws on network errors, timeouts and
 * non-2xx/3xx terminal statuses.
 */
async function fetchTextSafe(url: string, timeoutMs: number, capBytes: number): Promise<string> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    let current = url;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      let res: Response;
      try {
        res = await fetch(current, {
          signal: ctrl.signal,
          redirect: "manual",
          headers: { accept: "application/json, application/yaml, text/yaml, text/plain, */*" },
        });
      } catch (e) {
        if ((e as Error).name === "AbortError") {
          throw new Error(`openapi: fetch of '${url}' timed out after ${timeoutMs} ms`);
        }
        throw e;
      }
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get("location");
        if (!location) throw new Error(`openapi: redirect without Location from '${current}'`);
        const next = new URL(location, current);
        const prev = new URL(current);
        if (next.origin !== prev.origin) {
          throw new Error(
            `openapi: refusing cross-origin redirect ${prev.host} → ${next.host} (SSRF guard)`,
          );
        }
        assertSafeHttpUrl(next.toString(), "redirect target");
        current = next.toString();
        continue;
      }
      if (!res.ok) {
        throw new Error(`openapi: spec fetch of '${current}' failed with HTTP ${res.status}`);
      }
      const len = Number(res.headers.get("content-length") ?? 0);
      if (len > capBytes) {
        throw new Error(`openapi: spec at '${current}' exceeds the ${capBytes}-byte cap`);
      }
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.byteLength > capBytes) {
        throw new Error(`openapi: spec at '${current}' exceeds the ${capBytes}-byte cap`);
      }
      return buf.toString("utf8");
    }
    throw new Error(`openapi: too many redirects fetching '${url}' (>${MAX_REDIRECTS})`);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Load an OpenAPI spec from an https URL or a local file path (JSON or
 * YAML). Remote specs are cached on disk (24 h TTL); when the fetch fails
 * and a fresh-enough cache entry exists, the cache is used.
 */
export async function loadOpenApiSpec(specRef: string): Promise<OpenApiSpec> {
  if (!isHttpUrl(specRef)) {
    const p = path.resolve(specRef);
    const st = fs.statSync(p); // ENOENT → clear throw below
    if (st.size > SPEC_SIZE_CAP_BYTES) {
      throw new Error(
        `openapi: spec file '${p}' exceeds the ${SPEC_SIZE_CAP_BYTES}-byte cap`,
      );
    }
    return parseSpecText(fs.readFileSync(p, "utf8"), p);
  }
  assertSafeHttpUrl(specRef, "spec url");
  try {
    const text = await fetchTextSafe(specRef, SPEC_FETCH_TIMEOUT_MS, SPEC_SIZE_CAP_BYTES);
    const spec = parseSpecText(text, specRef);
    writeSpecCache(specRef, spec);
    return spec;
  } catch (e) {
    const cached = readSpecCache(specRef);
    if (cached) return cached;
    throw e;
  }
}

/**
 * Effective base URL: transport.baseUrl wins over the spec's servers[0].url
 * (server `{variables}` substituted with their defaults). Always validated
 * by the SSRF guard.
 */
export function resolveBaseUrl(spec: OpenApiSpec, override?: string): string {
  const raw = override ?? spec.servers?.[0]?.url;
  if (!raw) {
    throw new Error(
      `openapi: no servers[0].url in the spec and no transport.baseUrl override — ` +
        `set transport.baseUrl in scopegate.yaml`,
    );
  }
  const variables = override ? undefined : spec.servers?.[0]?.variables;
  const resolved = raw.replace(/\{([^}]+)\}/g, (match, name: string) => {
    const def = variables?.[name]?.default;
    if (def === undefined) {
      throw new Error(
        `openapi: server variable '${name}' has no default — set transport.baseUrl explicitly`,
      );
    }
    return def;
  });
  return assertSafeHttpUrl(resolved, "baseUrl").toString();
}

/* ------------------------------------------------------------------------ */
/* Local $ref resolution (#/components/...)                                  */
/* ------------------------------------------------------------------------ */

function unescapeJsonPointer(part: string): string {
  return decodeURIComponent(part).replace(/~1/g, "/").replace(/~0/g, "~");
}

/** Follow local `#/...` refs (chains up to 5 deep). External refs pass through. */
function resolveRef<T>(spec: OpenApiSpec, node: T, depth = 0): T {
  if (depth > 5 || node === null || typeof node !== "object") return node;
  const ref = (node as Record<string, unknown>).$ref;
  if (typeof ref !== "string" || !ref.startsWith("#/")) return node;
  let cur: unknown = spec;
  for (const part of ref.slice(2).split("/").map(unescapeJsonPointer)) {
    if (cur === null || typeof cur !== "object") return node;
    cur = (cur as Record<string, unknown>)[part];
  }
  if (cur === undefined) return node;
  return resolveRef(spec, cur as T, depth + 1);
}

/* ------------------------------------------------------------------------ */
/* Tool generation                                                           */
/* ------------------------------------------------------------------------ */

const HTTP_METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];

/** Tool names are MCP-safe: [a-zA-Z0-9_-], runs collapsed, edges trimmed. */
function sanitizeToolName(raw: string): string {
  return raw.replace(/[^a-zA-Z0-9_-]+/g, "_").replace(/^_+|_+$/g, "");
}

function deriveOperationName(method: string, pathTemplate: string): string {
  // Sanitize the path separately so `get` + "/search" yields "get_search"
  // (no double underscore at the join).
  const name = sanitizeToolName(pathTemplate);
  return name ? `${method.toLowerCase()}_${name}` : `${method.toLowerCase()}_root`;
}

/**
 * Generate one ToolDefinition per spec operation, plus the execution view
 * (ResolvedOperation) keyed by the same sanitized name. Operations without
 * an operationId get `<method>_<sanitized path>`; name collisions are
 * suffixed `_2`, `_3`, …
 */
export function toolsFromSpec(
  spec: OpenApiSpec,
  upstreamName: string,
): { tools: ToolDefinition[]; operations: Map<string, ResolvedOperation> } {
  const tools: ToolDefinition[] = [];
  const operations = new Map<string, ResolvedOperation>();
  const usedNames = new Set<string>();

  for (const [pathTemplate, pathItem] of Object.entries(spec.paths ?? {})) {
    if (!pathItem || typeof pathItem !== "object") continue;
    const pathParams = Array.isArray((pathItem as { parameters?: unknown }).parameters)
      ? ((pathItem as { parameters: unknown[] }).parameters ?? [])
      : [];
    for (const method of HTTP_METHODS) {
      const rawOp = pathItem[method];
      if (!rawOp || typeof rawOp !== "object") continue;
      const op = resolveRef(spec, rawOp) as OpenApiOperationObject;

      const base = op.operationId
        ? sanitizeToolName(op.operationId)
        : deriveOperationName(method, pathTemplate);
      let name = base || deriveOperationName(method, pathTemplate);
      for (let i = 2; usedNames.has(name); i++) name = `${base}_${i}`;
      usedNames.add(name);

      const description =
        [op.summary, op.description].filter((s) => typeof s === "string" && s.length > 0).join(" — ") ||
        `${method.toUpperCase()} ${pathTemplate}`;

      // Parameters: path-item level first, operation level overrides on (in, name).
      const merged = new Map<string, OpenApiParameter>();
      for (const rawParam of [...pathParams, ...(Array.isArray(op.parameters) ? op.parameters : [])]) {
        const p = resolveRef(spec, rawParam) as OpenApiParameter;
        if (!p || typeof p.name !== "string" || typeof p.in !== "string") continue;
        merged.set(`${p.in}:${p.name}`, p);
      }
      const parameters = [...merged.values()].filter((p) => p.in !== "cookie");

      // Request body: application/json preferred, first content entry otherwise.
      let requestBody: ResolvedOperation["requestBody"];
      const rawBody = resolveRef(spec, op.requestBody) as OpenApiRequestBody | undefined;
      if (rawBody && typeof rawBody === "object" && rawBody.content) {
        const entries = Object.entries(rawBody.content);
        if (entries.length > 0) {
          const [contentType, media] =
            entries.find(([ct]) => ct.toLowerCase().includes("application/json")) ?? entries[0];
          requestBody = {
            required: rawBody.required === true,
            contentType,
            schema: media?.schema ? (resolveRef(spec, media.schema) as JsonSchema) : undefined,
          };
        }
      }

      const bodyProp = parameters.some((p) => p.name === "body") ? "requestBody" : "body";

      // JSON Schema: parameters as properties + the body property.
      const properties: Record<string, JsonSchema> = {};
      const required: string[] = [];
      for (const p of parameters) {
        const schema: JsonSchema = p.schema
          ? { ...(resolveRef(spec, p.schema) as JsonSchema) }
          : { type: "string" };
        if (p.description && schema.description === undefined) schema.description = p.description;
        schema["x-scopegate-in"] = p.in;
        properties[p.name] = schema;
        if (p.in === "path" || p.required === true) required.push(p.name);
      }
      if (requestBody) {
        properties[bodyProp] = {
          ...(requestBody.schema ?? {}),
          description:
            (requestBody.schema?.description as string | undefined) ??
            `Request body (${requestBody.contentType})`,
        };
        if (requestBody.required) required.push(bodyProp);
      }
      const inputSchema: JsonSchema = {
        type: "object",
        properties,
        additionalProperties: false,
      };
      if (required.length > 0) inputSchema.required = required;

      tools.push({ name, description, inputSchema });
      operations.set(name, {
        name,
        method: method.toUpperCase(),
        path: pathTemplate,
        description,
        parameters,
        requestBody,
        bodyProp,
        inputSchema,
      });
    }
  }

  if (tools.length === 0) {
    throw new Error(`openapi: spec for upstream '${upstreamName}' declares no operations`);
  }
  return { tools, operations };
}

/* ------------------------------------------------------------------------ */
/* Operation execution                                                       */
/* ------------------------------------------------------------------------ */

function stringifyParam(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/**
 * Execute one operation as a direct HTTP call. Returns { status, body };
 * HTTP errors (status >= 400) come back as { error: true, status, body }.
 * Network failures and timeouts THROW (the proxy's bounded retry and
 * circuit breaker own those).
 */
export async function callOperation(
  spec: OpenApiSpec,
  op: ResolvedOperation,
  args: Record<string, unknown>,
  opts: { authHeaders?: Record<string, string>; baseUrl?: string },
): Promise<OpenApiCallResult> {
  void spec; // the operation is already fully resolved; spec kept for signature stability
  const base = assertSafeHttpUrl(
    opts.baseUrl ?? "",
    `baseUrl for operation '${op.name}'`,
  );

  // Path substitution (path params are always required by the spec).
  let pathname = op.path;
  const query = new URLSearchParams();
  const headers: Record<string, string> = {};
  for (const p of op.parameters) {
    const value = args[p.name];
    if (value === undefined) {
      if (p.in === "path" || p.required === true) {
        throw new Error(`openapi: missing required ${p.in} parameter '${p.name}' for '${op.name}'`);
      }
      continue;
    }
    if (p.in === "path") {
      pathname = pathname.replace(
        new RegExp(`\\{${p.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\}`, "g"),
        encodeURIComponent(stringifyParam(value)),
      );
    } else if (p.in === "query") {
      if (Array.isArray(value)) {
        for (const item of value) query.append(p.name, stringifyParam(item));
      } else {
        query.append(p.name, stringifyParam(value));
      }
    } else if (p.in === "header") {
      headers[p.name] = stringifyParam(value);
    }
  }
  const leftover = pathname.match(/\{[^}]+\}/);
  if (leftover) {
    throw new Error(
      `openapi: path parameter ${leftover[0]} of '${op.name}' was not provided ` +
        `(declared parameters: ${op.parameters.map((p) => p.name).join(", ") || "none"})`,
    );
  }

  // Credentials always win over operation-level header parameters.
  Object.assign(headers, opts.authHeaders ?? {});

  // Body.
  let body: string | undefined;
  if (op.requestBody) {
    const value = args[op.bodyProp];
    if (value === undefined) {
      if (op.requestBody.required) {
        throw new Error(`openapi: missing required request body ('${op.bodyProp}') for '${op.name}'`);
      }
    } else {
      const isJson = op.requestBody.contentType.toLowerCase().includes("json");
      headers["content-type"] = op.requestBody.contentType;
      body = isJson ? JSON.stringify(value) : stringifyParam(value);
    }
  }

  const url = new URL(pathname.replace(/^\//, ""), base.origin + (base.pathname.replace(/\/?$/, "/")));
  const qs = query.toString();
  if (qs) url.search = qs;

  // Execute with manual redirects (same-origin only) and a hard timeout that
  // covers the whole exchange (all hops + body read).
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), CALL_TIMEOUT_MS);
  let finalRes: Response | null = null;
  try {
    let current = url.toString();
    let method = op.method;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      let res: Response;
      try {
        res = await fetch(current, {
          method,
          headers,
          body: method === "GET" || method === "HEAD" ? undefined : body,
          signal: ctrl.signal,
          redirect: "manual",
        });
      } catch (e) {
        if ((e as Error).name === "AbortError") {
          throw new Error(`openapi: call '${op.name}' timed out after ${CALL_TIMEOUT_MS} ms`);
        }
        throw e;
      }
      if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
        const next = new URL(res.headers.get("location") as string, current);
        if (next.origin !== new URL(current).origin) {
          // Cross-host redirect: never followed — the 3xx IS the final answer.
          finalRes = res;
          break;
        }
        assertSafeHttpUrl(next.toString(), "redirect target");
        // 301/302/303 downgrade to GET; 307/308 keep method+body.
        if (res.status === 301 || res.status === 302 || res.status === 303) {
          method = "GET";
          body = undefined;
          delete headers["content-type"];
        }
        current = next.toString();
        continue;
      }
      finalRes = res;
      break;
    }
    if (!finalRes) {
      throw new Error(`openapi: call '${op.name}' exceeded ${MAX_REDIRECTS} redirects`);
    }

    const text = await finalRes.text();
    let parsed: unknown = text;
    const ct = finalRes.headers.get("content-type") ?? "";
    if (ct.toLowerCase().includes("json") && text.length > 0) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = text;
      }
    }
    if (finalRes.status >= 400) {
      return { error: true, status: finalRes.status, body: parsed };
    }
    return { status: finalRes.status, body: parsed };
  } finally {
    clearTimeout(timer);
  }
}

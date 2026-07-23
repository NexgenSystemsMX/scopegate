/**
 * EPIC-12: attestation (EdDSA JWT issuance, JWKS publication, standalone
 * verification) and the proxy's warm pool + header injection. Isolated from
 * the real HOME via tests/helpers.ts (SCOPEGATE_HOME + mkdtemp); src modules
 * are imported dynamically after useTempHome().
 */
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { cleanupTempHome, useTempHome } from "./helpers.js";
import { verifyAttestation } from "../src/attestation/verify.js";
import type { UpstreamConfig } from "../src/config/config.js";
import type { UpstreamProxy } from "../src/gateway/proxy.js";

let home: string;
let errSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  home = useTempHome();
  process.env.SCOPEGATE_VAULT_MODE = "local";
  process.env.SCOPEGATE_MASTER_KEY_BACKEND = "file";
  // The proxy logs to stderr by design; keep test output clean.
  errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  errSpy.mockRestore();
  delete process.env.SCOPEGATE_VAULT_MODE;
  delete process.env.SCOPEGATE_MASTER_KEY_BACKEND;
  cleanupTempHome(home);
});

const decode = (part: string) =>
  JSON.parse(Buffer.from(part, "base64url").toString("utf8"));

/* ------------------------------------------------------------------------ */
/* Attestation issuance / JWKS / verification                                */
/* ------------------------------------------------------------------------ */

describe("attestation issuance (EPIC-12)", () => {
  it("roundtrips: issue → verify against the published JWKS", async () => {
    const { createIdentity } = await import("../src/audit/identity.js");
    const id = createIdentity();
    const { issueAttestation } = await import("../src/attestation/attest.js");
    const att = issueAttestation("agent-test");

    // Issuing (re)published ~/.scopegate/jwks.json.
    const { JWKS_PATH } = await import("../src/attestation/jwks.js");
    const jwks = JSON.parse(fs.readFileSync(JWKS_PATH, "utf8"));
    expect(verifyAttestation(att.token, jwks)).toEqual({
      agentId: "agent-test",
      fingerprint: id.fingerprint,
    });

    // Frozen wire contract: header + claims shape.
    const [h, p] = att.token.split(".");
    expect(decode(h)).toMatchObject({ alg: "EdDSA", typ: "JWT", kid: id.fingerprint });
    const payload = decode(p);
    expect(payload.iss).toBe("agent-test");
    expect(payload.sub).toBe(id.fingerprint);
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(60);
    expect(typeof payload.jti).toBe("string");
  });

  it("rejects an expired token (fail-closed, no leeway)", async () => {
    const { createIdentity } = await import("../src/audit/identity.js");
    createIdentity();
    const { issueAttestation } = await import("../src/attestation/attest.js");
    const t0 = Date.now() - 120_000;
    const att = issueAttestation("agent-test", t0);
    const { publishJwks } = await import("../src/attestation/jwks.js");
    const jwks = publishJwks();
    expect(verifyAttestation(att.token, jwks, t0 + 30_000)).not.toBeNull();
    expect(verifyAttestation(att.token, jwks, t0 + 61_000)).toBeNull();
  });

  it("rejects an unknown kid, a tampered signature and a foreign JWKS", async () => {
    const { createIdentity } = await import("../src/audit/identity.js");
    createIdentity();
    const { issueAttestation } = await import("../src/attestation/attest.js");
    const att = issueAttestation("agent-test");
    const { publishJwks } = await import("../src/attestation/jwks.js");
    const jwks = publishJwks();

    const wrongKid = structuredClone(jwks);
    wrongKid.keys[0].kid = "sha256:unknown";
    expect(verifyAttestation(att.token, wrongKid)).toBeNull();

    const parts = att.token.split(".");
    const tampered = `${parts[0]}.${parts[1]}.${parts[2].slice(0, -2)}xx`;
    expect(verifyAttestation(tampered, jwks)).toBeNull();

    // A JWKS from a DIFFERENT keypair (even reusing the same kid) fails.
    const other = crypto.generateKeyPairSync("ed25519");
    const otherX = (other.publicKey.export({ format: "jwk" }) as { x?: string }).x!;
    const foreign = { keys: [{ ...jwks.keys[0], x: otherX }] };
    expect(verifyAttestation(att.token, foreign)).toBeNull();
  });

  it("caches the signature for ~45s and re-signs afterwards", async () => {
    const { createIdentity } = await import("../src/audit/identity.js");
    createIdentity();
    const { getAttestation } = await import("../src/attestation/attest.js");
    const t0 = Date.now();
    const a = getAttestation("agent-test", t0);
    expect(getAttestation("agent-test", t0 + 5_000).token).toBe(a.token);
    expect(getAttestation("agent-test", t0 + 44_999).token).toBe(a.token);
    const b = getAttestation("agent-test", t0 + 45_001);
    expect(b.token).not.toBe(a.token);
    const { publishJwks } = await import("../src/attestation/jwks.js");
    expect(verifyAttestation(b.token, publishJwks())).not.toBeNull();
  });

  it("rotates naturally by kid: a new identity invalidates the cache", async () => {
    const { createIdentity, IDENTITY_PATH, fingerprintOf } = await import(
      "../src/audit/identity.js"
    );
    const id1 = createIdentity();
    const { getAttestation } = await import("../src/attestation/attest.js");
    const t0 = Date.now();
    const a = getAttestation("agent-test", t0);
    expect(a.kid).toBe(id1.fingerprint);

    // Simulate `scopegate identity rotate`: fresh keypair on disk, and drop
    // the module-level identity/attestation caches.
    const kp = crypto.generateKeyPairSync("ed25519");
    const pubPem = kp.publicKey.export({ type: "spki", format: "pem" }).toString();
    fs.writeFileSync(
      IDENTITY_PATH,
      JSON.stringify({
        v: 1,
        algo: "ed25519",
        publicKey: pubPem,
        privateKey: kp.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
        fingerprint: fingerprintOf(pubPem),
        createdAt: new Date().toISOString(),
      }),
    );
    vi.resetModules();

    const mod2 = await import("../src/attestation/attest.js");
    const b = mod2.getAttestation("agent-test", t0 + 1_000); // within the old cache window
    expect(b.kid).not.toBe(id1.fingerprint);
    expect(b.token).not.toBe(a.token);
  });
});

describe("JWKS publication", () => {
  it("publishes the identity public key as an OKP/Ed25519 JWK keyed by kid", async () => {
    const { createIdentity } = await import("../src/audit/identity.js");
    const id = createIdentity();
    const { publishJwks, JWKS_PATH } = await import("../src/attestation/jwks.js");
    const jwks = publishJwks();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({
      kty: "OKP",
      crv: "Ed25519",
      kid: id.fingerprint,
      use: "sig",
      alg: "EdDSA",
    });
    expect(Buffer.from(jwks.keys[0].x, "base64url")).toHaveLength(32);
    const raw = fs.readFileSync(JWKS_PATH, "utf8");
    expect(JSON.parse(raw).keys[0].kid).toBe(id.fingerprint);
    expect(raw).not.toContain("PRIVATE KEY");
  });
});

/* ------------------------------------------------------------------------ */
/* Proxy: header injection + warm pool                                       */
/* ------------------------------------------------------------------------ */

/** Minimal stateless HTTP MCP upstream with a failure switch for self-heal tests. */
interface TestUpstream {
  url: string;
  seenHeaders: http.IncomingHttpHeaders[];
  failMode: boolean;
  close: () => Promise<void>;
}

async function startTestUpstream(): Promise<TestUpstream> {
  const state: TestUpstream = {
    url: "",
    seenHeaders: [],
    failMode: false,
    close: async () => {},
  };
  const createMcpServer = () => {
    const server = new Server({ name: "testup", version: "1.0.0" }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        { name: "ping", description: "ping", inputSchema: { type: "object", properties: {} } },
      ],
    }));
    server.setRequestHandler(CallToolRequestSchema, async (req) => {
      if (req.params.name !== "ping") {
        return { content: [{ type: "text", text: `unknown tool ${req.params.name}` }], isError: true };
      }
      return { content: [{ type: "text", text: "pong" }] };
    });
    return server;
  };
  const httpServer = http.createServer((req, res) => {
    state.seenHeaders.push(req.headers);
    if (state.failMode) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "upstream boom" }));
      return;
    }
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      let body;
      try {
        body = raw ? JSON.parse(raw) : undefined;
      } catch {
        body = undefined;
      }
      const server = createMcpServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => {
        transport.close().catch(() => {});
        server.close().catch(() => {});
      });
      server
        .connect(transport)
        .then(() => transport.handleRequest(req, res, body))
        .catch(() => {
          if (!res.headersSent) res.writeHead(500).end();
        });
    });
  });
  await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  state.url = `http://127.0.0.1:${(httpServer.address() as AddressInfo).port}/mcp`;
  state.close = () =>
    new Promise<void>((resolve) => {
      // Don't wait for idle keep-alive sockets to drain on their own.
      httpServer.closeAllConnections();
      httpServer.close(() => resolve());
    });
  return state;
}

describe("proxy: attestation injection + warm pool (EPIC-12)", () => {
  let upstream: TestUpstream;
  let proxy: UpstreamProxy | null;

  beforeEach(async () => {
    upstream = await startTestUpstream();
    proxy = null;
  });

  afterEach(async () => {
    await proxy?.closeAll().catch(() => {});
    await upstream.close();
  });

  async function makeProxy(upstreams: UpstreamConfig[]): Promise<UpstreamProxy> {
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const { createIdentity } = await import("../src/audit/identity.js");
    createIdentity();
    proxy = new UpstreamProxy(upstreams, Vault.open(), { agentId: "agent-test" });
    return proxy;
  }

  it("injects X-ScopeGate-Attestation NEXT TO the credential by default; attestation:false opts out", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    Vault.open().set("tok_ref", "sekret-value");
    const p = await makeProxy([
      {
        name: "att",
        transport: { kind: "http", url: upstream.url },
        auth: { type: "bearer", secretRef: "tok_ref" },
      },
      {
        name: "plain",
        transport: { kind: "http", url: upstream.url },
        auth: { type: "none" },
        attestation: false,
      },
    ]);
    const status = await p.connectAll();
    expect(status.att.ok).toBe(true);
    expect(status.plain.ok).toBe(true);

    const withAtt = upstream.seenHeaders.filter((h) => h["x-scopegate-attestation"]);
    const withoutAtt = upstream.seenHeaders.filter((h) => !h["x-scopegate-attestation"]);
    expect(withAtt.length).toBeGreaterThan(0);
    expect(withoutAtt.length).toBeGreaterThan(0);

    // The injected JWT verifies against the temp-home JWKS as agent-test …
    const { JWKS_PATH } = await import("../src/attestation/jwks.js");
    const jwks = JSON.parse(fs.readFileSync(JWKS_PATH, "utf8"));
    const token = String(withAtt[0]["x-scopegate-attestation"]);
    expect(verifyAttestation(token, jwks)?.agentId).toBe("agent-test");
    // … and rides ALONG the credential, never replacing it.
    const attested = withAtt.find((h) => h["authorization"]);
    expect(attested?.["authorization"]).toBe("Bearer sekret-value");
    expect(String(attested?.["x-scopegate-attestation"])).not.toContain("sekret-value");
  });

  it("warm pool respects min, reuses warm connections and caps at max", async () => {
    const p = await makeProxy([
      {
        name: "pooled",
        transport: { kind: "http", url: upstream.url },
        auth: { type: "none" },
        pool: { min: 1, max: 2 },
      },
    ]);
    const status = await p.connectAll();
    expect(status.pooled.ok).toBe(true);

    // min=1 pre-established at startup (diagnose probe does not count as a hit).
    let diag = await p.diagnose();
    expect(diag.pooled.ok).toBe(true);
    expect(diag.pooled.pool).toEqual({ size: 1, inUse: 0, hits: 0 });

    // A call is served by the warm connection (hit), no new connect needed.
    await p.call("pooled__ping", {});
    diag = await p.diagnose();
    expect(diag.pooled.pool).toEqual({ size: 1, inUse: 0, hits: 1 });

    // Two concurrent calls: the second misses into a new connection (≤ max).
    await Promise.all([p.call("pooled__ping", {}), p.call("pooled__ping", {})]);
    diag = await p.diagnose();
    expect(diag.pooled.pool!.size).toBeLessThanOrEqual(2);
    expect(diag.pooled.pool!.size).toBeGreaterThanOrEqual(1);
    expect(diag.pooled.pool!.inUse).toBe(0);
  });

  it("reaps idle connections above min after idleTimeoutMs", async () => {
    const p = await makeProxy([
      {
        name: "pooled",
        transport: { kind: "http", url: upstream.url },
        auth: { type: "none" },
        pool: { min: 1, max: 2, idleTimeoutMs: 100 },
      },
    ]);
    await p.connectAll();
    // Grow beyond min with two concurrent calls.
    await Promise.all([p.call("pooled__ping", {}), p.call("pooled__ping", {})]);
    let diag = await p.diagnose();
    expect(diag.pooled.pool!.size).toBe(2);

    await new Promise((r) => setTimeout(r, 150)); // let both go idle past 100 ms
    await p.maintainPools();
    diag = await p.diagnose();
    expect(diag.pooled.pool!.size).toBe(1);
  });

  it("rebuilds the pool after a dead connection is dropped (self-heal)", async () => {
    const p = await makeProxy([
      {
        name: "pooled",
        transport: { kind: "http", url: upstream.url },
        auth: { type: "none" },
        pool: { min: 1, max: 2 },
      },
    ]);
    await p.connectAll();

    // Kill the upstream: the call fails (bounded retries) and the pool drops
    // the dead connection.
    upstream.failMode = true;
    await expect(p.call("pooled__ping", {})).rejects.toThrow();

    // Recover: the next call reconnects with fresh state and the pool refills.
    upstream.failMode = false;
    const res = (await p.call("pooled__ping", {})) as { content?: unknown };
    expect(res.content).toBeTruthy();
    const diag = await p.diagnose();
    expect(diag.pooled.ok).toBe(true);
    expect(diag.pooled.pool!.size).toBeGreaterThanOrEqual(1);
  });
});

/**
 * Vault IPC client (EPIC-05) — two flavors:
 *
 * - `VaultIpcClient` (async): promise-based NDJSON client used by management
 *   commands (rotate-key) and tests. Safe to use in the same process as an
 *   in-process vaultd server (it never blocks the event loop).
 *
 * - `SyncIpcVault` (sync): implements the synchronous `VaultOps` surface so
 *   `Vault.open()` can serve the daemon transport WITHOUT changing its public
 *   API. Node sockets are async-only, so the socket lives in a worker thread
 *   and the main thread waits on a SharedArrayBuffer with `Atomics.wait`.
 *   Workers and sockets are unref'd so they never keep a CLI process alive.
 *
 *   IMPORTANT: the sync bridge blocks the process event loop during each
 *   request (sub-millisecond against a local vaultd). It therefore REQUIRES
 *   vaultd to run in a separate process — never point it at an in-process
 *   server (the loop would be frozen and the request would time out).
 *
 * Transport failures raise `DaemonUnavailableError`; vault-level errors (e.g.
 * a missing ref) come back as plain `Error` with the daemon's message, which
 * is byte-identical to the local vault's message.
 */
import net from "node:net";
import { Worker } from "node:worker_threads";
import type { VaultOps } from "./core.js";
import {
  VAULT_IPC_MAX_FRAME,
  LineDecoder,
  encodeLine,
  errMsg,
  type VaultOp,
  type VaultRequest,
  type VaultResponse,
} from "./transport.js";

/** Transport-level failure: vaultd unreachable, dead or timed out. */
export class DaemonUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DaemonUnavailableError";
  }
}

const DEFAULT_OP_TIMEOUT_MS = 5_000;
const ROTATE_OP_TIMEOUT_MS = 30_000;

// ---------------------------------------------------------------------------
// Async client
// ---------------------------------------------------------------------------

export class VaultIpcClient {
  private seq = 0;
  private closed = false;
  private readonly decoder = new LineDecoder();
  private readonly pending = new Map<
    number,
    {
      resolve: (data: unknown) => void;
      reject: (err: Error) => void;
      timer: NodeJS.Timeout;
    }
  >();

  static connect(socketPath: string, timeoutMs: number): Promise<VaultIpcClient> {
    return new Promise((resolve, reject) => {
      const sock = net.createConnection(socketPath);
      const timer = setTimeout(() => {
        sock.destroy();
        reject(
          new DaemonUnavailableError(
            `timeout connecting to vaultd at ${socketPath} (${timeoutMs}ms)`,
          ),
        );
      }, timeoutMs);
      sock.once("connect", () => {
        clearTimeout(timer);
        resolve(new VaultIpcClient(sock));
      });
      sock.once("error", (e) => {
        clearTimeout(timer);
        reject(
          new DaemonUnavailableError(
            `cannot connect to vaultd at ${socketPath}: ${e.message}`,
          ),
        );
      });
    });
  }

  private constructor(private readonly sock: net.Socket) {
    sock.on("data", (chunk: Buffer) => {
      let lines: string[];
      try {
        lines = this.decoder.push(chunk.toString("utf8"));
      } catch (e) {
        this.failAll(
          new DaemonUnavailableError(`vaultd response error: ${errMsg(e)}`),
        );
        this.close();
        return;
      }
      for (const line of lines) {
        if (!line.trim()) continue;
        let res: VaultResponse;
        try {
          res = JSON.parse(line) as VaultResponse;
        } catch {
          this.failAll(new DaemonUnavailableError("invalid JSON frame from vaultd"));
          this.close();
          return;
        }
        const id = res.id ?? -1;
        const entry = this.pending.get(id) ?? this.pending.values().next().value;
        if (!entry) continue; // unsolicited frame — ignore
        this.pending.delete(id);
        clearTimeout(entry.timer);
        if (res.ok) entry.resolve(res.data);
        else entry.reject(new Error(res.error ?? "vaultd request failed"));
      }
    });
    const onGone = () => {
      this.failAll(
        new DaemonUnavailableError("vaultd connection closed mid-request"),
      );
      this.closed = true;
    };
    sock.on("error", onGone);
    sock.on("close", onGone);
  }

  request(
    op: VaultOp,
    fields: { ref?: string; value?: string; backend?: string } = {},
    timeoutMs: number = DEFAULT_OP_TIMEOUT_MS,
  ): Promise<unknown> {
    if (this.closed) {
      return Promise.reject(
        new DaemonUnavailableError("vaultd connection is closed"),
      );
    }
    const id = ++this.seq;
    let line: string;
    try {
      line = encodeLine({ id, op, ...fields } as VaultRequest);
    } catch (e) {
      return Promise.reject(e instanceof Error ? e : new Error(String(e)));
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(
          new DaemonUnavailableError(
            `vaultd request '${op}' timed out after ${timeoutMs}ms`,
          ),
        );
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.sock.write(line);
    });
  }

  close(): void {
    this.closed = true;
    this.sock.destroy();
    this.failAll(new DaemonUnavailableError("vaultd client closed"));
  }

  private failAll(err: Error): void {
    for (const entry of this.pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(err);
    }
    this.pending.clear();
  }
}

/** Quick liveness check: connect + status within timeoutMs. */
export async function probeVaultd(
  socketPath: string,
  timeoutMs = 300,
): Promise<boolean> {
  try {
    const client = await VaultIpcClient.connect(socketPath, timeoutMs);
    await client.request("status", {}, timeoutMs);
    client.close();
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Sync bridge (worker thread + SharedArrayBuffer + Atomics.wait)
// ---------------------------------------------------------------------------

// Worker thread source (CommonJS — `eval` workers are CJS). Owns the socket;
// communicates responses back through the SharedArrayBuffer. States written to
// i32[0]: 1 = connected, 2 = transport error, 3 = response ready. The response
// JSON bytes live at byte offset 8, length in i32[1]. Requests arrive via
// parentPort messages (strictly one in flight — the main thread is blocked
// until each answer lands).
const WORKER_SOURCE = `
"use strict";
const { parentPort, workerData } = require("node:worker_threads");
const net = require("node:net");
const i32 = new Int32Array(workerData.sab);
const u8 = new Uint8Array(workerData.sab);
const HEADER = 8;
const MAX_FRAME = workerData.maxFrame;
let dead = false;
function post(state, obj) {
  try {
    let len = 0;
    if (obj !== undefined) {
      let b = Buffer.from(JSON.stringify(obj), "utf8");
      if (HEADER + b.length > u8.length) {
        b = Buffer.from(JSON.stringify({ ok: false, error: "vaultd response exceeds shared buffer" }), "utf8");
      }
      u8.set(b, HEADER);
      len = b.length;
    }
    Atomics.store(i32, 1, len);
    Atomics.store(i32, 0, state);
    Atomics.notify(i32, 0);
  } catch (e) { /* main thread gone */ }
}
const sock = net.createConnection(workerData.socketPath);
let buf = "";
sock.on("connect", () => post(1));
sock.on("error", (e) => {
  if (!dead) { dead = true; post(2, { error: String((e && e.message) || e) }); }
});
sock.on("close", () => {
  if (!dead) { dead = true; post(2, { error: "vaultd connection closed" }); }
});
sock.on("data", (chunk) => {
  if (dead) return;
  buf += chunk.toString("utf8");
  const idx = buf.indexOf("\\n");
  if (idx < 0) {
    if (Buffer.byteLength(buf, "utf8") > MAX_FRAME) {
      dead = true;
      post(2, { error: "vaultd response frame exceeds 64KiB" });
      sock.destroy();
    }
    return;
  }
  const line = buf.slice(0, idx);
  buf = buf.slice(idx + 1);
  try {
    post(3, JSON.parse(line));
  } catch (e) {
    dead = true;
    post(2, { error: "invalid JSON frame from vaultd" });
  }
});
parentPort.on("message", (req) => {
  if (dead) { post(2, { error: "vaultd connection closed" }); return; }
  try {
    sock.write(JSON.stringify(req) + "\\n");
  } catch (e) {
    dead = true;
    post(2, { error: String((e && e.message) || e) });
  }
});
sock.unref();
`;

const SAB_BYTES = 8 + VAULT_IPC_MAX_FRAME * 2 + 4096;

/** Poll the state cell with Atomics.wait; returns 0 on timeout. */
function waitState(i32: Int32Array, timeoutMs: number): number {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const state = Atomics.load(i32, 0);
    if (state !== 0) return state;
    const remain = deadline - Date.now();
    if (remain <= 0) return 0;
    Atomics.wait(i32, 0, 0, Math.min(remain, 100));
  }
}

/** One worker-bridged connection to vaultd; respawns after transport death. */
export class SyncVaultBridge {
  private worker: Worker | null = null;
  private i32: Int32Array | null = null;
  private u8: Uint8Array | null = null;
  private seq = 0;
  private dead = true;

  constructor(readonly socketPath: string) {}

  private ensureConnected(timeoutMs: number): void {
    if (!this.dead && this.worker) return;
    this.discardWorker();
    const sab = new SharedArrayBuffer(SAB_BYTES);
    const i32 = new Int32Array(sab);
    const u8 = new Uint8Array(sab);
    const worker = new Worker(WORKER_SOURCE, {
      eval: true,
      workerData: { socketPath: this.socketPath, sab, maxFrame: VAULT_IPC_MAX_FRAME },
    });
    worker.unref();
    worker.on("error", () => {
      this.dead = true;
    });
    worker.on("exit", () => {
      this.dead = true;
    });
    const state = waitState(i32, timeoutMs);
    if (state === 1) {
      this.worker = worker;
      this.i32 = i32;
      this.u8 = u8;
      this.dead = false;
      return;
    }
    const why =
      state === 2
        ? readPayloadError(u8, i32)
        : `timeout after ${timeoutMs}ms`;
    void worker.terminate();
    throw new DaemonUnavailableError(
      `cannot connect to vaultd at ${this.socketPath}: ${why}`,
    );
  }

  request(
    op: VaultOp,
    fields: { ref?: string; value?: string; backend?: string } = {},
    timeoutMs: number = DEFAULT_OP_TIMEOUT_MS,
  ): unknown {
    const deadline = Date.now() + timeoutMs;
    this.ensureConnected(Math.max(100, deadline - Date.now()));
    const i32 = this.i32!;
    const worker = this.worker!;
    Atomics.store(i32, 0, 0);
    const id = ++this.seq;
    try {
      worker.postMessage({ id, op, ...fields });
    } catch (e) {
      this.dead = true;
      throw new DaemonUnavailableError(
        `vaultd request '${op}' could not be sent: ${errMsg(e)}`,
      );
    }
    const state = waitState(i32, Math.max(50, deadline - Date.now()));
    if (state === 3) {
      const res = JSON.parse(
        Buffer.from(this.u8!.slice(8, 8 + Atomics.load(i32, 1))).toString("utf8"),
      ) as VaultResponse;
      if (res.ok) return res.data;
      // Vault-level error (e.g. missing ref): same message as the local vault.
      throw new Error(res.error ?? "vaultd request failed");
    }
    this.dead = true;
    const why =
      state === 2
        ? readPayloadError(this.u8!, i32)
        : `timeout after ${timeoutMs}ms`;
    void worker.terminate();
    throw new DaemonUnavailableError(`vaultd request '${op}' failed: ${why}`);
  }

  close(): void {
    this.discardWorker();
  }

  private discardWorker(): void {
    if (this.worker) {
      void this.worker.terminate();
      this.worker = null;
    }
    this.i32 = null;
    this.u8 = null;
    this.dead = true;
  }
}

function readPayloadError(u8: Uint8Array, i32: Int32Array): string {
  try {
    const obj = JSON.parse(
      Buffer.from(u8.slice(8, 8 + Atomics.load(i32, 1))).toString("utf8"),
    ) as { error?: string };
    return obj.error ?? "unknown transport error";
  } catch {
    return "unknown transport error";
  }
}

/** Bridges are shared per socket path (one worker serves every Vault.open). */
function bridgeRegistry(): Map<string, SyncVaultBridge> {
  const g = globalThis as { __scopegateVaultBridges?: Map<string, SyncVaultBridge> };
  if (!g.__scopegateVaultBridges) g.__scopegateVaultBridges = new Map();
  return g.__scopegateVaultBridges;
}

export function getOrCreateBridge(socketPath: string): SyncVaultBridge {
  const registry = bridgeRegistry();
  let bridge = registry.get(socketPath);
  if (!bridge) {
    bridge = new SyncVaultBridge(socketPath);
    registry.set(socketPath, bridge);
  }
  return bridge;
}

/** Terminate every bridge worker (test cleanup; not needed by consumers). */
export function closeVaultTransports(): void {
  for (const bridge of bridgeRegistry().values()) bridge.close();
  bridgeRegistry().clear();
}

/** VaultOps over the sync bridge — the daemon-mode backend of the Vault facade. */
export class SyncIpcVault implements VaultOps {
  constructor(private readonly bridge: SyncVaultBridge) {}

  /** Probe used at Vault.open(): status within the given budget. */
  ping(timeoutMs: number): void {
    this.bridge.request("status", {}, timeoutMs);
  }

  get(ref: string): string {
    return this.bridge.request("get", { ref }) as string;
  }

  has(ref: string): boolean {
    return this.bridge.request("has", { ref }) as boolean;
  }

  set(ref: string, value: string): void {
    this.bridge.request("set", { ref, value });
  }

  delete(ref: string): void {
    this.bridge.request("delete", { ref });
  }

  listRefs(): string[] {
    return this.bridge.request("listRefs", {}) as string[];
  }

  rotate(backend?: string): unknown {
    return this.bridge.request(
      "rotate",
      backend ? { backend } : {},
      ROTATE_OP_TIMEOUT_MS,
    );
  }
}

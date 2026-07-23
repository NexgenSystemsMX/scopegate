/**
 * vaultd (EPIC-05): the vault as an isolated process.
 *
 * A standalone `net` server that is the ONLY process holding the master key
 * and the decrypted store in memory. It listens exclusively on a local
 * transport — unix socket (POSIX) or named pipe (Windows) — and never opens
 * a network port.
 *
 * Protocol: NDJSON (one JSON request, one JSON response per line), frames
 * capped at 64 KiB. Ops: get | has | set | delete | listRefs | status | rotate.
 * Secret VALUES are never logged and only ever travel inside responses to
 * `get` on the same-user local channel (see peer-auth notes in transport.ts).
 *
 * Write serialization ("single writer"): every op runs synchronously on the
 * event loop (the core's encrypt+persist is sync), so requests are naturally
 * processed one at a time — the event loop itself is the mutex.
 */
import fs from "node:fs";
import net from "node:net";
import { ensureDir } from "../config/config.js";
import { LocalVaultCore } from "./core.js";
import { probeVaultd } from "./client.js";
import {
  LineDecoder,
  debugLog,
  encodeLine,
  errMsg,
  resolveVaultSocketPath,
  vaultTransportKind,
  type VaultRequest,
  type VaultResponse,
} from "./transport.js";

export interface VaultdServer {
  socketPath: string;
  close(): Promise<void>;
}

interface HandleContext {
  core: LocalVaultCore;
  socketPath: string;
  startedAt: number;
}

function requireRef(req: VaultRequest): string {
  if (typeof req.ref !== "string" || req.ref.length === 0) {
    throw new Error(`op '${req.op}' requires a non-empty string 'ref'`);
  }
  return req.ref;
}

function handleOp(ctx: HandleContext, req: VaultRequest): VaultResponse {
  const id = typeof req.id === "number" ? req.id : null;
  try {
    switch (req.op) {
      case "get":
        return { id, ok: true, data: ctx.core.get(requireRef(req)) };
      case "has":
        return { id, ok: true, data: ctx.core.has(requireRef(req)) };
      case "set": {
        const ref = requireRef(req);
        if (typeof req.value !== "string") {
          throw new Error("op 'set' requires a string 'value'");
        }
        ctx.core.set(ref, req.value);
        return { id, ok: true, data: null };
      }
      case "delete":
        ctx.core.delete(requireRef(req));
        return { id, ok: true, data: null };
      case "listRefs":
        return { id, ok: true, data: ctx.core.listRefs() };
      case "status":
        return {
          id,
          ok: true,
          data: {
            status: "ok",
            pid: process.pid,
            transport: vaultTransportKind(ctx.socketPath),
            socketPath: ctx.socketPath,
            masterKeyBackend: ctx.core.masterKeyBackend,
            kid: ctx.core.kid,
            refs: ctx.core.listRefs().length,
            uptimeSeconds: Math.round((Date.now() - ctx.startedAt) / 1000),
          },
        };
      case "rotate":
        return {
          id,
          ok: true,
          data: ctx.core.rotateMasterKey({
            backend: typeof req.backend === "string" ? req.backend : undefined,
          }),
        };
      default:
        return { id, ok: false, error: `unknown op '${String(req.op)}'` };
    }
  } catch (e) {
    return { id, ok: false, error: errMsg(e) };
  }
}

/**
 * Start a vaultd server. Used by the `scopegate vaultd` command and directly
 * by tests (with a custom socket and an injected core).
 */
export async function startVaultdServer(
  opts: { socket?: string; core?: LocalVaultCore } = {},
): Promise<VaultdServer> {
  const socketPath = resolveVaultSocketPath(opts.socket);
  const kind = vaultTransportKind(socketPath);
  ensureDir();
  const core = opts.core ?? LocalVaultCore.open();
  const ctx: HandleContext = { core, socketPath, startedAt: Date.now() };
  const conns = new Set<net.Socket>();

  if (kind === "unix" && fs.existsSync(socketPath)) {
    // Stale socket from a dead daemon? Probe, then take over.
    if (await probeVaultd(socketPath, 300)) {
      throw new Error(`vaultd already running on ${socketPath}`);
    }
    fs.unlinkSync(socketPath);
  }

  const server = net.createServer((conn) => {
    conns.add(conn);
    debugLog(`vaultd: peer connected (${conns.size} total)`);
    const decoder = new LineDecoder();
    conn.on("data", (chunk) => {
      let lines: string[];
      try {
        lines = decoder.push(chunk.toString("utf8"));
      } catch (e) {
        // Frame cap violation: best-effort error response, then drop the peer.
        try {
          conn.write(
            JSON.stringify({ id: null, ok: false, error: errMsg(e) }) + "\n",
          );
        } catch {
          /* peer already gone */
        }
        conn.destroy();
        return;
      }
      for (const line of lines) {
        if (!line.trim()) continue;
        let req: VaultRequest;
        try {
          req = JSON.parse(line) as VaultRequest;
        } catch {
          writeResponse(conn, { id: null, ok: false, error: "invalid JSON frame" });
          continue;
        }
        writeResponse(conn, handleOp(ctx, req));
      }
    });
    conn.on("error", () => {
      /* peer errors are expected on disconnect */
    });
    conn.on("close", () => conns.delete(conn));
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });

  if (kind === "unix") {
    // Same-user enforcement on POSIX: only the owner can connect.
    try {
      fs.chmodSync(socketPath, 0o600);
    } catch (e) {
      debugLog(`vaultd: could not chmod socket (best effort): ${errMsg(e)}`);
    }
  }

  return {
    socketPath,
    close: () =>
      new Promise<void>((resolve) => {
        for (const conn of conns) conn.destroy();
        server.close(() => {
          if (kind === "unix") {
            try {
              fs.unlinkSync(socketPath);
            } catch {
              /* already gone */
            }
          }
          resolve();
        });
      }),
  };
}

function writeResponse(conn: net.Socket, res: VaultResponse): void {
  try {
    conn.write(encodeLine(res));
  } catch (e) {
    debugLog(`vaultd: failed to write response: ${errMsg(e)}`);
  }
}

/**
 * Vault IPC transport (EPIC-05): how the Vault facade reaches vaultd.
 *
 * - POSIX: unix socket at ~/.scopegate/vault.sock (dir 0700, socket chmod 0600).
 * - Windows: named pipe \\.\pipe\scopegate-vault-<hash8>, where hash8 is the
 *   first 8 hex chars of sha256(SCOPEGATE_DIR). In production SCOPEGATE_DIR is
 *   <home>/.scopegate, so the pipe is namespaced per user; in tests it is a
 *   mkdtemp dir, so parallel test runs never share a pipe.
 * - Protocol: NDJSON — one JSON request and one JSON response per line.
 *
 * Peer authentication model (documented limitation, no over-engineering):
 * - POSIX: same-user enforcement comes from filesystem permissions (the
 *   ~/.scopegate dir is 0700 and the socket is chmod 0600 after listen), so
 *   other users cannot connect at all. SO_PEERCRED is not exposed by pure
 *   Node.js and would require a native addon — noted, deliberately not used.
 * - Windows: the pipe name embeds a hash of the user's ScopeGate home, which
 *   namespaces it per user but is NOT a real ACL (any local process that can
 *   compute the hash could connect). True pipe ACLs need native calls; from
 *   pure Node this is the accepted best effort.
 * - In both cases the threat model is: defense against OTHER users and against
 *   secret residency in the gateway process — not against arbitrary code
 *   already running as the same user.
 */
import crypto from "node:crypto";
import path from "node:path";
import { SCOPEGATE_DIR } from "../config/config.js";

/** Max bytes for a single NDJSON frame (request or response line). */
export const VAULT_IPC_MAX_FRAME = 64 * 1024;

export type VaultOp =
  | "get"
  | "has"
  | "set"
  | "delete"
  | "listRefs"
  | "status"
  | "rotate";

export interface VaultRequest {
  id: number;
  op: VaultOp;
  ref?: string;
  value?: string;
  /** Optional target master-key backend for the `rotate` op. */
  backend?: string;
}

export interface VaultResponse {
  id: number | null;
  ok: boolean;
  data?: unknown;
  error?: string;
}

/** Pidfile of a running vaultd (best-effort single instance). */
export const VAULTD_PID_PATH = path.join(SCOPEGATE_DIR, "vaultd.pid");

/** First 8 hex chars of sha256(input) — short stable id for pipe names. */
export function hash8(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex").slice(0, 8);
}

export function defaultVaultSocketPath(): string {
  if (process.platform === "win32") {
    const dirHash = hash8(path.resolve(SCOPEGATE_DIR).toLowerCase());
    return `\\\\.\\pipe\\scopegate-vault-${dirHash}`;
  }
  return path.join(SCOPEGATE_DIR, "vault.sock");
}

/** Resolution order: explicit override > SCOPEGATE_VAULT_SOCKET > default. */
export function resolveVaultSocketPath(override?: string): string {
  return override ?? process.env.SCOPEGATE_VAULT_SOCKET ?? defaultVaultSocketPath();
}

export function vaultTransportKind(socketPath: string): "unix" | "pipe" {
  return socketPath.startsWith("\\\\.\\pipe\\") ? "pipe" : "unix";
}

/** Serialize one message as an NDJSON line, enforcing the frame cap. */
export function encodeLine(msg: VaultRequest | VaultResponse): string {
  const line = JSON.stringify(msg);
  if (Buffer.byteLength(line, "utf8") > VAULT_IPC_MAX_FRAME) {
    throw new Error(
      `vault IPC frame exceeds ${VAULT_IPC_MAX_FRAME} bytes (op '${msg && (msg as VaultRequest).op}')`,
    );
  }
  return line + "\n";
}

/** Incremental NDJSON splitter with the frame cap enforced on single lines. */
export class LineDecoder {
  private buf = "";

  push(chunk: string): string[] {
    this.buf += chunk;
    const lines: string[] = [];
    let idx: number;
    while ((idx = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, idx);
      if (Buffer.byteLength(line, "utf8") > VAULT_IPC_MAX_FRAME) {
        throw new Error(`vault IPC frame exceeds ${VAULT_IPC_MAX_FRAME} bytes`);
      }
      lines.push(line);
      this.buf = this.buf.slice(idx + 1);
    }
    if (Buffer.byteLength(this.buf, "utf8") > VAULT_IPC_MAX_FRAME) {
      throw new Error(`vault IPC frame exceeds ${VAULT_IPC_MAX_FRAME} bytes`);
    }
    return lines;
  }
}

/** Debug-only logger: stderr, and never called with secret values. */
export function debugLog(msg: string): void {
  if ((process.env.SCOPEGATE_LOG_LEVEL ?? "").toLowerCase() === "debug") {
    console.error(`[scopegate:vault] ${msg}`);
  }
}

export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

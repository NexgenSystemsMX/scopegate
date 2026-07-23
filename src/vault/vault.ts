/**
 * Vault: encrypted-at-rest secret store (hardened in EPIC-05).
 *
 * - AES-256-GCM, key derived (scrypt) from a master key held by a
 *   MasterKeyStore backend: OS keychain where available (DPAPI / macOS
 *   Keychain / Secret Service), file fallback (master.key, mode 0600).
 * - Secrets are written via CLI/stdin ONLY — never through the model's context.
 * - The gateway reads secrets exclusively at the upstream hop; tool results
 *   and tool listings never contain them.
 *
 * Transport — an INTERNAL detail, invisible to consumers (the public surface
 * `Vault.open()` + set/get/has/delete/listRefs is unchanged). Selected by
 * SCOPEGATE_VAULT_MODE:
 *   auto   (default) use vaultd over unix socket / Windows named pipe when it
 *          answers a status probe within 300ms, otherwise the in-process
 *          local vault (debug-logged). If vaultd dies mid-session, the next
 *          op transparently fails over to the local vault — the gateway never
 *          crashes and never waits on the daemon beyond the probe budget.
 *   local  always the in-process vault (dev/tests).
 *   daemon require vaultd; fail fast with an actionable error when absent.
 */
import { LocalVaultCore, type VaultOps } from "./core.js";
import {
  DaemonUnavailableError,
  SyncIpcVault,
  getOrCreateBridge,
} from "./client.js";
import { debugLog, errMsg, resolveVaultSocketPath } from "./transport.js";

const AUTO_PROBE_TIMEOUT_MS = 300;
const DAEMON_CONNECT_TIMEOUT_MS = 3_000;

type VaultMode = "auto" | "local" | "daemon";

function requestedMode(): VaultMode {
  const raw = (process.env.SCOPEGATE_VAULT_MODE ?? "auto").toLowerCase();
  if (raw === "local" || raw === "daemon" || raw === "auto") return raw;
  debugLog(`unknown SCOPEGATE_VAULT_MODE '${raw}', falling back to 'auto'`);
  return "auto";
}

export class Vault {
  private ops!: VaultOps;
  /** True while this instance may still fail over from daemon to local. */
  private failoverArmed = false;

  private constructor() {}

  static open(): Vault {
    const v = new Vault();
    const mode = requestedMode();
    if (mode === "local") {
      v.ops = LocalVaultCore.open();
      debugLog("vault transport: local (SCOPEGATE_VAULT_MODE=local)");
      return v;
    }

    const socketPath = resolveVaultSocketPath();
    const ipc = new SyncIpcVault(getOrCreateBridge(socketPath));
    try {
      ipc.ping(
        mode === "auto" ? AUTO_PROBE_TIMEOUT_MS : DAEMON_CONNECT_TIMEOUT_MS,
      );
      v.ops = ipc;
      v.failoverArmed = mode === "auto";
      debugLog(`vault transport: daemon (${socketPath})`);
      return v;
    } catch (e) {
      if (mode === "daemon") {
        throw new Error(
          `SCOPEGATE_VAULT_MODE=daemon but vaultd is not reachable at ${socketPath}. ` +
            `Start it with \`scopegate vaultd\` (or unset SCOPEGATE_VAULT_MODE). Cause: ${errMsg(e)}`,
        );
      }
      debugLog(
        `vaultd probe at ${socketPath} failed (${errMsg(e)}); using local transport`,
      );
      v.ops = LocalVaultCore.open();
      v.failoverArmed = true;
      return v;
    }
  }

  private call<T>(op: string, fn: (ops: VaultOps) => T): T {
    try {
      return fn(this.ops);
    } catch (e) {
      if (this.failoverArmed && e instanceof DaemonUnavailableError) {
        debugLog(
          `vaultd lost during '${op}' (${e.message}); failing over to local transport`,
        );
        this.ops = LocalVaultCore.open();
        this.failoverArmed = false; // local errors must surface as-is
        return fn(this.ops);
      }
      throw e;
    }
  }

  set(ref: string, value: string): void {
    this.call("set", (ops) => ops.set(ref, value));
  }

  get(ref: string): string {
    return this.call("get", (ops) => ops.get(ref));
  }

  has(ref: string): boolean {
    return this.call("has", (ops) => ops.has(ref));
  }

  delete(ref: string): void {
    this.call("delete", (ops) => ops.delete(ref));
  }

  /** Names only — safe to show to agents/humans. Never values. */
  listRefs(): string[] {
    return this.call("listRefs", (ops) => ops.listRefs());
  }
}

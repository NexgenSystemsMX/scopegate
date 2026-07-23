/**
 * `scopegate vaultd` — run the vault as an isolated process (EPIC-05).
 *
 * vaultd is the only process holding the master key and the decrypted store;
 * the gateway and CLI talk to it over a unix socket (POSIX) or named pipe
 * (Windows). See daemon.ts for the protocol and transport.ts for the
 * peer-authentication model.
 *
 * Single instance is best-effort: a pidfile + live probe refuses a second
 * daemon on the same socket; a stale pidfile/socket from a crashed daemon is
 * taken over silently.
 */
import fs from "node:fs";
import { ensureDir } from "../config/config.js";
import { startVaultdServer } from "../vault/daemon.js";
import { probeVaultd } from "../vault/client.js";
import {
  VAULTD_PID_PATH,
  debugLog,
  errMsg,
  resolveVaultSocketPath,
} from "../vault/transport.js";

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export async function runVaultd(opts: { socket?: string }): Promise<void> {
  const socketPath = resolveVaultSocketPath(opts.socket);

  if (fs.existsSync(VAULTD_PID_PATH)) {
    try {
      const info = JSON.parse(fs.readFileSync(VAULTD_PID_PATH, "utf8")) as {
        pid?: number;
        socketPath?: string;
      };
      const recordedSocket = info.socketPath ?? socketPath;
      if (
        info.pid &&
        info.pid !== process.pid &&
        pidAlive(info.pid) &&
        (await probeVaultd(recordedSocket, 300))
      ) {
        throw new Error(
          `vaultd already running (pid ${info.pid}) on ${recordedSocket}`,
        );
      }
    } catch (e) {
      if (e instanceof Error && e.message.includes("already running")) throw e;
      debugLog(`vaultd: ignoring stale/corrupt pidfile: ${errMsg(e)}`);
    }
  }

  const server = await startVaultdServer({ socket: opts.socket });

  ensureDir();
  const tmpPid = VAULTD_PID_PATH + ".tmp";
  fs.writeFileSync(
    tmpPid,
    JSON.stringify({
      pid: process.pid,
      socketPath: server.socketPath,
      startedAt: new Date().toISOString(),
    }),
    { mode: 0o600 },
  );
  fs.renameSync(tmpPid, VAULTD_PID_PATH);

  // Parseable readiness line for the orchestrator and e2e tests.
  console.log(`vaultd listening on ${server.socketPath} (pid ${process.pid})`);

  await new Promise<void>((resolve) => {
    let shuttingDown = false;
    const shutdown = (signal: string) => {
      if (shuttingDown) return;
      shuttingDown = true;
      debugLog(`vaultd: received ${signal}; shutting down`);
      void server
        .close()
        .catch(() => {})
        .then(() => {
          try {
            fs.rmSync(VAULTD_PID_PATH, { force: true });
          } catch {
            /* best effort */
          }
          resolve();
        });
    };
    process.once("SIGINT", () => shutdown("SIGINT"));
    process.once("SIGTERM", () => shutdown("SIGTERM"));
  });
}

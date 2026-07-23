/**
 * `scopegate vault rotate-key` — rotate the vault master key (EPIC-05 H5).
 *
 * Generates a fresh 32-byte master key, re-encrypts the whole vault
 * (VaultFile v2, new kid) with a verified backup and atomic write, and stores
 * the new key in the master-key backend. With `--backend <name>` the new key
 * lands in that backend, which also completes the Fase 0 file → OS keychain
 * migration (the legacy master.key is securely deleted after verification).
 *
 * When vaultd is running it owns the vault, so the rotation is sent to it
 * over IPC instead of touching files behind its back.
 */
import { LocalVaultCore, type VaultRotationResult } from "../vault/core.js";
import { probeVaultd, VaultIpcClient } from "../vault/client.js";
import { resolveVaultSocketPath } from "../vault/transport.js";

export async function runVaultRotateKey(opts: { backend?: string }): Promise<void> {
  const socketPath = resolveVaultSocketPath();

  if (await probeVaultd(socketPath, 300)) {
    const client = await VaultIpcClient.connect(socketPath, 1_000);
    try {
      const result = (await client.request(
        "rotate",
        opts.backend ? { backend: opts.backend } : {},
        30_000,
      )) as VaultRotationResult;
      report(result, "via vaultd");
      return;
    } finally {
      client.close();
    }
  }

  const core = LocalVaultCore.open({ backend: opts.backend });
  report(core.rotateMasterKey({ backend: opts.backend }), "local");
}

function report(r: VaultRotationResult, how: string): void {
  console.log(
    `[scopegate] master key rotated (${how}): kid ${r.oldKid} → ${r.newKid} (backend: ${r.backend})`,
  );
  console.log(
    `[scopegate] pre-rotation backup kept at ${r.backupPath} — delete it once ` +
      "you have verified the vault works (e.g. `scopegate status`).",
  );
  if (r.backend === "file") {
    console.error(
      "[scopegate] WARN: the master key still uses the file backend " +
        "(~/.scopegate/master.key). Re-run with --backend dpapi | keychain | " +
        "secret-service to move it into the OS keychain.",
    );
  }
}

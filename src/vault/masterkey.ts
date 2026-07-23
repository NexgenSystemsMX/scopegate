/**
 * MasterKeyStore (EPIC-05): where the vault's 32-byte master key lives.
 *
 * The interface is SYNCHRONOUS on purpose: `Vault.open()` is a synchronous
 * public API consumed by the gateway, proxy, minter and CLI, and none of them
 * can await. OS backends therefore use short blocking `spawnSync` calls to
 * the OS CLI tooling (powershell.exe / security / secret-tool), with results
 * cached in memory for the life of the process.
 *
 * Backends:
 * - file           legacy Fase 0 behavior: hex key at ~/.scopegate/master.key,
 *                  mode 0600. Explicit fallback (WARN once when auto-selected).
 * - dpapi          Windows DPAPI (ProtectedData, CurrentUser scope) via
 *                  powershell.exe; protected blob at ~/.scopegate/master.dpapi.
 * - keychain       macOS `security` generic-password (service "scopegate",
 *                  account "master-key"). Note: `security add-generic-password`
 *                  takes the secret via argv — briefly visible in `ps` to the
 *                  same user; accepted platform trade-off, documented.
 * - secret-service Linux `secret-tool` (libsecret / org.freedesktop.secrets).
 *
 * Selection: SCOPEGATE_MASTER_KEY_BACKEND=auto|file|dpapi|keychain|secret-service
 * (default auto = best OS backend available on this platform, else file).
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { MASTER_KEY_PATH, SCOPEGATE_DIR, ensureDir } from "../config/config.js";
import { debugLog } from "./transport.js";

export interface MasterKeyStore {
  readonly backend: string;
  /** Returns the 32-byte master key, or null when none is stored yet. */
  load(): Buffer | null;
  /** Replaces the stored master key. */
  store(key: Buffer): void;
}

const DPAPI_BLOB_PATH = path.join(SCOPEGATE_DIR, "master.dpapi");
const KEYCHAIN_SERVICE = "scopegate";
const KEYCHAIN_ACCOUNT = "master-key";
const SECRET_TOOL_ATTRS = ["service", "scopegate", "account", "master-key"];

/**
 * Per-process caches kept on globalThis so vitest's vi.resetModules() (which
 * rebuilds the module graph per test) does not re-spawn OS tooling for every
 * test. Key material cached here is already resident in the process heap via
 * LocalVaultCore.masterKey, so this does not change the threat model.
 */
interface MkCache {
  availability: Map<string, boolean>;
  keys: Map<string, string>; // blob/service id -> key hex
  warnedFileFallback: boolean;
}

function mkCache(): MkCache {
  const g = globalThis as { __scopegateMkCache?: MkCache };
  if (!g.__scopegateMkCache) {
    g.__scopegateMkCache = {
      availability: new Map(),
      keys: new Map(),
      warnedFileFallback: false,
    };
  }
  return g.__scopegateMkCache;
}

function cachedAvailability(
  name: string,
  probe: () => boolean,
): boolean {
  const cache = mkCache().availability;
  const hit = cache.get(name);
  if (hit !== undefined) return hit;
  const ok = probe();
  cache.set(name, ok);
  return ok;
}

function validateKey(key: Buffer, source: string): Buffer {
  if (key.length !== 32) {
    throw new Error(
      `master key from ${source} has invalid length ${key.length} (expected 32 bytes)`,
    );
  }
  return key;
}

// ---------------------------------------------------------------------------
// file (legacy Fase 0)
// ---------------------------------------------------------------------------

class FileMasterKeyStore implements MasterKeyStore {
  readonly backend = "file";

  load(): Buffer | null {
    if (!fs.existsSync(MASTER_KEY_PATH)) return null;
    return validateKey(
      Buffer.from(fs.readFileSync(MASTER_KEY_PATH, "utf8").trim(), "hex"),
      MASTER_KEY_PATH,
    );
  }

  store(key: Buffer): void {
    ensureDir();
    fs.writeFileSync(MASTER_KEY_PATH, key.toString("hex") + "\n", {
      mode: 0o600,
    });
  }
}

// ---------------------------------------------------------------------------
// dpapi (Windows) — ProtectedData, CurrentUser scope, via powershell.exe
// ---------------------------------------------------------------------------

const DPAPI_PROBE_PS = [
  "$ErrorActionPreference='Stop'",
  "Add-Type -AssemblyName System.Security",
  "$b=New-Object byte[] 32",
  "(New-Object Random).NextBytes($b)",
  "$p=[System.Security.Cryptography.ProtectedData]::Protect($b,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
  "$u=[System.Security.Cryptography.ProtectedData]::Unprotect($p,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
  "if ([System.BitConverter]::ToString($b) -eq [System.BitConverter]::ToString($u)) { [Console]::Out.Write('ok') } else { throw 'dpapi roundtrip mismatch' }",
].join("\n");

const DPAPI_PROTECT_PS = [
  "$ErrorActionPreference='Stop'",
  "Add-Type -AssemblyName System.Security",
  "$in=[Console]::In.ReadToEnd().Trim()",
  "$b=[Convert]::FromBase64String($in)",
  "$p=[System.Security.Cryptography.ProtectedData]::Protect($b,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
  "[Console]::Out.Write([Convert]::ToBase64String($p))",
].join("\n");

const DPAPI_UNPROTECT_PS = [
  "$ErrorActionPreference='Stop'",
  "Add-Type -AssemblyName System.Security",
  "$in=[Console]::In.ReadToEnd().Trim()",
  "$p=[Convert]::FromBase64String($in)",
  "$b=[System.Security.Cryptography.ProtectedData]::Unprotect($p,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
  "[Console]::Out.Write([Convert]::ToBase64String($b))",
].join("\n");

function runPowerShell(script: string, stdin: string): string {
  const r = spawnSync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    {
      input: stdin,
      encoding: "utf8",
      timeout: 15_000,
      windowsHide: true,
      maxBuffer: 4 * 1024 * 1024,
    },
  );
  if (r.error) throw r.error;
  if (r.status !== 0) {
    throw new Error(
      `powershell.exe exited with code ${r.status}: ${(r.stderr ?? "").trim()}`,
    );
  }
  return (r.stdout ?? "").trim();
}

/** True on Windows when powershell.exe can roundtrip DPAPI CurrentUser. */
export function isDpapiAvailable(): boolean {
  if (process.platform !== "win32") return false;
  return cachedAvailability("dpapi", () => {
    try {
      return runPowerShell(DPAPI_PROBE_PS, "") === "ok";
    } catch (e) {
      debugLog(`dpapi availability probe failed: ${e}`);
      return false;
    }
  });
}

class DpapiMasterKeyStore implements MasterKeyStore {
  readonly backend = "dpapi";

  load(): Buffer | null {
    const cache = mkCache().keys;
    const cached = cache.get(DPAPI_BLOB_PATH);
    if (cached) return Buffer.from(cached, "hex");
    if (!fs.existsSync(DPAPI_BLOB_PATH)) return null;
    const blobB64 = fs.readFileSync(DPAPI_BLOB_PATH, "utf8").trim();
    const key = validateKey(
      Buffer.from(runPowerShell(DPAPI_UNPROTECT_PS, blobB64), "base64"),
      `DPAPI blob ${DPAPI_BLOB_PATH}`,
    );
    cache.set(DPAPI_BLOB_PATH, key.toString("hex"));
    return key;
  }

  store(key: Buffer): void {
    ensureDir();
    const blobB64 = runPowerShell(DPAPI_PROTECT_PS, key.toString("base64"));
    const tmp = DPAPI_BLOB_PATH + ".tmp";
    fs.writeFileSync(tmp, blobB64 + "\n", { mode: 0o600 });
    fs.renameSync(tmp, DPAPI_BLOB_PATH);
    mkCache().keys.set(DPAPI_BLOB_PATH, key.toString("hex"));
  }
}

// ---------------------------------------------------------------------------
// keychain (macOS `security`)
// ---------------------------------------------------------------------------

function isKeychainAvailable(): boolean {
  if (process.platform !== "darwin") return false;
  return cachedAvailability("keychain", () => {
    const r = spawnSync("security", ["list-keychains"], {
      encoding: "utf8",
      timeout: 10_000,
    });
    return !r.error;
  });
}

class KeychainMasterKeyStore implements MasterKeyStore {
  readonly backend = "keychain";
  private static CACHE_ID = "keychain:scopegate/master-key";

  load(): Buffer | null {
    const cache = mkCache().keys;
    const cached = cache.get(KeychainMasterKeyStore.CACHE_ID);
    if (cached) return Buffer.from(cached, "hex");
    const r = spawnSync(
      "security",
      ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"],
      { encoding: "utf8", timeout: 10_000 },
    );
    if (r.error) throw r.error;
    if (r.status !== 0) return null; // errSecItemNotFound
    const key = validateKey(
      Buffer.from((r.stdout ?? "").trim(), "hex"),
      "macOS keychain",
    );
    cache.set(KeychainMasterKeyStore.CACHE_ID, key.toString("hex"));
    return key;
  }

  store(key: Buffer): void {
    const r = spawnSync(
      "security",
      [
        "add-generic-password",
        "-U",
        "-s", KEYCHAIN_SERVICE,
        "-a", KEYCHAIN_ACCOUNT,
        "-w", key.toString("hex"),
      ],
      { encoding: "utf8", timeout: 10_000 },
    );
    if (r.error) throw r.error;
    if (r.status !== 0) {
      throw new Error(
        `security add-generic-password exited with code ${r.status}: ${(r.stderr ?? "").trim()}`,
      );
    }
    mkCache().keys.set(KeychainMasterKeyStore.CACHE_ID, key.toString("hex"));
  }
}

// ---------------------------------------------------------------------------
// secret-service (Linux `secret-tool`, libsecret)
// ---------------------------------------------------------------------------

function isSecretServiceAvailable(): boolean {
  if (process.platform !== "linux") return false;
  return cachedAvailability("secret-service", () => {
    // A lookup of a nonexistent key still proves the tool + daemon respond.
    const r = spawnSync("secret-tool", ["lookup", "service", "scopegate-probe"], {
      encoding: "utf8",
      timeout: 3_000,
    });
    return !r.error;
  });
}

class SecretServiceMasterKeyStore implements MasterKeyStore {
  readonly backend = "secret-service";
  private static CACHE_ID = "secret-service:scopegate/master-key";

  load(): Buffer | null {
    const cache = mkCache().keys;
    const cached = cache.get(SecretServiceMasterKeyStore.CACHE_ID);
    if (cached) return Buffer.from(cached, "hex");
    const r = spawnSync("secret-tool", ["lookup", ...SECRET_TOOL_ATTRS], {
      encoding: "utf8",
      timeout: 10_000,
    });
    if (r.error) throw r.error;
    if (r.status !== 0) return null; // not stored yet
    const key = validateKey(
      Buffer.from((r.stdout ?? "").trim(), "hex"),
      "secret-service",
    );
    cache.set(SecretServiceMasterKeyStore.CACHE_ID, key.toString("hex"));
    return key;
  }

  store(key: Buffer): void {
    const r = spawnSync(
      "secret-tool",
      ["store", "--label=ScopeGate vault master key", ...SECRET_TOOL_ATTRS],
      { input: key.toString("hex"), encoding: "utf8", timeout: 10_000 },
    );
    if (r.error) throw r.error;
    if (r.status !== 0) {
      throw new Error(
        `secret-tool store exited with code ${r.status}: ${(r.stderr ?? "").trim()}`,
      );
    }
    mkCache().keys.set(SecretServiceMasterKeyStore.CACHE_ID, key.toString("hex"));
  }
}

// ---------------------------------------------------------------------------
// selection
// ---------------------------------------------------------------------------

function warnFileFallbackOnce(): void {
  const cache = mkCache();
  if (cache.warnedFileFallback) return;
  cache.warnedFileFallback = true;
  console.error(
    "[scopegate] WARN: no OS keychain backend available on this system; the vault master key " +
      "is stored in ~/.scopegate/master.key (backend: file, mode 0600) — the Fase 0 behavior. " +
      "Set SCOPEGATE_MASTER_KEY_BACKEND=file to make this explicit.",
  );
}

/**
 * Resolve the master-key backend. `backend` (or env SCOPEGATE_MASTER_KEY_BACKEND
 * when omitted) is one of: auto | file | dpapi | keychain | secret-service.
 */
export function selectMasterKeyStore(backend?: string): MasterKeyStore {
  const name = (
    backend ??
    process.env.SCOPEGATE_MASTER_KEY_BACKEND ??
    "auto"
  ).toLowerCase();

  if (name !== "auto") {
    switch (name) {
      case "file":
        return new FileMasterKeyStore();
      case "dpapi":
        if (!isDpapiAvailable()) {
          throw new Error(
            "master key backend 'dpapi' requires Windows with powershell.exe (DPAPI, CurrentUser scope)",
          );
        }
        return new DpapiMasterKeyStore();
      case "keychain":
        if (!isKeychainAvailable()) {
          throw new Error(
            "master key backend 'keychain' requires macOS with the `security` tool",
          );
        }
        return new KeychainMasterKeyStore();
      case "secret-service":
        if (!isSecretServiceAvailable()) {
          throw new Error(
            "master key backend 'secret-service' requires Linux with `secret-tool` (libsecret)",
          );
        }
        return new SecretServiceMasterKeyStore();
      default:
        throw new Error(
          `unknown master key backend '${name}' (valid: auto, file, dpapi, keychain, secret-service)`,
        );
    }
  }

  if (process.platform === "win32" && isDpapiAvailable()) {
    return new DpapiMasterKeyStore();
  }
  if (process.platform === "darwin" && isKeychainAvailable()) {
    return new KeychainMasterKeyStore();
  }
  if (process.platform === "linux" && isSecretServiceAvailable()) {
    return new SecretServiceMasterKeyStore();
  }
  warnFileFallbackOnce();
  return new FileMasterKeyStore();
}

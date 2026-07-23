/**
 * LocalVaultCore (EPIC-05): the transport-independent vault core.
 *
 * - AES-256-GCM, key derived (scrypt) from a master key held by a
 *   MasterKeyStore backend (OS keychain where available, file fallback).
 * - The whole store is one encrypted JSON blob at ~/.scopegate/vault.enc,
 *   written atomically (tmp + rename, mode 0600).
 * - VaultFile v2 carries a `kid` (key id, sha256(masterKey) truncated) so
 *   rotations are auditable; v1 files (Fase 0) still decrypt and report
 *   kid "legacy" until the next write upgrades them to v2.
 * - rotateMasterKey(): verified backup → atomic re-encrypt with a fresh key →
 *   store new key in the backend → verify re-open → rollback on failure.
 *
 * This module never touches the network or IPC; the daemon wraps it and the
 * Vault facade falls back to it.
 */
import fs from "node:fs";
import crypto from "node:crypto";
import { VAULT_PATH, MASTER_KEY_PATH, ensureDir } from "../config/config.js";
import { selectMasterKeyStore, type MasterKeyStore } from "./masterkey.js";
import { errMsg } from "./transport.js";

export interface VaultFileV1 {
  v: 1;
  salt: string; // base64
  iv: string; // base64
  tag: string; // base64
  data: string; // base64 ciphertext of JSON Record<string, string>
}

export interface VaultFileV2 extends Omit<VaultFileV1, "v"> {
  v: 2;
  kid: string;
}

export type VaultFile = VaultFileV1 | VaultFileV2;

/** The ops surface shared by the local core and the daemon client. */
export interface VaultOps {
  set(ref: string, value: string): void;
  get(ref: string): string;
  has(ref: string): boolean;
  delete(ref: string): void;
  listRefs(): string[];
}

export interface VaultRotationResult {
  oldKid: string;
  newKid: string;
  backupPath: string;
  backend: string;
}

/** kid = first 12 hex chars of sha256(key). Identifies, never reveals. */
export function kidForKey(key: Buffer): string {
  return crypto.createHash("sha256").update(key).digest("hex").slice(0, 12);
}

/** Exact consumer-facing message for a missing ref (kept stable on purpose). */
export function vaultNotFoundMessage(ref: string): string {
  return `Vault: secret '${ref}' not found. Deposit it with: scopegate secret add ${ref}`;
}

function secretsEqual(
  a: Record<string, string>,
  b: Record<string, string>,
): boolean {
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return (
    ka.length === kb.length &&
    ka.every((k, i) => k === kb[i] && a[k] === b[k])
  );
}

/** Best-effort secure delete: overwrite with random bytes, then unlink. */
function secureDeleteFile(p: string): void {
  try {
    fs.writeFileSync(p, crypto.randomBytes(fs.statSync(p).size));
  } catch {
    /* already gone or read-only — unlink below is the real goal */
  }
  try {
    fs.unlinkSync(p);
  } catch {
    /* best effort */
  }
}

function decryptVaultFile(
  f: VaultFile,
  masterKey: Buffer,
): Record<string, string> {
  if (f.v !== 1 && f.v !== 2) {
    throw new Error(`unsupported vault.enc version ${(f as VaultFile).v}`);
  }
  if (f.v === 2) {
    const expected = kidForKey(masterKey);
    if (f.kid !== expected) {
      throw new Error(
        `vault.enc was encrypted with a different master key (kid ${f.kid}, current ${expected}). ` +
          "If a key rotation was interrupted, restore the vault.enc.<kid>.bak backup.",
      );
    }
  }
  const key = crypto.scryptSync(masterKey, Buffer.from(f.salt, "base64"), 32);
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(f.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(f.tag, "base64"));
  const plain = Buffer.concat([
    decipher.update(Buffer.from(f.data, "base64")),
    decipher.final(),
  ]);
  return JSON.parse(plain.toString("utf8")) as Record<string, string>;
}

function encryptVaultFile(
  secrets: Record<string, string>,
  masterKey: Buffer,
): VaultFileV2 {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(masterKey, salt, 32);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(secrets), "utf8")),
    cipher.final(),
  ]);
  return {
    v: 2,
    kid: kidForKey(masterKey),
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64"),
  };
}

function writeVaultFileAtomic(f: VaultFileV2): void {
  const tmp = VAULT_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(f), { mode: 0o600 });
  fs.renameSync(tmp, VAULT_PATH);
}

export class LocalVaultCore implements VaultOps {
  private secrets: Record<string, string> = {};
  private masterKey!: Buffer;
  private store!: MasterKeyStore;
  private fileKid = "legacy";

  private constructor() {}

  static open(opts: { backend?: string } = {}): LocalVaultCore {
    const c = new LocalVaultCore();
    ensureDir();
    c.store = selectMasterKeyStore(opts.backend);
    c.masterKey = c.loadOrCreateMasterKey();
    c.load();
    return c;
  }

  get masterKeyBackend(): string {
    return this.store.backend;
  }

  /** kid of the key that encrypted the current vault.enc ('legacy' for v1). */
  get kid(): string {
    return this.fileKid;
  }

  private loadOrCreateMasterKey(): Buffer {
    const existing = this.store.load();
    if (existing) return existing;

    // Transparent migration (EPIC-05 H4): a legacy master.key file moves into
    // the OS backend on first open, verified, then securely deleted.
    if (this.store.backend !== "file" && fs.existsSync(MASTER_KEY_PATH)) {
      const legacy = selectMasterKeyStore("file").load();
      if (legacy) {
        this.store.store(legacy);
        const verify = this.store.load();
        if (!verify || !verify.equals(legacy)) {
          throw new Error(
            `master key migration to backend '${this.store.backend}' failed verification; ` +
              `${MASTER_KEY_PATH} was left untouched`,
          );
        }
        secureDeleteFile(MASTER_KEY_PATH);
        console.error(
          `[scopegate] master key migrated to '${this.store.backend}' backend; ${MASTER_KEY_PATH} removed.`,
        );
        return legacy;
      }
    }

    const key = crypto.randomBytes(32);
    this.store.store(key);
    return key;
  }

  private load(): void {
    if (!fs.existsSync(VAULT_PATH)) {
      this.secrets = {};
      this.fileKid = kidForKey(this.masterKey);
      return;
    }
    const f = JSON.parse(fs.readFileSync(VAULT_PATH, "utf8")) as VaultFile;
    this.secrets = decryptVaultFile(f, this.masterKey);
    this.fileKid = f.v === 2 ? f.kid : "legacy";
  }

  private persist(): void {
    writeVaultFileAtomic(encryptVaultFile(this.secrets, this.masterKey));
    this.fileKid = kidForKey(this.masterKey);
  }

  set(ref: string, value: string): void {
    this.secrets[ref] = value;
    this.persist();
  }

  get(ref: string): string {
    const v = this.secrets[ref];
    if (v === undefined) throw new Error(vaultNotFoundMessage(ref));
    return v;
  }

  has(ref: string): boolean {
    return this.secrets[ref] !== undefined;
  }

  delete(ref: string): void {
    delete this.secrets[ref];
    this.persist();
  }

  /** Names only — safe to show to agents/humans. Never values. */
  listRefs(): string[] {
    return Object.keys(this.secrets).sort();
  }

  /**
   * Rotate the master key: fresh 32-byte key, full re-encryption of the vault.
   *
   * Order of operations (crash-safe):
   *  1. persist if the vault was never written, then copy vault.enc to
   *     vault.enc.<kid-prev>.bak and VERIFY the backup decrypts with the old
   *     key to exactly the in-memory store — before touching anything.
   *  2. Atomically write vault.enc re-encrypted with the new key (v2, new kid).
   *  3. Store the new key in the target backend (default: current backend).
   *  4. Verify: reload key from the backend and decrypt vault.enc from disk.
   *     Any failure rolls back vault.enc from the backup and, when the target
   *     backend was overwritten, restores the old key there too.
   *  5. On success, a legacy master.key (when the target backend is not file)
   *     is securely deleted — completing the Fase 0 → keychain migration.
   *
   * The .bak is kept after success as the rollback artifact; the caller tells
   * the user where it is.
   *
   * TODO(EPIC-07): emit a signed `vault_key_rotated` audit event once the
   * audit emitter is shared with the vault daemon.
   */
  rotateMasterKey(opts: { backend?: string } = {}): VaultRotationResult {
    if (!fs.existsSync(VAULT_PATH)) this.persist();
    const oldKey = this.masterKey;
    const oldKid = this.fileKid;
    const target = opts.backend
      ? selectMasterKeyStore(opts.backend)
      : this.store;

    // 1. Verified backup.
    const backupPath = `${VAULT_PATH}.${oldKid}.bak`;
    const tmpBak = backupPath + ".tmp";
    fs.writeFileSync(tmpBak, fs.readFileSync(VAULT_PATH), { mode: 0o600 });
    fs.renameSync(tmpBak, backupPath);
    const backupSecrets = decryptVaultFile(
      JSON.parse(fs.readFileSync(backupPath, "utf8")) as VaultFile,
      oldKey,
    );
    if (!secretsEqual(backupSecrets, this.secrets)) {
      fs.rmSync(backupPath, { force: true });
      throw new Error(
        "vault backup verification failed; rotation aborted before any change",
      );
    }

    const restoreFromBackup = (): void => {
      fs.writeFileSync(VAULT_PATH + ".tmp", fs.readFileSync(backupPath), {
        mode: 0o600,
      });
      fs.renameSync(VAULT_PATH + ".tmp", VAULT_PATH);
    };

    // 2. Atomic re-encrypt with the new key.
    const newKey = crypto.randomBytes(32);
    const newKid = kidForKey(newKey);
    writeVaultFileAtomic(encryptVaultFile(this.secrets, newKey));

    // 3. Store the new key. The old key is still in `oldKey`/the old backend
    //    slot until this succeeds, so a failure here is fully recoverable.
    //    (Compare by backend NAME: a forced backend is a fresh instance, but
    //    the same backend name means the same underlying storage slot.)
    const sameSlot = target.backend === this.store.backend;
    try {
      target.store(newKey);
    } catch (e) {
      try {
        if (sameSlot) target.store(oldKey);
        restoreFromBackup();
      } catch {
        /* primary error below is what matters */
      }
      throw new Error(
        `rotation failed while storing the new key in backend '${target.backend}': ${errMsg(e)}. ` +
          `vault.enc was restored from ${backupPath}.`,
      );
    }

    // 4. Verify re-open from disk + backend before committing.
    try {
      const stored = target.load();
      if (!stored || !stored.equals(newKey)) {
        throw new Error("backend did not return the new key after store()");
      }
      const reread = decryptVaultFile(
        JSON.parse(fs.readFileSync(VAULT_PATH, "utf8")) as VaultFile,
        stored,
      );
      if (!secretsEqual(reread, this.secrets)) {
        throw new Error("re-opened vault does not match the in-memory store");
      }
    } catch (e) {
      // Roll back BOTH halves; ignore secondary errors but report them.
      let rollbackNote = "";
      try {
        if (sameSlot) target.store(oldKey);
        restoreFromBackup();
      } catch (rb) {
        rollbackNote = ` ROLLBACK ALSO FAILED: ${errMsg(rb)} — restore manually: rename ${backupPath} over ${VAULT_PATH}.`;
      }
      throw new Error(
        `rotation failed verification (${errMsg(e)}); rolled back to the previous key.` +
          (sameSlot
            ? ""
            : ` Note: the new key may remain stored (unused) in backend '${target.backend}'.`) +
          rollbackNote,
      );
    }

    // 5. Commit + finish the keychain migration when applicable.
    this.store = target;
    this.masterKey = newKey;
    this.fileKid = newKid;
    if (target.backend !== "file" && fs.existsSync(MASTER_KEY_PATH)) {
      secureDeleteFile(MASTER_KEY_PATH);
    }
    return { oldKid, newKid, backupPath, backend: target.backend };
  }
}

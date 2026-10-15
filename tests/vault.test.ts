import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
  // These tests exercise the legacy local/file behavior specifically; the
  // daemon transport and OS keychain backends are covered in vaultd.test.ts.
  process.env.SCOPEGATE_VAULT_MODE = "local";
  process.env.SCOPEGATE_MASTER_KEY_BACKEND = "file";
});

afterEach(() => {
  delete process.env.SCOPEGATE_VAULT_MODE;
  delete process.env.SCOPEGATE_MASTER_KEY_BACKEND;
  cleanupTempHome(home);
});

describe("Vault", () => {
  it("roundtrips set/get and persists across instances", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    Vault.open().set("github_token", "ghp_secretvalue");
    // A fresh instance must decrypt the same value from disk.
    expect(Vault.open().get("github_token")).toBe("ghp_secretvalue");
  });

  it("never stores plaintext secrets on disk", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const { VAULT_PATH } = await import("../src/config/config.js");
    Vault.open().set("api_key", "supersecret123");
    const raw = fs.readFileSync(VAULT_PATH, "utf8");
    expect(raw).not.toContain("supersecret123");
    const parsed = JSON.parse(raw);
    // Writes are VaultFile v2 since EPIC-05 (kid + AES-256-GCM fields).
    expect(parsed.v).toBe(2);
    expect(parsed.kid).toBeTruthy();
    expect(parsed.salt).toBeTruthy();
    expect(parsed.iv).toBeTruthy();
    expect(parsed.tag).toBeTruthy();
    expect(parsed.data).toBeTruthy();
  });

  it("detects ciphertext tampering (AES-256-GCM auth tag)", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const { VAULT_PATH } = await import("../src/config/config.js");
    Vault.open().set("k", "v");
    const f = JSON.parse(fs.readFileSync(VAULT_PATH, "utf8"));
    f.data = Buffer.from("tampered-ciphertext").toString("base64");
    fs.writeFileSync(VAULT_PATH, JSON.stringify(f));
    expect(() => Vault.open()).toThrow();
  });

  it("detects auth-tag tampering", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const { VAULT_PATH } = await import("../src/config/config.js");
    Vault.open().set("k", "v");
    const f = JSON.parse(fs.readFileSync(VAULT_PATH, "utf8"));
    f.tag = Buffer.alloc(16).toString("base64");
    fs.writeFileSync(VAULT_PATH, JSON.stringify(f));
    expect(() => Vault.open()).toThrow();
  });

  it("fails to decrypt with a different master key", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const { MASTER_KEY_PATH } = await import("../src/config/config.js");
    Vault.open().set("k", "v");
    fs.writeFileSync(MASTER_KEY_PATH, "00".repeat(32) + "\n", { mode: 0o600 });
    expect(() => Vault.open()).toThrow();
  });

  it("listRefs is sorted and has() reflects contents", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const v = Vault.open();
    expect(v.listRefs()).toEqual([]);
    expect(v.has("x")).toBe(false);
    v.set("beta", "2");
    v.set("alpha", "1");
    expect(v.listRefs()).toEqual(["alpha", "beta"]);
    expect(v.has("alpha")).toBe(true);
  });

  it("get() on a missing ref throws an actionable error", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const v = Vault.open();
    expect(() => v.get("nope")).toThrow(/scopegate secret add nope/);
  });

  it("delete() removes the ref durably", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const v = Vault.open();
    v.set("a", "1");
    v.delete("a");
    expect(v.has("a")).toBe(false);
    expect(Vault.open().has("a")).toBe(false);
  });

  it("writes only inside SCOPEGATE_HOME (never the real HOME)", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    Vault.open().set("x", "y");
    expect(fs.existsSync(path.join(home, "vault.enc"))).toBe(true);
    expect(fs.existsSync(path.join(home, "master.key"))).toBe(true);
  });

  it("writes vault.enc and master.key with mode 0600 (posix)", async () => {
    if (process.platform === "win32") return; // mode bits not enforced on Windows
    const { Vault } = await import("../src/vault/vault.js");
    const { VAULT_PATH, MASTER_KEY_PATH } = await import(
      "../src/config/config.js"
    );
    Vault.open().set("x", "y");
    expect(fs.statSync(VAULT_PATH).mode & 0o777).toBe(0o600);
    expect(fs.statSync(MASTER_KEY_PATH).mode & 0o777).toBe(0o600);
  });
});

describe("copia antes de borrar (E6)", () => {
  it("deja un .bak que, restaurado, devuelve el ref borrado", async () => {
    // Sin esto, `delete` reescribe el fichero sin copia: si el proceso muere
    // entre el `rm` y el `add` de un bootstrap declarativo, el ref se pierde
    // para siempre (no hay `secret get`).
    const { Vault } = await import("../src/vault/vault.js");
    const { VAULT_PATH } = await import("../src/config/config.js");
    const v = Vault.open();
    v.set("github_token", "ghp_secretvalue");
    v.set("otro_ref", "valor");
    v.delete("github_token");

    const bak = `${VAULT_PATH}.pre-delete-github_token.bak`;
    expect(fs.existsSync(bak)).toBe(true);

    // La prueba que importa: restaurar la copia recupera el ref.
    fs.copyFileSync(bak, VAULT_PATH);
    const restaurado = Vault.open();
    expect(restaurado.get("github_token")).toBe("ghp_secretvalue");
    expect(restaurado.get("otro_ref")).toBe("valor");
  });

  it("borrar un ref que no existe no escribe ninguna copia", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const { VAULT_PATH } = await import("../src/config/config.js");
    const v = Vault.open();
    v.set("existe", "v");
    v.delete("no_existe");

    const dir = path.dirname(VAULT_PATH);
    const baks = fs.readdirSync(dir).filter((f) => f.includes(".pre-delete-"));
    expect(baks).toEqual([]);
  });

  it("la copia se nombra POR REF y cada copia contiene el ref que protege", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const { VAULT_PATH } = await import("../src/config/config.js");
    const v = Vault.open();
    v.set("a", "1");
    v.set("b", "2");
    v.delete("a");
    v.delete("b");

    const dir = path.dirname(VAULT_PATH);
    const baks = fs.readdirSync(dir).filter((f) => f.includes(".pre-delete-")).sort();
    expect(baks).toContain("vault.enc.pre-delete-a.bak");
    expect(baks).toContain("vault.enc.pre-delete-b.bak");

    // Propiedad REAL, y la única que promete el diseño: la copia de un ref
    // contiene ese ref. El orden importa y conviene dejarlo escrito —
    // `pre-delete-a.bak` se tomó cuando el blob era {a,b} y por tanto recupera los
    // dos; `pre-delete-b.bak` se tomó cuando ya faltaba `a`, así que sólo trae `b`.
    // Para una pérdida multi-ref, la copia que recupera más es la del PRIMER
    // borrado del lote.
    fs.copyFileSync(`${VAULT_PATH}.pre-delete-a.bak`, VAULT_PATH);
    const desdeA = Vault.open();
    expect(desdeA.get("a")).toBe("1");
    expect(desdeA.get("b")).toBe("2");

    fs.copyFileSync(`${VAULT_PATH}.pre-delete-b.bak`, VAULT_PATH);
    const desdeB = Vault.open();
    expect(desdeB.get("b")).toBe("2");
  });
});

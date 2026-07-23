/**
 * `scopegate secret add|rm|ls` — the HUMAN-only path for secret values.
 *
 * Values are read from a hidden TTY prompt or piped stdin, never from argv
 * (argv leaks via shell history / process lists) and never through the
 * agent's chat context.
 */
import readline from "node:readline";
import { Vault } from "../vault/vault.js";

export async function secretAdd(ref: string): Promise<void> {
  validateRef(ref);
  const value = await readSecretValue(`Value for '${ref}' (input hidden): `);
  if (!value) {
    console.error("Empty value; aborted.");
    process.exit(1);
  }
  Vault.open().set(ref, value.trim());
  console.log(`[scopegate] secret '${ref}' stored (encrypted at rest).`);
}

export function secretRm(ref: string): void {
  validateRef(ref);
  const vault = Vault.open();
  if (!vault.has(ref)) {
    console.error(`[scopegate] no secret named '${ref}'. See what's stored: scopegate secret ls`);
    process.exit(1);
  }
  vault.delete(ref);
  console.log(`[scopegate] secret '${ref}' removed.`);
}

export function secretLs(): void {
  const refs = Vault.open().listRefs();
  if (refs.length === 0) console.log("(vault empty)");
  else refs.forEach((r) => console.log(r));
}

function validateRef(ref: string): void {
  if (!/^[a-z0-9_][a-z0-9_.:-]*$/i.test(ref)) {
    console.error(
      "Invalid ref name. Use letters, digits, '_', '-', '.', ':' (e.g. github_token, oauth2:notion).",
    );
    process.exit(1);
  }
}

function readSecretValue(prompt: string): Promise<string> {
  // Piped stdin (e.g. `echo $TOKEN | scopegate secret add github_token`)
  if (!process.stdin.isTTY) {
    return new Promise((resolve) => {
      let data = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (c) => (data += c));
      process.stdin.on("end", () => resolve(data));
    });
  }
  // Interactive: hidden input
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    const stdout = process.stdout;
    process.stdout.write(prompt);
    const onData = (char: Buffer) => {
      const s = char.toString();
      if (s === "\n" || s === "\r" || s === "\u0004") return;
      readline.moveCursor(stdout, -s.length, 0);
      stdout.write("*".repeat(s.length));
    };
    process.stdin.on("data", onData);
    rl.question("", (answer) => {
      process.stdin.off("data", onData);
      rl.close();
      stdout.write("\n");
      resolve(answer);
    });
  });
}

/**
 * Structured rule editing (`/admin/policies/rules`).
 *
 * The properties under test are the ones the raw YAML endpoint does not have
 * and that a console makes newly reachable: comments survive an edit, a stale
 * writer gets a 409 instead of clobbering, and widening a human gate is never
 * silent. See src/gateway/policy-rules.ts for the reasoning.
 */
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

// A policies file that looks like production: comments carrying operational
// reasoning, a hard deny floor, and a specific human gate under a wide
// auto-approve — the pair whose precedence must not be broken by a toggle.
const SEED = `version: 1

# Hard floor: never editable from the console.
limits:
  max_ttl: 1h
  deny:
    - "*delete_repository*"
    - "*merge_pull_request*"

agents:
  # The worker's default identity. Reads are cheap, writes are gated.
  nexgen-kimi:
    default_ttl: 15m
    capabilities:
      # Wide auto-approve for ordinary domain calls.
      - { match: "nexgen:call:*", auto_approve: true, ttl: 15m }
      # A PR draft is a write to a human's repo: it stays gated on purpose.
      # This rule wins over the glob above because it is more specific.
      - { match: "nexgen:call:github_create_pr_draft", require: human_approval }
`;

describe("policy rules API layer", () => {
  let home: string;
  let policiesPath: string;

  beforeEach(() => {
    home = useTempHome();
    policiesPath = path.join(home, "policies.yaml");
    fs.writeFileSync(policiesPath, SEED);
  });

  afterEach(() => {
    cleanupTempHome(home);
  });

  it("reads rules and flags the ones a hard deny already kills", async () => {
    const { readRules } = await import("../src/gateway/policy-rules.js");
    const snap = await readRules();

    expect(snap.denyGlobs).toEqual(["*delete_repository*", "*merge_pull_request*"]);
    expect(snap.etag).toMatch(/^[0-9a-f]{16}$/);
    const agent = snap.agents.find((a) => a.agentId === "nexgen-kimi")!;
    expect(agent.defaultTtl).toBe("15m");
    expect(agent.rules.map((r) => r.match)).toEqual([
      "nexgen:call:*",
      "nexgen:call:github_create_pr_draft",
    ]);
    expect(agent.rules[1].require).toBe("human_approval");
    // Nothing in the seed collides with the deny floor.
    expect(agent.rules.every((r) => r.deniedByGlob === undefined)).toBe(true);
  });

  it("keeps comments across an edit", async () => {
    // The failure this prevents: YAML.parse + stringify silently deletes every
    // comment, so the console's first toggle would erase the operational
    // documentation that explains why the human gate exists.
    const { applyUpsert, readPoliciesRaw } = await import("../src/gateway/policy-rules.js");
    const res = await applyUpsert(readPoliciesRaw(), {
      agentId: "nexgen-kimi",
      match: "nexgen:call:huly_reply",
      auto_approve: true,
      ttl: "15m",
    });
    if ("error" in res) throw new Error(`unexpected refusal: ${res.error.message}`);

    expect(res.raw).toContain("# Hard floor: never editable from the console.");
    expect(res.raw).toContain("# A PR draft is a write to a human's repo");
    expect(res.raw).toContain("# Wide auto-approve for ordinary domain calls.");
    // And the new rule is there, appended last so it cannot outrank the
    // first-match-wins rules an operator wrote before it.
    const lines = res.raw.split("\n").filter((l) => l.includes("match:"));
    expect(lines[lines.length - 1]).toContain("nexgen:call:huly_reply");
  });

  it("refuses a rule that a hard deny glob already kills", async () => {
    const { applyUpsert, readPoliciesRaw } = await import("../src/gateway/policy-rules.js");
    const res = await applyUpsert(readPoliciesRaw(), {
      agentId: "nexgen-kimi",
      match: "github:call:merge_pull_request",
      auto_approve: true,
    });
    if (!("error" in res)) throw new Error("expected a refusal");
    expect(res.error.kind).toBe("invalid");
    expect(res.error.message).toContain("*merge_pull_request*");
    // The message must say WHY, not just no: dead config that reads as a grant
    // is worse than an error.
    expect(res.error.message).toMatch(/never grant/i);
  });

  it("refuses to auto-approve over an existing human gate without acknowledgement", async () => {
    const { applyUpsert, readPoliciesRaw } = await import("../src/gateway/policy-rules.js");
    const raw = readPoliciesRaw();

    // `nexgen:call:*` is wider than the gated `nexgen:call:github_create_pr_draft`.
    const refused = await applyUpsert(raw, {
      agentId: "nexgen-kimi",
      match: "nexgen:call:*",
      auto_approve: true,
      ttl: "15m",
    });
    if (!("error" in refused)) throw new Error("expected a refusal");
    expect(refused.error.kind).toBe("needs_acknowledge");
    expect((refused.error as { widens: string[] }).widens).toContain(
      "nexgen:call:github_create_pr_draft",
    );

    // With the acknowledgement it goes through — the human confirmed the
    // consequence, which is the whole point of the guard.
    const accepted = await applyUpsert(raw, {
      agentId: "nexgen-kimi",
      match: "nexgen:call:*",
      auto_approve: true,
      ttl: "15m",
      acknowledge_widening: true,
    });
    expect("error" in accepted).toBe(false);
  });

  it("does not cry wolf on a narrower or unrelated rule", async () => {
    const { applyUpsert, readPoliciesRaw } = await import("../src/gateway/policy-rules.js");
    const raw = readPoliciesRaw();

    // Narrower than the gate, different capability: no widening.
    const narrow = await applyUpsert(raw, {
      agentId: "nexgen-kimi",
      match: "nexgen:call:huly_issue_read",
      auto_approve: true,
    });
    expect("error" in narrow).toBe(false);

    // A rule that only requires approval never widens anything.
    const gated = await applyUpsert(raw, {
      agentId: "nexgen-kimi",
      match: "railway:deploy:*",
      require: "human_approval",
    });
    expect("error" in gated).toBe(false);
  });

  it("rejects contradictory and incomplete rules", async () => {
    const { applyUpsert } = await import("../src/gateway/policy-rules.js");
    const raw = "";
    for (const bad of [
      { agentId: "", match: "a:b" },
      { agentId: "x", match: "" },
      { agentId: "x", match: "a:b", auto_approve: true, require: "human_approval" as const },
    ]) {
      const res = await applyUpsert(raw, bad);
      if (!("error" in res)) throw new Error(`expected refusal for ${JSON.stringify(bad)}`);
      expect(res.error.kind).toBe("invalid");
    }
  });

  it("upsert replaces in place instead of duplicating a match", async () => {
    const { applyUpsert, readPoliciesRaw } = await import("../src/gateway/policy-rules.js");
    const res = await applyUpsert(readPoliciesRaw(), {
      agentId: "nexgen-kimi",
      match: "nexgen:call:github_create_pr_draft",
      require: "human_approval",
      ttl: "30m",
    });
    if ("error" in res) throw new Error(res.error.message);
    const occurrences = res.raw.split("nexgen:call:github_create_pr_draft").length - 1;
    expect(occurrences).toBe(1);
    expect(res.raw).toContain("30m");
  });

  it("delete removes one rule and reports a miss instead of silently passing", async () => {
    const { applyDelete, readPoliciesRaw } = await import("../src/gateway/policy-rules.js");
    const raw = readPoliciesRaw();

    const gone = await applyDelete(raw, "nexgen-kimi", {
      match: "nexgen:call:github_create_pr_draft",
    });
    if ("error" in gone) throw new Error(gone.error.message);
    expect(gone.raw).not.toContain("nexgen:call:github_create_pr_draft");
    expect(gone.raw).toContain("nexgen:call:*");
    // Comments outside the deleted node survive.
    expect(gone.raw).toContain("# Hard floor: never editable from the console.");

    const missing = await applyDelete(raw, "nexgen-kimi", { match: "does:not:exist" });
    if (!("error" in missing)) throw new Error("expected not_found");
    expect(missing.error.kind).toBe("not_found");

    const noAgent = await applyDelete(raw, "ghost", { match: "nexgen:call:*" });
    if (!("error" in noAgent)) throw new Error("expected not_found");
    expect(noAgent.error.kind).toBe("not_found");
  });

  it("commit validates, backs up, writes 0600 and reloads", async () => {
    const { applyUpsert, commitRules, readPoliciesRaw, currentEtag } = await import(
      "../src/gateway/policy-rules.js"
    );
    const before = currentEtag();
    const edit = await applyUpsert(readPoliciesRaw(), {
      agentId: "nexgen-kimi",
      match: "nexgen:call:huly_reply",
      auto_approve: true,
      ttl: "15m",
    });
    if ("error" in edit) throw new Error(edit.error.message);

    let reloaded = false;
    const res = await commitRules(edit.raw, async () => {
      reloaded = true;
    });
    if (!res.ok) throw new Error(res.error.message);

    expect(reloaded).toBe(true);
    expect(res.etag).not.toBe(before);
    expect(currentEtag()).toBe(res.etag);
    expect(fs.existsSync(`${policiesPath}.prev`)).toBe(true);
    expect(fs.readFileSync(`${policiesPath}.prev`, "utf8")).toBe(SEED);
    expect(fs.readFileSync(policiesPath, "utf8")).toContain("huly_reply");
  });

  it("commit refuses output the engine would reject, leaving the file untouched", async () => {
    // A structured edit producing invalid policies is a bug in this layer, not
    // user error — but it must never reach disk.
    const { commitRules } = await import("../src/gateway/policy-rules.js");
    const res = await commitRules("version: 2\nagents: {}\n", async () => {
      throw new Error("reload must not run on a rejected commit");
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error.kind).toBe("invalid");
    expect(fs.readFileSync(policiesPath, "utf8")).toBe(SEED);
  });

  it("etag changes only when the bytes change (the If-Match contract)", async () => {
    const { currentEtag, etagOf, readPoliciesRaw } = await import(
      "../src/gateway/policy-rules.js"
    );
    const a = currentEtag();
    expect(etagOf(readPoliciesRaw())).toBe(a);
    // A human editing the raw file moves the etag → a console write holding the
    // old one must 409 rather than overwrite.
    fs.writeFileSync(policiesPath, SEED + "\n# touched by a human\n");
    expect(currentEtag()).not.toBe(a);
  });

  it("globWidens is biased toward asking rather than missing a gate", async () => {
    const { globWidens } = await import("../src/gateway/policy-rules.js");
    // The production pair.
    expect(globWidens("nexgen:call:*", "nexgen:call:github_create_pr_draft")).toBe(true);
    expect(globWidens("*", "nexgen:call:github_create_pr_draft")).toBe(true);
    // Same glob is not widening.
    expect(globWidens("nexgen:call:*", "nexgen:call:*")).toBe(false);
    // A literal (no wildcard) cannot widen anything.
    expect(globWidens("nexgen:call:huly_reply", "nexgen:call:github_create_pr_draft")).toBe(false);
    // A glob over a different namespace does not touch the gate.
    expect(globWidens("railway:deploy:*", "nexgen:call:github_create_pr_draft")).toBe(false);
  });
});

/**
 * Shadowing. Not a hypothetical: this is the shape of the policy actually
 * running on the kimi-tag gateways, discovered by calling the new endpoint
 * against Railway. Production guards the first rule with
 * `when: { branch: "kimi/*" }` so the gate below stays reachable; staging has
 * the same rule WITHOUT the guard, which makes its human gate dead code.
 * Nothing in the system reported that before.
 */
describe("reglas ensombrecidas", () => {
  let home: string;
  let policiesPath: string;

  beforeEach(() => {
    home = useTempHome();
    policiesPath = path.join(home, "policies.yaml");
  });
  afterEach(() => cleanupTempHome(home));

  const write = (rules: string) =>
    fs.writeFileSync(
      policiesPath,
      `version: 1\nagents:\n  nexgen-kimi:\n    default_ttl: 15m\n    capabilities:\n${rules}`,
    );

  it("marca el gate humano muerto detrás de un auto_approve sin guardia (staging)", async () => {
    write(
      `      - { match: "nexgen:call:github_create_pr_draft", auto_approve: true, ttl: 15m }\n` +
        `      - { match: "nexgen:call:github_create_pr_draft", require: human_approval }\n` +
        `      - { match: "nexgen:call:*", auto_approve: true, ttl: 15m }\n`,
    );
    const { readRules } = await import("../src/gateway/policy-rules.js");
    const rules = (await readRules()).agents[0].rules;

    expect(rules[0].shadowedBy).toBeUndefined();
    // El gate humano es inalcanzable: primer match gana.
    expect(rules[1].shadowedBy).toBe(0);
    // Y el glob ancho también queda tapado por la regla específica anterior?
    // No: `nexgen:call:*` es MÁS ancho, la anterior no lo cubre.
    expect(rules[2].shadowedBy).toBeUndefined();
  });

  it("expone el guardia `when` — sin el, la politica se lee al reves", async () => {
    // Este es el fallo que este test fija: la primera version de RuleView NO
    // devolvia `when`, y quien leyo la respuesta del endpoint contra el gateway
    // real concluyo que staging habia perdido el guardia y tenia un gate humano
    // muerto. Era falso: el guardia estaba, solo era invisible.
    write(
      `      - { match: "nexgen:call:github_create_pr_draft", when: { branch: "kimi/*" }, auto_approve: true, ttl: 15m }
` +
        `      - { match: "nexgen:call:github_create_pr_draft", require: human_approval }
`,
    );
    const { readRules } = await import("../src/gateway/policy-rules.js");
    const rules = (await readRules()).agents[0].rules;
    expect(rules[0].when).toEqual({ branch: "kimi/*" });
    expect(rules[1].when).toBeUndefined();
  });

  it("no deja editar una regla con guardia `when` (borraria el guardia)", async () => {
    write(
      `      - { match: "nexgen:call:github_create_pr_draft", when: { branch: "kimi/*" }, auto_approve: true, ttl: 15m }
`,
    );
    const { applyUpsert, readPoliciesRaw } = await import("../src/gateway/policy-rules.js");
    // Un toggle sobre esa capacidad reemplazaria el nodo entero y dejaria el
    // auto_approve SIN guardia: de "solo en ramas kimi/*" a "siempre".
    const res = await applyUpsert(readPoliciesRaw(), {
      agentId: "nexgen-kimi",
      match: "nexgen:call:github_create_pr_draft",
      auto_approve: true,
      ttl: "15m",
    });
    if (!("error" in res)) throw new Error("expected a refusal");
    expect(res.error.kind).toBe("invalid");
    expect(res.error.message).toMatch(/when/);
    expect(res.error.message).toMatch(/widen/i);
  });

  it("un auto_approve con guardia `when` NO ensombrece lo que sigue (producción)", async () => {
    write(
      `      - { match: "nexgen:call:github_create_pr_draft", when: { branch: "kimi/*" }, auto_approve: true, ttl: 15m }\n` +
        `      - { match: "nexgen:call:github_create_pr_draft", require: human_approval }\n`,
    );
    const { readRules } = await import("../src/gateway/policy-rules.js");
    const rules = (await readRules()).agents[0].rules;
    // La regla guardada puede no casar en tiempo de llamada, así que el gate
    // sigue vivo. Marcarlo como muerto seria una falsa alarma.
    expect(rules[1].shadowedBy).toBeUndefined();
  });

  it("un glob ancho ensombrece las reglas específicas que van detrás", async () => {
    write(
      `      - { match: "nexgen:call:*", auto_approve: true, ttl: 15m }\n` +
        `      - { match: "nexgen:call:github_create_pr_draft", require: human_approval }\n`,
    );
    const { readRules } = await import("../src/gateway/policy-rules.js");
    const rules = (await readRules()).agents[0].rules;
    expect(rules[1].shadowedBy).toBe(0);
  });

  it("borrar por match se niega cuando hay duplicados; por índice funciona", async () => {
    write(
      `      - { match: "nexgen:call:github_create_pr_draft", auto_approve: true, ttl: 15m }\n` +
        `      - { match: "nexgen:call:github_create_pr_draft", require: human_approval }\n`,
    );
    const { applyDelete, readPoliciesRaw } = await import("../src/gateway/policy-rules.js");
    const raw = readPoliciesRaw();

    // Ambiguo: elegir uno al azar podría borrar el gate humano en vez de la
    // regla que lo tapa.
    const ambiguous = await applyDelete(raw, "nexgen-kimi", {
      match: "nexgen:call:github_create_pr_draft",
    });
    if (!("error" in ambiguous)) throw new Error("expected a refusal");
    expect(ambiguous.error.kind).toBe("invalid");
    expect(ambiguous.error.message).toMatch(/indexes 0, 1/);

    // Por índice: quita el auto_approve y deja vivo el gate.
    const byIndex = await applyDelete(raw, "nexgen-kimi", { index: 0 });
    if ("error" in byIndex) throw new Error(byIndex.error.message);
    expect(byIndex.raw).toContain("human_approval");
    expect(byIndex.raw).not.toContain("auto_approve");

    // Índice fuera de rango: 404, nunca un no-op silencioso.
    const oob = await applyDelete(raw, "nexgen-kimi", { index: 9 });
    if (!("error" in oob)) throw new Error("expected not_found");
    expect(oob.error.kind).toBe("not_found");
  });
});

/**
 * M7: embeddable library API (scopegate / scopegate/testkit).
 *
 *   - createGatewayServer boots the real pieces in-process (no subprocess,
 *     no daemons, throws instead of process.exit).
 *   - bootFakeGateway wires an MCP client over InMemoryTransport: the full
 *     management + proxied surface works without real credentials.
 *   - the published surface exists in dist (api.js, api.d.ts, testkit).
 *
 * Isolation: throwaway SCOPEGATE_HOME via helpers BEFORE any src import
 * (dynamic imports only — config paths resolve at module load).
 */
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  cleanupTempHome(home);
});

describe("M7 embeddable API", () => {
  it("bootFakeGateway serves the full MCP surface in-process", async () => {
    const { bootFakeGateway } = await import("../src/testkit/index.js");
    const handle = await bootFakeGateway();
    try {
      const { tools } = await handle.client.listTools();
      const names = tools.map((t) => t.name);
      expect(names).toContain("scopegate_request_capability");
      expect(names).toContain("fakegit__whoami");
      expect(names).toContain("fakegit__echo");

      // Proxied call with the auto-approve rule: policy passes, vault secret
      // reaches the upstream env.
      const res = await handle.client.callTool({ name: "fakegit__whoami", arguments: {} });
      expect(res.isError).not.toBe(true);
      expect((res.content as { text: string }[])[0].text).toContain("authenticated=true");

      // Echo round-trips args through the gateway.
      const echo = await handle.client.callTool({
        name: "fakegit__echo",
        arguments: { message: "hola-m7" },
      });
      expect((echo.content as { text: string }[])[0].text).toBe("hola-m7");

      // The management surface reports the live grant.
      const caps = await handle.client.callTool({
        name: "scopegate_list_capabilities",
        arguments: {},
      });
      expect((caps.content as { text: string }[])[0].text).toContain("fakegit:call:whoami");
    } finally {
      await handle.close();
    }
  }, 30_000);

  it("home mismatch is a loud error, never a silent wrong-home boot", async () => {
    const { createGatewayServer } = await import("../src/api.js");
    await expect(
      createGatewayServer({ home: "C:/definitely/not/the/resolved/home" }),
    ).rejects.toThrow(/SCOPEGATE_HOME/);
  });

  it("the published dist surface exists (api.js + types + testkit)", () => {
    const dist = path.join(process.cwd(), "dist");
    expect(fs.existsSync(path.join(dist, "api.js"))).toBe(true);
    expect(fs.existsSync(path.join(dist, "api.d.ts"))).toBe(true);
    expect(fs.existsSync(path.join(dist, "testkit", "index.js"))).toBe(true);
    expect(fs.existsSync(path.join(dist, "testkit", "index.d.ts"))).toBe(true);
    expect(fs.existsSync(path.join(dist, "testkit", "fake-upstream.js"))).toBe(true);
  });
});

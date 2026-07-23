/**
 * Test isolation primitive: every test gets its own throwaway SCOPEGATE_HOME
 * (a mkdtemp dir) so the real ~/.scopegate is NEVER touched.
 *
 * src/config/config.ts resolves paths from process.env.SCOPEGATE_HOME at
 * module load time, so after changing the env var we must force vitest to
 * re-evaluate the src modules — that is what vi.resetModules() is for.
 * Tests therefore import src modules dynamically AFTER calling useTempHome().
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { vi } from "vitest";

export function useTempHome(): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-test-"));
  process.env.SCOPEGATE_HOME = home;
  vi.resetModules();
  return home;
}

export function cleanupTempHome(home: string): void {
  delete process.env.SCOPEGATE_HOME;
  vi.resetModules();
  fs.rmSync(home, { recursive: true, force: true });
}

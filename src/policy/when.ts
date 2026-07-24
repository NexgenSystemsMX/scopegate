/**
 * M6: arg-aware policy guards — shared by the engine (rule evaluation) and
 * the grant store (coverage checks), kept dependency-free to avoid cycles.
 */
import picomatch from "picomatch";

/**
 * Evaluate a rule's `when` clause against the tool call's args. String
 * patterns match as picomatch globs; numbers/booleans by strict equality.
 * Undefined args (e.g. scopegate_request_capability, which has none yet)
 * never satisfy a `when` — the rule simply does not match.
 */
export function matchesWhen(
  when: Record<string, string | number | boolean>,
  args: Record<string, unknown> | undefined,
): boolean {
  if (args === undefined) return false;
  for (const [argName, pattern] of Object.entries(when)) {
    const value = args[argName];
    if (typeof pattern === "string") {
      if (typeof value !== "string" || !picomatch.isMatch(value, pattern)) return false;
    } else if (value !== pattern) {
      return false;
    }
  }
  return true;
}

/**
 * Read/write classification of proxied tools (mejoras #9, #4, #6, #10).
 *
 * The gateway needs to know which calls can CHANGE state upstream: recall
 * views (#9) report "writes effected", capability plans (#4) split reads from
 * writes for blast-radius display, idempotency (#6) dedupes writes, and
 * taint tracking (#10) degrades cross-upstream writes.
 *
 * Resolution order (first hit wins):
 *   1. Upstream manifest override: `side_effects: { "<tool>": "read"|"write" }`
 *      in the upstream's config (operator-curated, always trusted).
 *   2. Curated prefix table per native bridge.
 *   3. Glob heuristic on the tool name (create_/update_/delete_/send_/deploy_/
 *      write_/merge_/set_/add_/remove_/redeploy_).
 *   4. Default: READ (fail-safe for the recall/idempotency use cases; the
 *      taint gate uses its own stricter default).
 */

const WRITE_PREFIXES = [
  "create_",
  "update_",
  "delete_",
  "remove_",
  "send_",
  "deploy_",
  "redeploy_",
  "write_",
  "merge_",
  "set_",
  "add_",
  "put_",
  "post_",
  "patch_",
  "insert_",
  "upsert_",
  "execute_",
  "run_",
  "apply_",
  "cancel_",
  "close_",
];

/** Curated writes of the native bridges (exact names, win over prefixes). */
const CURATED_WRITES: Record<string, string[]> = {
  huly: [
    "create_issue",
    "update_issue",
    "create_comment",
    "create_project",
    "send_message",
  ],
  railway: ["deploy", "redeploy"],
  cloudflare: ["dns_create", "dns_update", "dns_delete"],
  google: ["gmail_send", "calendar_create"],
};

/** Curated reads that would otherwise match a write prefix (exact names). */
const CURATED_READS: Record<string, string[]> = {
  railway: ["get_logs", "service_status", "list_services", "variables_list", "domain_status"],
};

/**
 * True when the tool is classified as a WRITE for the given upstream.
 * `manifestOverrides` is the upstream config's `side_effects` map (optional).
 */
export function isWriteTool(
  upstream: string,
  toolName: string,
  manifestOverrides?: Record<string, "read" | "write">,
): boolean {
  const override = manifestOverrides?.[toolName];
  if (override === "write") return true;
  if (override === "read") return false;
  if ((CURATED_READS[upstream] ?? []).includes(toolName)) return false;
  if ((CURATED_WRITES[upstream] ?? []).includes(toolName)) return true;
  return WRITE_PREFIXES.some((p) => toolName.startsWith(p) || toolName.includes("_" + p));
}

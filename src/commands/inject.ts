/**
 * `scopegate inject` — governed secret materialization into files (M10).
 *
 *   scopegate inject --ref moonshot_api_key --out ~/.kimi/config.toml \
 *     --template '[model]\napi_key = "{{secret}}"'
 *   scopegate inject --refresh ~/.kimi/config.toml
 *
 * The capability `vault:inject:<ref>` escalates to human approval BY DEFAULT
 * (the engine's inverted default) — a policy rule must explicitly
 * auto_approve to lift it. Output is one JSON line (agents parse it);
 * exit 0 on materialized, 1 on denied/error, 2 on pending approval.
 */
import { materializeSecret, refreshInject } from "../inject/inject.js";

export interface InjectCliOpts {
  ref?: string;
  out?: string;
  template?: string;
  templateFile?: string;
  refresh?: string;
}

export async function runInject(opts: InjectCliOpts): Promise<void> {
  const agentId = process.env.SCOPEGATE_AGENT_ID ?? "inject";
  try {
    if (opts.refresh) {
      const res = await refreshInject(opts.refresh, agentId);
      emit(res);
      process.exit(exitCode(res));
    }
    if (!opts.ref || !opts.out) {
      console.error(
        "usage: scopegate inject --ref <secretRef> --out <path> [--template <inline> | --template-file <path>] " +
          "| scopegate inject --refresh <path>",
      );
      process.exit(1);
    }
    if (opts.template && opts.templateFile) {
      console.error("--template and --template-file are mutually exclusive");
      process.exit(1);
    }
    const res = await materializeSecret({
      ref: opts.ref,
      out: opts.out,
      template: opts.template,
      templateFile: opts.templateFile,
      agentId,
    });
    emit(res);
    process.exit(exitCode(res));
  } catch (e) {
    console.log(JSON.stringify({ ok: false, status: "error", reason: (e as Error).message }));
    process.exit(1);
  }
}

function emit(res: { ok: boolean; status: string; approvalId?: string; reason?: string }): void {
  console.log(JSON.stringify(res));
  if (res.status === "pending_human_approval" && res.approvalId) {
    console.error(
      `pending human approval — run: scopegate approve ${res.approvalId} (then re-run the inject)`,
    );
  }
}

function exitCode(res: { status: string }): number {
  if (res.status === "materialized") return 0;
  if (res.status === "pending_human_approval") return 2;
  return 1;
}

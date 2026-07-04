import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Args, Command, Flags } from "@oclif/core";
import { parse as parseYaml } from "yaml";
import { ClaudeAdapter, CodexAdapter, type EngineId } from "../../adapters/index.js";
import { loadBrief } from "../../brief.js";
import { ensureSigningKey, publicKeyFingerprint } from "../../keys.js";
import { buildReceipt } from "../../receipt.js";
import { extractFinalMessageText, parseJsonlEvents, runEngine } from "../../run/engine.js";
import { assembleRun, type RunInput } from "../../run/orchestrate.js";
import { RUN_DIR_FILES, writeRunDir } from "../../run/run-dir.js";
import type { Brief } from "../../schema/brief.js";
import type { Receipt } from "../../schema/receipt.js";
import { validateLoopeix } from "../../validate.js";
import { computeVerdicts } from "../../verdicts.js";

/**
 * `loopeix run start <spec>` — execute a loop end-to-end into a run directory.
 * Validates the spec, gets the engine event stream (a live Codex/Claude call, or `--events-file`
 * replay), normalizes it, seals a ledger, evaluates gates, and writes a truthful report + manifest.
 * With `--seal <brief.yaml>` (Claims Check M2) the brief is sealed as ledger event 1, the verdict
 * engine adjudicates it, and a signed `receipt.json` lands in the run dir — for FAILED runs too
 * (a truthful record of a failed run is still a record).
 * Exit 0 = completed clean; 1 = invalid spec / brief / usage; 4 = a blocking gate held/failed —
 * unchanged by sealing (verdicts inform, the gate engine decides).
 */
export default class RunStart extends Command {
  static summary = "Execute a loop through an engine (or replay captured events) into a run directory.";
  static args = {
    spec: Args.string({ description: "path to the Loopeix YAML", required: true }),
  };
  static flags = {
    engine: Flags.string({ options: ["codex", "claude"], required: true, description: "engine to run" }),
    prompt: Flags.string({ description: "prompt / work item for the engine (required for a live run)" }),
    "events-file": Flags.string({ description: "replay a pre-captured JSONL event file instead of a live call" }),
    workspace: Flags.string({ default: ".", description: "workspace root (run dir = <workspace>/.loopeix/runs/<id>)" }),
    "max-budget-usd": Flags.string({ description: "Claude budget cap in USD (default 0.10)" }),
    seal: Flags.string({ description: "brief YAML to seal into the ledger; emits a signed receipt.json" }),
  };
  static examples = [
    '<%= config.bin %> run start my-loop.yaml --engine codex --prompt "Reply with ok"',
    "<%= config.bin %> run start my-loop.yaml --engine claude --events-file captured.jsonl",
    "<%= config.bin %> run start my-loop.yaml --engine codex --events-file captured.jsonl --seal brief.yaml",
  ];

  public async run(): Promise<void> {
    const { args, flags } = await this.parse(RunStart);
    const spec = parseYaml(readFileSync(args.spec, "utf8")) as Record<string, unknown>;

    const validation = validateLoopeix(spec);
    if (!validation.ok) {
      this.log(`INVALID spec (${validation.errors.length} issue(s)) — run aborted:`);
      for (const e of validation.errors) this.log(`  - ${e.path}: ${e.message}`);
      process.exitCode = 1;
      return;
    }

    const isCodex = flags.engine === "codex";
    const engine: EngineId = isCodex ? "codex_cli" : "claude_code_cli";

    let maxBudgetUsd: number | undefined;
    if (flags["max-budget-usd"] !== undefined) {
      maxBudgetUsd = Number(flags["max-budget-usd"]);
      if (!Number.isFinite(maxBudgetUsd) || maxBudgetUsd <= 0 || maxBudgetUsd > 100) {
        this.log(`ERROR: --max-budget-usd must be a positive number ≤ 100 (got '${flags["max-budget-usd"]}').`);
        process.exitCode = 1;
        return;
      }
    }

    // Sealed brief (--seal): loaded and validated BEFORE any engine work — a run must never
    // start against a promise that could not be parsed exactly as written.
    let brief: Brief | undefined;
    if (flags.seal !== undefined) {
      try {
        brief = loadBrief(readFileSync(flags.seal, "utf8"));
      } catch (err) {
        this.log(`ERROR: cannot seal brief '${flags.seal}': ${(err as Error).message}`);
        process.exitCode = 1;
        return;
      }
    }

    // Events: replay a captured file, or a live engine call.
    let rawEvents: unknown[];
    let engineStatus: { exit_code: number; timed_out: boolean } | undefined;
    if (flags["events-file"]) {
      rawEvents = parseJsonlEvents(readFileSync(flags["events-file"], "utf8"));
      this.log(`Replaying ${rawEvents.length} captured event(s) from ${flags["events-file"]}`);
    } else {
      if (!flags.prompt) {
        this.log("ERROR: --prompt is required for a live run (or pass --events-file to replay).");
        process.exitCode = 1;
        return;
      }
      this.log(`Invoking ${engine} (read-only, empty stdin)...`);
      const res = runEngine(engine, flags.prompt, { maxBudgetUsd });
      rawEvents = res.rawEvents;
      engineStatus = { exit_code: res.exit_code, timed_out: res.timed_out };
      if (res.exit_code !== 0 || res.timed_out) {
        this.warn(
          `engine exited ${res.exit_code}${res.timed_out ? " (timed out)" : ""}; captured ${rawEvents.length} event(s) — the run will seal run.failed, not run.completed.`,
        );
      }
    }

    const normalized = new (isCodex ? CodexAdapter : ClaudeAdapter)().normalize(rawEvents);
    const run_id = `run_${Date.now().toString(36)}`;
    const run_dir = `${flags.workspace}/.loopeix/runs/${run_id}`;
    const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

    const runInput: RunInput = {
      run_id,
      loop_family: String(spec.loop_family),
      loopeix_version: String(spec.version),
      started_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      engine,
      events: normalized.events,
      capture_gaps: normalized.capture_gaps,
      gates: asArray(spec.gates).map((g) => {
        const gate = g as Record<string, unknown>;
        return {
          id: String(gate.id),
          blocking: gate.blocking === true,
          inputs_required: asArray(gate.inputs_required).map(String),
          waiver_allowed: gate.waiver_allowed === true,
        };
      }),
      risk_controls: spec.risk_controls as RunInput["risk_controls"],
      tool_grant_tiers: asArray(spec.tool_grants).map((t) => String((t as Record<string, unknown>).risk_tier)),
      workspace_root: flags.workspace,
      run_dir,
      engine_status: engineStatus,
      brief,
    };

    const assembly = assembleRun(runInput);

    // Sealed pipeline: verdicts → workspace signing key → signed receipt. Runs for FAILED runs
    // too — the receipt records what actually happened, not only successes.
    // If buildReceipt fails, the run dir is STILL written (without a receipt) so the run
    // artifacts are preserved even when the seal step itself fails.
    let receipt: Receipt | undefined;
    if (brief) {
      const engineFinalText = extractFinalMessageText(engine, rawEvents);
      const verdicts = computeVerdicts({
        brief,
        events: normalized.events,
        captureGaps: normalized.capture_gaps,
        // resolve() ensures "." becomes the real cwd — without this, absolute paths under the
        // workspace root would not strip the prefix and would be excluded from adjudication (P3a).
        workspaceRoot: resolve(flags.workspace),
        ...(engineFinalText !== undefined ? { engineFinalText } : {}),
      });
      let key;
      try {
        key = ensureSigningKey(flags.workspace);
      } catch (err) {
        this.log(`ERROR: cannot initialize signing key: ${(err as Error).message}`);
        writeRunDir(run_dir, assembly, {});
        process.exitCode = 1;
        return;
      }
      if (key.created) {
        this.log(`Created signing key ${key.keyPath} (public key ${publicKeyFingerprint(key.publicKeySpkiB64)}); the keys directory is git-ignored.`);
      } else if (key.mode_corrected) {
        this.log(`Notice: signing key ${key.keyPath} had incorrect permissions — corrected to 0600.`);
      }
      try {
        receipt = buildReceipt(
          {
            run: {
              run_id,
              loop_family: String(spec.loop_family),
              loopeix_version: String(spec.version),
              engine,
              sealed_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
            },
            brief,
            claims: verdicts.claims,
            brief_clauses: verdicts.brief_clauses,
            evidence: verdicts.evidence,
            capture_gaps: normalized.capture_gaps.map((g) => ({ engine, capability: g.capability, level: g.level, note: g.note })),
            ledger: assembly.ledger,
          },
          key.privateKeyPem,
        );
      } catch (err) {
        this.log(`ERROR: cannot build receipt — run dir written without receipt: ${(err as Error).message}`);
        writeRunDir(run_dir, assembly, {});
        process.exitCode = 1;
        return;
      }
    }

    writeRunDir(run_dir, assembly, receipt ? { receipt } : {});

    this.log(`Run ${run_id}: ${assembly.integrity.run_state} (integrity ${assembly.integrity.integrity_status})`);
    this.log(
      `Gates: pass=${assembly.gate_report.summary.pass} hold=${assembly.gate_report.summary.hold} fail=${assembly.gate_report.summary.fail}`,
    );
    this.log(`Evidence: ${assembly.evidence.length} item(s) from ${normalized.events.length} normalized event(s)`);
    this.log(`Run dir: ${run_dir}  (${RUN_DIR_FILES.reportMd} / ${RUN_DIR_FILES.reportHtml})`);

    if (receipt) {
      this.log("");
      this.log(`Sealed brief verdicts (brief_hash ${receipt.brief.brief_hash}):`);
      for (const c of receipt.claims) this.log(`  ${c.verdict}  ${c.text}${c.reason !== undefined ? `  (${c.reason})` : ""}`);
      for (const c of receipt.brief_clauses) this.log(`  ${c.verdict}  ${c.text}${c.reason !== undefined ? `  (${c.reason})` : ""}`);
      this.log(`Receipt: ${run_dir}/${RUN_DIR_FILES.receipt}`);
      this.log(`verify: npx loopeix verify ${run_dir}/${RUN_DIR_FILES.receipt}`);
    }
    if (assembly.gate_report.blocking_hold_or_fail) process.exitCode = 4;
  }
}

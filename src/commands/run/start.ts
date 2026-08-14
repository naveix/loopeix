import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { Args, Command, Flags } from "@oclif/core";
import { parse as parseYaml } from "yaml";
import { ClaudeAdapter, CodexAdapter, type EngineId } from "../../adapters/index.js";
import { loadBrief } from "../../brief.js";
import { ensureSigningKey, publicKeyFingerprint } from "../../keys.js";
import { acquireLock, LockHeldError, type LockHandle } from "../../lock.js";
import { buildReceipt } from "../../receipt.js";
import { extractFinalMessageText, parseJsonlEvents } from "../../run/engine.js";
import { reserveRawRunDirectory } from "../../run/id.js";
import { assembleRun, type RunInput } from "../../run/orchestrate.js";
import {
  capturePlannedRunV02,
  consumeCapturedPlannedRunV02,
} from "../../run/capture-planned-v02.js";
import { preflightPlannedRun } from "../../run/preflight.js";
import { buildPlannedRunPrompt } from "../../run/prompt.js";
import { RUN_DIR_FILES, RUN_LEDGER_LOCK, RUN_WRITE_LOCK_OPTIONS, writeRunDir } from "../../run/run-dir.js";
import type { Brief } from "../../schema/brief.js";
import type { Receipt } from "../../schema/receipt.js";
import { captureStructuredFile, releaseCapturedStructuredFile } from "../../io/captured-file.js";
import { validateLoopeix } from "../../validate.js";
import { computeVerdicts } from "../../verdicts.js";
import { prohibitS37GeneralAgentSpawnV02 } from "../../run/pre-spawn-capability-broker-v02.js";

function isPlannedRunDir(path: string): boolean {
  return existsSync(path) && statSync(path).isDirectory() && existsSync(join(path, "resolved-run-plan.json"));
}

type V02StartSelection =
  | { selected: false; raw_spec?: Record<string, unknown> }
  | { selected: true; reason: "UNSUPPORTED_EXECUTION_PROFILE" | "V02_RUN_LAYOUT_CONTAMINATED" | "INVALID_RESOLVED_RUN_PLAN_DOCUMENT" | "INVALID_AUTHORING_DOCUMENT" };

async function selectPlannedV02Start(target: string): Promise<V02StartSelection> {
  if (!isPlannedRunDir(target)) return { selected: false };
  const captured = await capturePlannedRunV02(target);
  if (captured.ok) {
    if (consumeCapturedPlannedRunV02(captured.captured) === null) return { selected: false };
    return { selected: true, reason: "UNSUPPORTED_EXECUTION_PROFILE" };
  }
  if (captured.reason === "NOT_V02_PLANNED_RUN") return { selected: false };
  return {
    selected: true,
    reason: captured.reason === "V02_RUN_LAYOUT_CONTAMINATED"
      ? "V02_RUN_LAYOUT_CONTAMINATED"
      : "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
  };
}

async function selectRawV02Start(target: string): Promise<V02StartSelection> {
  const captured = await captureStructuredFile(target, {
    mode: "operator-approved-finite",
    max_member_bytes: 4_194_304,
    max_total_bytes: 4_194_304,
    max_heap_bytes: 16_777_216,
    max_elapsed_ms: 30_000,
    approved_by: "operator",
  });
  if (!captured.ok) {
    return { selected: true, reason: "INVALID_AUTHORING_DOCUMENT" };
  }
  let selection: V02StartSelection;
  try {
    const selected = await captured.capture.selectFamily("authoring");
    if (!selected.ok) selection = { selected: true, reason: "INVALID_AUTHORING_DOCUMENT" };
    else if (selected.schema_version === "0.2") selection = { selected: true, reason: "UNSUPPORTED_EXECUTION_PROFILE" };
    else {
      const parsed = await captured.capture.parseV01("authoring");
      selection = parsed.ok && typeof parsed.value === "object" && parsed.value !== null && !Array.isArray(parsed.value)
        ? { selected: false, raw_spec: parsed.value as Record<string, unknown> }
        : { selected: true, reason: "INVALID_AUTHORING_DOCUMENT" };
    }
  } catch {
    selection = { selected: true, reason: "INVALID_AUTHORING_DOCUMENT" };
  }
  const released = await releaseCapturedStructuredFile(captured.capture);
  return released.ok ? selection : { selected: true, reason: "INVALID_AUTHORING_DOCUMENT" };
}

async function selectV02Start(target: string): Promise<V02StartSelection> {
  const planned = await selectPlannedV02Start(target);
  if (planned.selected) return planned;
  if (isPlannedRunDir(target)) return { selected: false };
  return await selectRawV02Start(target);
}

/**
 * `loopeix run start <spec>` — replay a captured engine event stream into a run directory.
 * Validates the spec, normalizes `--events-file` input, seals a ledger, evaluates gates, and writes
 * a truthful report + manifest. S37 holds every live Codex/Claude path before process creation.
 * With `--seal <brief.yaml>` (Claims Check M2) the brief is sealed as ledger event 1, the verdict
 * engine adjudicates it, and a signed `receipt.json` lands in the run dir — for FAILED runs too
 * (a truthful record of a failed run is still a record).
 * Exit 0 = completed clean; 1 = invalid spec / brief / usage; 4 = a blocking gate held/failed —
 * unchanged by sealing (verdicts inform, the gate engine decides).
 */
export default class RunStart extends Command {
  static summary = "Replay captured engine events into a run directory; live execution is held in S37.";
  static args = {
    spec: Args.string({ description: "path to the Loopeix YAML", required: true }),
  };
  static flags = {
    engine: Flags.string({ options: ["codex", "claude"], required: true, description: "captured engine identity used to normalize replay events" }),
    prompt: Flags.string({ description: "legacy live-run input; all live execution is held in S37" }),
    "events-file": Flags.string({ description: "captured JSONL event file required for executable S37 replay" }),
    workspace: Flags.string({ default: ".", description: "workspace root (run dir = <workspace>/.loopeix/runs/<id>)" }),
    "max-budget-usd": Flags.string({ description: "legacy Claude live-run budget; all live execution is held in S37" }),
    seal: Flags.string({ description: "brief YAML to seal into the ledger; emits a signed receipt.json" }),
  };
  static examples = [
    "<%= config.bin %> run start my-loop.yaml --engine claude --events-file captured.jsonl",
    "<%= config.bin %> run start .loopeix/loops/minimal-bugfix/runs/run_abc --engine codex --events-file captured.jsonl",
    "<%= config.bin %> run start my-loop.yaml --engine codex --events-file captured.jsonl --seal brief.yaml",
  ];

  public async run(): Promise<void> {
    const { args, flags } = await this.parse(RunStart);
    const target = resolve(args.spec);
    const v02Selection = await selectV02Start(target);
    if (v02Selection.selected) {
      this.log("terminal: held");
      this.log(`reason: ${v02Selection.reason}`);
      this.log(
        `message: ${v02Selection.reason === "UNSUPPORTED_EXECUTION_PROFILE"
          ? "This execution profile is not available in S35."
          : v02Selection.reason === "V02_RUN_LAYOUT_CONTAMINATED"
            ? "Planned V02 run directory layout is contaminated."
            : v02Selection.reason === "INVALID_AUTHORING_DOCUMENT"
              ? "The authoring document could not be captured and validated safely."
              : "The planned V02 run could not be captured and validated safely."}`,
      );
      process.exitCode = v02Selection.reason === "UNSUPPORTED_EXECUTION_PROFILE" ? 1 : 4;
      return;
    }
    const plannedMode = isPlannedRunDir(target);
    const isCodex = flags.engine === "codex";
    const engine: EngineId = isCodex ? "codex_cli" : "claude_code_cli";

    let run_id: string | undefined;
    let run_dir: string | undefined;
    let workspace = flags.workspace;
    let specSource = target;
    let plannedPrompt: string | undefined;
    let runLock: LockHandle | undefined;

    if (plannedMode) {
      if (flags.prompt !== undefined) {
        this.log("ERROR: planned run directories use the approved generated prompt; remove --prompt to start the planned run.");
        process.exitCode = 1;
        return;
      }
      const preflight = preflightPlannedRun({ runDir: target, engine });
      if (!preflight.ok) {
        this.log(`ERROR: planned run preflight failed (${preflight.status}).`);
        for (const finding of preflight.findings) this.log(`  - ${finding}`);
        process.exitCode = 1;
        return;
      }
      run_id = preflight.run_id;
      run_dir = preflight.run_dir;
      workspace = preflight.workspace_root ?? ".";
      specSource = preflight.spec_path ?? join(target, "generated.loop.yaml");
      try {
        runLock = acquireLock(join(run_dir, RUN_LEDGER_LOCK), RUN_WRITE_LOCK_OPTIONS);
      } catch (err) {
        if (err instanceof LockHeldError) {
          this.log(`ERROR: run lock is held: ${err.message}`);
          process.exitCode = 1;
          return;
        }
        throw err;
      }
      if (!flags["events-file"]) {
        const promptResult = buildPlannedRunPrompt({ runDir: target });
        if (!promptResult.ok) {
          this.log(`ERROR: planned run prompt failed (${promptResult.status}).`);
          for (const finding of promptResult.findings) this.log(`  - ${finding}`);
          process.exitCode = 1;
          return;
        }
        plannedPrompt = promptResult.prompt;
      }
    }

    try {
      const spec = v02Selection.raw_spec
        ?? parseYaml(readFileSync(specSource, "utf8")) as Record<string, unknown>;

      const validation = validateLoopeix(spec);
      if (!validation.ok) {
        this.log(`INVALID spec (${validation.errors.length} issue(s)) — run aborted:`);
        for (const e of validation.errors) this.log(`  - ${e.path}: ${e.message}`);
        process.exitCode = 1;
        return;
      }

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

      const executionPrompt = flags["events-file"] ? undefined : (plannedPrompt ?? flags.prompt);
      if (!flags["events-file"] && !executionPrompt) {
        this.log("ERROR: --prompt is required for a live run (or pass --events-file to replay).");
        process.exitCode = 1;
        return;
      }

      if (!flags["events-file"]) {
        const blocked = prohibitS37GeneralAgentSpawnV02(engine);
        this.log("terminal: held");
        this.log(`reason: ${blocked.reason}`);
        this.log("message: S37 prohibits general-agent execution. The separate inert-probe enforcement interface has no verified host backend; no process was started.");
        process.exitCode = 1;
        return;
      }

      if (!plannedMode) {
        try {
          const allocation = reserveRawRunDirectory(flags.workspace);
          run_id = allocation.run_id;
          run_dir = allocation.run_dir;
        } catch (err) {
          this.log(`ERROR: cannot reserve raw run directory: ${(err as Error).message}`);
          process.exitCode = 1;
          return;
        }
      }

      // S37 permits only operator-supplied captured-event replay. The live path
      // returned above, and this command intentionally has no engine call site.
      const rawEvents = parseJsonlEvents(readFileSync(flags["events-file"] as string, "utf8"));
      this.log(`Replaying ${rawEvents.length} captured event(s) from ${flags["events-file"]}`);

      const normalized = new (isCodex ? CodexAdapter : ClaudeAdapter)().normalize(rawEvents);
      const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
      if (run_id === undefined || run_dir === undefined) {
        this.log("ERROR: cannot determine run identity.");
        process.exitCode = 1;
        return;
      }

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
        workspace_root: workspace,
        run_dir,
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
          workspaceRoot: resolve(workspace),
          ...(engineFinalText !== undefined ? { engineFinalText } : {}),
        });
        let key;
        try {
          key = ensureSigningKey(workspace);
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
    } finally {
      runLock?.release();
    }
  }
}

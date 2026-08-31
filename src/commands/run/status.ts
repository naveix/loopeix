import { join } from "node:path";
import { Args, Command } from "@oclif/core";
import { parseLedgerText, recoverLedger, type RecoveryResult } from "../../ledger.js";
import { parseResolvedRunPlanDocument } from "../../schema/runtime.js";
import {
  capturePlannedRunV02,
  consumeCapturedPlannedRunV02,
} from "../../run/capture-planned-v02.js";
import { presentPlannedRunV02, type PlannedRunPresentationV02 } from "../../run/present-planned-v02.js";
import { inspectRuntimeDirectoryV04 } from "../../run/runtime-directory-v04.js";
import {
  readAnchoredRuntimeDirectoryMemberText,
  readAnchoredRuntimeTextFile,
  resolveRunInspectionTarget,
} from "../../run/runtime-inspection-read.js";
import { projectRuntimeStatusV04, type RuntimeStatusV04 } from "../../run/runtime-status-v04.js";

export type RunStatusResult =
  | (RecoveryResult & { source: "ledger"; ledger_path: string })
  | {
      source: "runtime-v04";
      run_state: RuntimeStatusV04["run"]["state"];
      integrity_status: "valid";
      last_valid_sequence: number;
      terminated: boolean;
      findings: [];
      run_dir: string;
      status: RuntimeStatusV04;
    }
  | {
      source: "runtime-v04";
      run_state: "unknown";
      integrity_status: "invalid";
      last_valid_sequence: 0;
      terminated: false;
      findings: string[];
      run_dir: string;
      reason: "INVALID_RUNTIME_V04_DIRECTORY";
    }
  | {
      source: "planned";
      run_id: string;
      run_state: "planned";
      integrity_status: "unknown";
      last_valid_sequence: 0;
      terminated: false;
      findings: string[];
      run_dir: string;
      engine: string | null;
      next_action: string;
    }
  | (PlannedRunPresentationV02 & {
      source: "planned";
      integrity_status: "unknown";
      last_valid_sequence: 0;
      terminated: false;
      findings: [];
      run_dir: string;
      engine: string;
    })
  | {
      source: "planned";
      run_state: "planned";
      integrity_status: "invalid";
      last_valid_sequence: 0;
      terminated: false;
      findings: string[];
      run_dir: string;
      reason: "V02_RUN_LAYOUT_CONTAMINATED" | "INVALID_RESOLVED_RUN_PLAN_DOCUMENT";
    };

const MAX_LEDGER_BYTES = 67_108_864;
const MAX_PLAN_BYTES = 4_194_304;

function plannedEngine(plan: unknown): string | null {
  const adapter = (plan as { adapter_plan?: unknown }).adapter_plan;
  if (typeof adapter !== "object" || adapter === null) return null;
  const engine = (adapter as { engine?: unknown }).engine;
  return typeof engine === "string" ? engine : null;
}

function shortEngine(engine: string | null): string {
  if (engine === "codex_cli") return "codex";
  if (engine === "claude_code_cli") return "claude";
  return "<engine>";
}

/** `loopeix run status <run>` — show a run's state, integrity, and findings. */
export default class RunStatus extends Command {
  static summary = "Show a run's state, integrity, and findings from its ledger.";
  static description = "Reads the run's ledger.jsonl, recovers it, and reports. Exit 4 if integrity is not valid.";
  static args = {
    run: Args.string({ description: "run directory or ledger.jsonl path", required: true }),
  };
  static enableJsonFlag = true;

  public async run(): Promise<RunStatusResult> {
    const { args } = await this.parse(RunStatus);
    const target = await resolveRunInspectionTarget(args.run);
    if (!target.ok) {
      this.error(target.message, { exit: target.reason === "INPUT_NOT_FOUND" ? 2 : 4 });
    }
    const inspectionTarget = target.target;
    if (inspectionTarget.kind === "directory") {
      const inspectedV04 = await inspectRuntimeDirectoryV04(inspectionTarget.path);
      if (inspectedV04.ok) {
        const projected = projectRuntimeStatusV04(inspectedV04.inspected);
        if (!projected.ok) {
          const result: RunStatusResult = {
            source: "runtime-v04",
            run_state: "unknown",
            integrity_status: "invalid",
            last_valid_sequence: 0,
            terminated: false,
            findings: ["The V04 runtime directory failed the final status projection."],
            run_dir: inspectionTarget.path,
            reason: "INVALID_RUNTIME_V04_DIRECTORY",
          };
          if (!this.jsonEnabled()) this.log(`HOLD  ${result.reason}`);
          process.exitCode = 4;
          return result;
        }
        const result: RunStatusResult = {
          source: "runtime-v04",
          run_state: projected.status.run.state,
          integrity_status: "valid",
          last_valid_sequence: projected.status.integrity.ledger_sequence,
          terminated: projected.status.run.terminal.sealed,
          findings: [],
          run_dir: inspectionTarget.path,
          status: projected.status,
        };
        if (!this.jsonEnabled()) {
          this.log(`run_state:     ${result.status.run.state}`);
          this.log(`phase:         ${result.status.run.phase}`);
          this.log(`attempt:       ${result.status.attempt.current_attempt_ordinal ?? 0}`);
          this.log(`owner:         ${result.status.owner.status}`);
          this.log(`next action:   ${result.status.next_action.disposition} (${result.status.next_action.reason_code})`);
        }
        return result;
      }
      if (inspectedV04.reason === "RUNTIME_V04_INVALID") {
        const result: RunStatusResult = {
          source: "runtime-v04",
          run_state: "unknown",
          integrity_status: "invalid",
          last_valid_sequence: 0,
          terminated: false,
          findings: [inspectedV04.message],
          run_dir: inspectionTarget.path,
          reason: "INVALID_RUNTIME_V04_DIRECTORY",
        };
        if (!this.jsonEnabled()) this.log(`HOLD  ${result.reason}`);
        process.exitCode = 4;
        return result;
      }
    }
    if (inspectionTarget.kind === "directory") {
      const captured = await capturePlannedRunV02(inspectionTarget.path);
      if (captured.ok) {
        const value = consumeCapturedPlannedRunV02(captured.captured);
        if (value === null) {
          const result: RunStatusResult = {
            source: "planned",
            run_state: "planned",
            integrity_status: "invalid",
            last_valid_sequence: 0,
            terminated: false,
            findings: ["The captured V02 planned run could not be consumed safely."],
            run_dir: inspectionTarget.path,
            reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
          };
          process.exitCode = 4;
          return result;
        }
        const result: RunStatusResult = {
          ...presentPlannedRunV02(value.plan),
          source: "planned",
          integrity_status: "unknown",
          last_valid_sequence: 0,
          terminated: false,
          findings: [],
          run_dir: inspectionTarget.path,
          engine: value.plan.adapter_plan.engine,
        };
        if (!this.jsonEnabled()) {
          this.log("run_state:     planned");
          this.log("execution:     NOT EXECUTED");
          this.log("enforcement:   NOT ENFORCED");
          this.log(`reason:        ${result.reason}`);
        }
        return result;
      }
      if (captured.reason !== "NOT_V02_PLANNED_RUN") {
        const result: RunStatusResult = {
          source: "planned",
          run_state: "planned",
          integrity_status: "invalid",
          last_valid_sequence: 0,
          terminated: false,
          findings: [captured.message],
          run_dir: inspectionTarget.path,
          reason: captured.reason === "V02_RUN_LAYOUT_CONTAMINATED"
            ? "V02_RUN_LAYOUT_CONTAMINATED"
            : "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
        };
        if (!this.jsonEnabled()) this.log(`HOLD  ${result.reason}`);
        process.exitCode = 4;
        return result;
      }
    }
    const ledgerRead = inspectionTarget.kind === "file"
      ? await readAnchoredRuntimeTextFile(inspectionTarget.path, MAX_LEDGER_BYTES)
      : await readAnchoredRuntimeDirectoryMemberText(inspectionTarget.path, "ledger.jsonl", MAX_LEDGER_BYTES);
    if (!ledgerRead.ok) {
      if (ledgerRead.reason !== "FILE_NOT_FOUND" || inspectionTarget.kind === "file") {
        this.error(`ledger unavailable: ${ledgerRead.message}`, { exit: ledgerRead.reason === "FILE_NOT_FOUND" ? 2 : 4 });
      }
      const planRead = await readAnchoredRuntimeDirectoryMemberText(
        inspectionTarget.path,
        "resolved-run-plan.json",
        MAX_PLAN_BYTES,
      );
      if (!planRead.ok) {
        if (planRead.reason === "FILE_NOT_FOUND") {
          this.error(`ledger not found: ${join(inspectionTarget.path, "ledger.jsonl")}`, { exit: 2 });
        }
        const result: RunStatusResult = {
          source: "planned",
          run_state: "planned",
          integrity_status: "invalid",
          last_valid_sequence: 0,
          terminated: false,
          findings: [planRead.message],
          run_dir: inspectionTarget.path,
          reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
        };
        if (!this.jsonEnabled()) this.log(`HOLD  ${result.reason}`);
        process.exitCode = 4;
        return result;
      }
      let decodedPlan:
        | ReturnType<typeof parseResolvedRunPlanDocument>
        | {
            ok: false;
            schema_version: null;
            reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT";
            message: string;
          };
      try {
        decodedPlan = parseResolvedRunPlanDocument(JSON.parse(planRead.text));
      } catch {
        decodedPlan = {
          ok: false,
          schema_version: null,
          reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
          message: "The resolved run plan is not valid strict JSON.",
        };
      }
      if (!decodedPlan.ok) {
        const findings = "issues" in decodedPlan
          ? decodedPlan.issues.map((issue) => `${issue.path}: ${issue.message}`)
          : [decodedPlan.message];
        const result: RunStatusResult = {
          source: "planned",
          run_state: "planned",
          integrity_status: "invalid",
          last_valid_sequence: 0,
          terminated: false,
          findings,
          run_dir: inspectionTarget.path,
          reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
        };
        if (!this.jsonEnabled()) this.log(`HOLD  ${result.reason}`);
        process.exitCode = 4;
        return result;
      }
      const engine = plannedEngine(decodedPlan.value);
      const result: RunStatusResult = {
        source: "planned",
        run_id: decodedPlan.value.run_id,
        run_state: "planned",
        integrity_status: "unknown",
        last_valid_sequence: 0,
        terminated: false,
        findings: [],
        run_dir: inspectionTarget.path,
        engine,
        next_action: `loopeix run start ${inspectionTarget.path} --engine ${shortEngine(engine)}`,
      };
      if (!this.jsonEnabled()) {
        this.log(`run_state:     ${result.run_state}`);
        this.log(`integrity:     ${result.integrity_status}`);
        this.log(`last sequence: ${result.last_valid_sequence}`);
        this.log(`terminated:    ${result.terminated}`);
        this.log(`run_id:        ${result.run_id}`);
        this.log(`source:        ${result.source}`);
        this.log(`next action:   ${result.next_action}`);
      }
      return result;
    }
    let recovery: RecoveryResult;
    try {
      const { events, partialFinalLineDropped, corruptLines } = parseLedgerText(ledgerRead.text);
      recovery = recoverLedger(events, { partialFinalLineDropped, corruptLines });
    } catch (err) {
      this.error(`corrupt ledger: ${(err as Error).message}`, { exit: 4 });
    }
    if (!this.jsonEnabled()) {
      this.log(`run_state:     ${recovery.run_state}`);
      this.log(`integrity:     ${recovery.integrity_status}`);
      this.log(`last sequence: ${recovery.last_valid_sequence}`);
      this.log(`terminated:    ${recovery.terminated}`);
      if (recovery.findings.length > 0) {
        this.log("findings:");
        for (const f of recovery.findings) this.log(`  - ${f}`);
      }
    }
    if (recovery.integrity_status !== "valid") process.exitCode = 4;
    return { ...recovery, source: "ledger", ledger_path: ledgerRead.path };
  }
}

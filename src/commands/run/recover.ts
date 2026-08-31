import { Args, Command } from "@oclif/core";
import { parseLedgerText, recoverLedger, type RecoveryResult } from "../../ledger.js";
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

export type RunRecoverResult =
  | (RecoveryResult & { recoverable: boolean })
  | {
      source: "runtime-v04";
      recoverable: boolean;
      integrity_status: "valid";
      findings: [];
      run_dir: string;
      reason: RuntimeStatusV04["next_action"]["reason_code"];
      status: RuntimeStatusV04;
    }
  | {
      source: "runtime-v04";
      recoverable: false;
      integrity_status: "invalid";
      findings: string[];
      run_dir: string;
      reason: "INVALID_RUNTIME_V04_DIRECTORY";
    }
  | {
      source: "runtime-v04";
      recoverable: false;
      integrity_status: "unknown";
      findings: [];
      run_dir: string;
    }
  | (PlannedRunPresentationV02 & {
      recoverable: false;
      integrity_status: "unknown";
      findings: [];
      run_dir: string;
    })
  | {
      recoverable: false;
      integrity_status: "invalid";
      findings: string[];
      run_dir: string;
      reason: "V02_RUN_LAYOUT_CONTAMINATED" | "INVALID_RESOLVED_RUN_PLAN_DOCUMENT";
    };

const MAX_LEDGER_BYTES = 67_108_864;

function statusResult(
  runDirectory: string,
  status: RuntimeStatusV04,
): Extract<RunRecoverResult, { source: "runtime-v04"; integrity_status: "valid" }> {
  const recoverable = status.next_action.disposition !== "hold";
  if (!recoverable) process.exitCode = 4;
  return {
    source: "runtime-v04",
    recoverable,
    integrity_status: "valid",
    findings: [],
    run_dir: runDirectory,
    reason: status.next_action.reason_code,
    status,
  };
}

/**
 * `loopeix run recover <run>` — assess whether an interrupted run can be recovered.
 * Packaged S41 remains read-only: it reports integrity findings and a verdict; authenticated
 * recovery writes stay on trusted composition hosts outside this public CLI surface.
 * Exit 4 if the run is held/unrecoverable.
 */
export default class RunRecover extends Command {
  static summary = "Assess and report the recoverability of a run from its ledger (read-only in V1).";
  static args = {
    run: Args.string({ description: "run directory or ledger.jsonl path", required: true }),
  };
  static enableJsonFlag = true;

  public async run(): Promise<RunRecoverResult> {
    const { args } = await this.parse(RunRecover);
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
          const result: RunRecoverResult = {
            source: "runtime-v04",
            recoverable: false,
            integrity_status: "invalid",
            findings: ["The V04 runtime directory failed the final recovery projection."],
            run_dir: inspectionTarget.path,
            reason: "INVALID_RUNTIME_V04_DIRECTORY",
          };
          process.exitCode = 4;
          return result;
        }
        const result = statusResult(inspectionTarget.path, projected.status);
        if (!this.jsonEnabled()) {
          this.log(`run_state:  ${result.status.run.state}`);
          this.log(`phase:      ${result.status.run.phase}`);
          this.log(`verdict:    ${result.recoverable ? "recoverable — bounded S41 resume is eligible" : "HOLD — not recoverable on the current trusted boundary"}`);
          this.log(`reason:     ${result.reason}`);
        }
        return result;
      }
      if (inspectedV04.reason === "RUNTIME_V04_INVALID") {
        const result: RunRecoverResult = {
          source: "runtime-v04",
          recoverable: false,
          integrity_status: "invalid",
          findings: [inspectedV04.message],
          run_dir: inspectionTarget.path,
          reason: "INVALID_RUNTIME_V04_DIRECTORY",
        };
        process.exitCode = 4;
        return result;
      }
    }
    if (inspectionTarget.kind === "directory") {
      const captured = await capturePlannedRunV02(inspectionTarget.path);
      if (captured.ok) {
        const value = consumeCapturedPlannedRunV02(captured.captured);
        if (value === null) {
          const result: RunRecoverResult = {
            recoverable: false,
            integrity_status: "invalid",
            findings: ["The captured V02 planned run could not be consumed safely."],
            run_dir: inspectionTarget.path,
            reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
          };
          process.exitCode = 4;
          return result;
        }
        const result: RunRecoverResult = {
          ...presentPlannedRunV02(value.plan),
          recoverable: false,
          integrity_status: "unknown",
          findings: [],
          run_dir: inspectionTarget.path,
        };
        if (!this.jsonEnabled()) {
          this.log("verdict:    HOLD — V02 execution is not available in S35");
          this.log(`reason:     ${result.reason}`);
        }
        process.exitCode = 1;
        return result;
      }
      if (captured.reason !== "NOT_V02_PLANNED_RUN") {
        const result: RunRecoverResult = {
          recoverable: false,
          integrity_status: "invalid",
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
      this.error(
        ledgerRead.reason === "FILE_NOT_FOUND"
          ? `ledger not found: ${inspectionTarget.kind === "file" ? inspectionTarget.path : `${inspectionTarget.path}/ledger.jsonl`}`
          : `corrupt ledger (unrecoverable): ${ledgerRead.message}`,
        { exit: ledgerRead.reason === "FILE_NOT_FOUND" ? 2 : 4 },
      );
    }
    let recovery: RecoveryResult;
    try {
      const { events, partialFinalLineDropped, corruptLines } = parseLedgerText(ledgerRead.text);
      recovery = recoverLedger(events, { partialFinalLineDropped, corruptLines });
    } catch (err) {
      this.error(`corrupt ledger (unrecoverable): ${(err as Error).message}`, { exit: 4 });
    }
    const recoverable = recovery.integrity_status === "valid";
    if (!this.jsonEnabled()) {
      this.log(`run_state:  ${recovery.run_state}`);
      this.log(`integrity:  ${recovery.integrity_status}`);
      this.log(`verdict:    ${recoverable ? "recoverable — chain and content verified" : "HOLD — needs review before continuing"}`);
      if (recovery.findings.length > 0) {
        this.log("findings:");
        for (const f of recovery.findings) this.log(`  - ${f}`);
      }
    }
    if (!recoverable) process.exitCode = 4;
    return { ...recovery, recoverable };
  }
}

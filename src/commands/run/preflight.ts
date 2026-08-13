import { Args, Command, Flags } from "@oclif/core";
import { resolve } from "node:path";
import { preflightPlannedRun, type PlannedRunPreflightResult } from "../../run/preflight.js";
import type { EngineId } from "../../adapters/index.js";
import {
  capturePlannedRunV02,
  consumeCapturedPlannedRunV02,
} from "../../run/capture-planned-v02.js";
import { presentPlannedRunV02, type PlannedRunPresentationV02 } from "../../run/present-planned-v02.js";

export type RunPreflightCommandResult = PlannedRunPreflightResult | V02RunPreflightResult;

export type V02RunPreflightResult =
  | (PlannedRunPresentationV02 & {
      ok: false;
      status: "hold-unsupported-execution-profile";
      run_dir: string;
      engine: EngineId;
      findings: [];
    })
  | {
      ok: false;
      status: "hold-engine-mismatch" | "hold-invalid-v02-plan" | "hold-v02-layout-contaminated";
      run_dir: string;
      run_id?: string;
      engine?: string;
      reason: "ENGINE_MISMATCH" | "INVALID_RESOLVED_RUN_PLAN_DOCUMENT" | "V02_RUN_LAYOUT_CONTAMINATED";
      findings: string[];
    };

function engineId(engine: string): EngineId {
  return engine === "codex" ? "codex_cli" : "claude_code_cli";
}

export default class RunPreflight extends Command {
  static summary = "Check whether a planned run directory is ready to start.";
  static description =
    "Validates planned-run files, engine binding, generated loop validity, and absence of execution artifacts without invoking an engine or mutating files.";
  static args = {
    run: Args.string({ description: "planned run directory", required: true }),
  };
  static flags = {
    engine: Flags.string({ options: ["codex", "claude"], required: true, description: "engine adapter to preflight against" }),
  };
  static enableJsonFlag = true;

  public async run(): Promise<RunPreflightCommandResult> {
    const { args, flags } = await this.parse(RunPreflight);
    const runDir = resolve(args.run);
    const requestedEngine = engineId(flags.engine);
    const captured = await capturePlannedRunV02(runDir);
    if (captured.ok) {
      const value = consumeCapturedPlannedRunV02(captured.captured);
      if (value === null) {
        const result: V02RunPreflightResult = {
          ok: false,
          status: "hold-invalid-v02-plan",
          run_dir: runDir,
          reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
          findings: ["The captured V02 planned run could not be consumed safely."],
        };
        if (!this.jsonEnabled()) this.log(`HOLD  ${result.reason}`);
        process.exitCode = 4;
        return result;
      }
      if (value.plan.adapter_plan.engine !== requestedEngine) {
        const result: V02RunPreflightResult = {
          ok: false,
          status: "hold-engine-mismatch",
          run_dir: runDir,
          run_id: value.plan.run_id,
          engine: value.plan.adapter_plan.engine,
          reason: "ENGINE_MISMATCH",
          findings: [`planned run was prepared for ${value.plan.adapter_plan.engine}, not ${requestedEngine}`],
        };
        if (!this.jsonEnabled()) {
          this.log(`HOLD  ${result.status}`);
          for (const finding of result.findings) this.log(`  - ${finding}`);
        }
        process.exitCode = 1;
        return result;
      }
      const result: V02RunPreflightResult = {
        ...presentPlannedRunV02(value.plan),
        ok: false,
        status: "hold-unsupported-execution-profile",
        run_dir: runDir,
        engine: requestedEngine,
        findings: [],
      };
      if (!this.jsonEnabled()) {
        this.log(`HOLD  ${result.reason}`);
        this.log("This execution profile is not available in S35.");
      }
      process.exitCode = 1;
      return result;
    }
    if (captured.reason !== "NOT_V02_PLANNED_RUN") {
      const contaminated = captured.reason === "V02_RUN_LAYOUT_CONTAMINATED";
      const result: V02RunPreflightResult = {
        ok: false,
        status: contaminated ? "hold-v02-layout-contaminated" : "hold-invalid-v02-plan",
        run_dir: runDir,
        reason: contaminated ? "V02_RUN_LAYOUT_CONTAMINATED" : "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
        findings: [captured.message],
      };
      if (!this.jsonEnabled()) this.log(`HOLD  ${result.reason}`);
      process.exitCode = 4;
      return result;
    }
    const result = preflightPlannedRun({ runDir: args.run, engine: requestedEngine });

    if (!this.jsonEnabled()) {
      if (result.ok) {
        this.log(`READY  ${result.run_id}`);
        this.log(`Run dir: ${result.run_dir}`);
        this.log(`Next action: ${result.next_action}`);
      } else {
        this.log(`HOLD  ${result.status}`);
        for (const finding of result.findings) this.log(`  - ${finding}`);
      }
    }

    if (!result.ok) process.exitCode = 1;
    return result;
  }
}

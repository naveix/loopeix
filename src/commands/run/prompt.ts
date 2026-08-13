import { Args, Command } from "@oclif/core";
import { resolve } from "node:path";
import { buildPlannedRunPrompt, type PlannedRunPromptResult } from "../../run/prompt.js";
import {
  capturePlannedRunV02,
  consumeCapturedPlannedRunV02,
} from "../../run/capture-planned-v02.js";
import { presentPlannedRunV02, type PlannedRunPresentationV02 } from "../../run/present-planned-v02.js";

export type RunPromptCommandResult = PlannedRunPromptResult | V02RunPromptResult;

export type V02RunPromptResult =
  | (PlannedRunPresentationV02 & {
      ok: true;
      status: "planned-non-runnable";
      run_dir: string;
      engine: string;
      prompt: string;
    })
  | {
      ok: false;
      status: "hold-invalid-v02-plan" | "hold-v02-layout-contaminated";
      run_dir: string;
      reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT" | "V02_RUN_LAYOUT_CONTAMINATED";
      findings: string[];
    };

function renderV02PromptProjection(presentation: PlannedRunPresentationV02): string {
  return [
    "# Loopeix V02 planned-run projection",
    "",
    `Run: ${JSON.stringify(presentation.run_id)}`,
    "Execution profile: bounded-v02",
    "Execution: NOT EXECUTED",
    "Control enforcement: NOT ENFORCED",
    "Execution blocked reason: UNSUPPORTED_EXECUTION_PROFILE",
    "",
    "## Planned controls",
    ...presentation.controls.map((control) =>
      `- [${control.category}] ${control.control_ref}: ${JSON.stringify(control.label)} = ${control.value}`),
    "",
    "This is a read-only planning projection. It is not an instruction to start or execute work.",
  ].join("\n");
}

export default class RunPrompt extends Command {
  static summary = "Print the bounded engine prompt for a planned run directory.";
  static description =
    "Renders a deterministic prompt from intake-brief.json and resolved-run-plan.json after the same preflight gate used by run start passes. This does not invoke an engine or write artifacts.";
  static args = {
    run: Args.string({ description: "planned run directory", required: true }),
  };
  static enableJsonFlag = true;

  public async run(): Promise<RunPromptCommandResult> {
    const { args } = await this.parse(RunPrompt);
    const runDir = resolve(args.run);
    const captured = await capturePlannedRunV02(runDir);
    if (captured.ok) {
      const value = consumeCapturedPlannedRunV02(captured.captured);
      if (value === null) {
        const result: V02RunPromptResult = {
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
      const presentation = presentPlannedRunV02(value.plan);
      const result: V02RunPromptResult = {
        ...presentation,
        ok: true,
        status: "planned-non-runnable",
        run_dir: runDir,
        engine: value.plan.adapter_plan.engine,
        prompt: renderV02PromptProjection(presentation),
      };
      if (!this.jsonEnabled()) this.log(result.prompt);
      return result;
    }
    if (captured.reason !== "NOT_V02_PLANNED_RUN") {
      const result: V02RunPromptResult = {
        ok: false,
        status: captured.reason === "V02_RUN_LAYOUT_CONTAMINATED"
          ? "hold-v02-layout-contaminated"
          : "hold-invalid-v02-plan",
        run_dir: runDir,
        reason: captured.reason === "V02_RUN_LAYOUT_CONTAMINATED"
          ? "V02_RUN_LAYOUT_CONTAMINATED"
          : "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
        findings: [captured.message],
      };
      if (!this.jsonEnabled()) this.log(`HOLD  ${result.reason}`);
      process.exitCode = 4;
      return result;
    }
    const result = buildPlannedRunPrompt({ runDir: args.run });

    if (!this.jsonEnabled()) {
      if (result.ok) {
        this.log(result.prompt);
      } else {
        this.log(`HOLD  ${result.status}`);
        for (const finding of result.findings) this.log(`  - ${finding}`);
      }
    }

    if (!result.ok) process.exitCode = 1;
    return result;
  }
}

import { Args, Command, Flags } from "@oclif/core";
import { preflightPlannedRun, type PlannedRunPreflightResult } from "../../run/preflight.js";
import type { EngineId } from "../../adapters/index.js";

export interface RunPreflightCommandResult extends PlannedRunPreflightResult {}

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
    const result = preflightPlannedRun({ runDir: args.run, engine: engineId(flags.engine) });

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

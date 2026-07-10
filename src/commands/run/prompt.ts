import { Args, Command } from "@oclif/core";
import { buildPlannedRunPrompt, type PlannedRunPromptResult } from "../../run/prompt.js";

export type RunPromptCommandResult = PlannedRunPromptResult;

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

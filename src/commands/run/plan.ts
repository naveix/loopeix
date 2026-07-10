import { Args, Command, Flags } from "@oclif/core";
import { planRunFromCompilePack, type PlanEngine, type PlanRunResult } from "../../run/plan.js";

export interface RunPlanCommandResult extends PlanRunResult {}

export default class RunPlan extends Command {
  static summary = "Create an approved resolved run plan from a compiled pack.";
  static description =
    "Consumes a compiled `loopeix compile --pack-dir` output and writes a planned run directory with intake brief and resolved-run-plan.json. HOLD packs are refused.";
  static args = {
    pack: Args.string({ description: "compile pack directory", required: true }),
  };
  static flags = {
    engine: Flags.string({ options: ["codex", "claude"], required: true, description: "engine adapter to plan for" }),
    "approve-compiled-pack": Flags.boolean({
      description: "confirm the compiled pack was reviewed and approved for planning",
      default: false,
    }),
    "workspace-root": Flags.string({
      description: "approved workspace root (run dir = <workspace-root>/.loopeix/loops/<family>/runs/<run-id>)",
      default: process.cwd(),
    }),
  };
  static examples = [
    "<%= config.bin %> run plan .loopeix/compiles/date-parser --engine codex --workspace-root .",
  ];
  static enableJsonFlag = true;

  public async run(): Promise<RunPlanCommandResult> {
    const { args, flags } = await this.parse(RunPlan);
    const result = planRunFromCompilePack({
      packDir: args.pack,
      workspaceRoot: flags["workspace-root"],
      engine: flags.engine as PlanEngine,
      approved: flags["approve-compiled-pack"],
    });

    if (!this.jsonEnabled()) {
      if (result.ok) {
        this.log(`PLANNED  ${result.run_id}`);
        this.log(`Run dir: ${result.run_dir}`);
        this.log(`Resolved plan: ${result.paths?.resolved_run_plan}`);
      } else {
        this.log(`HOLD  ${result.terminal_state}`);
        if (result.message !== undefined) this.log(`  - ${result.message}`);
      }
    }

    if (!result.ok) process.exitCode = 1;
    return result;
  }
}

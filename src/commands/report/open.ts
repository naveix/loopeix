import { lstatSync } from "node:fs";
import { join, resolve } from "node:path";
import { Args, Command } from "@oclif/core";
import { reportHtmlPath } from "../../run/run-dir.js";
import { capturePlanReportOpenDecisionV02 } from "../../report/plan-open.js";

/**
 * `loopeix report open <run-dir>` — print the path + file:// URL of a run's HTML report so you can
 * open it in a browser. (Prints rather than spawning a browser, to avoid platform assumptions.)
 */
export default class ReportOpen extends Command {
  static summary = "Show the path to a run's HTML report (open it in your browser).";
  static args = {
    "run-dir": Args.string({ description: "path to the run directory (.loopeix/runs/<id>)", required: true }),
  };
  static examples = ["<%= config.bin %> report open .loopeix/runs/run_abc"];

  public async run(): Promise<void> {
    const { args } = await this.parse(ReportOpen);
    const resolvedPlanPath = join(args["run-dir"], "resolved-run-plan.json");
    let hasResolvedPlan = false;
    try {
      const metadata = lstatSync(resolvedPlanPath);
      hasResolvedPlan = metadata.isFile() && !metadata.isSymbolicLink();
    } catch {
      hasResolvedPlan = false;
    }
    if (hasResolvedPlan) {
      const decision = await capturePlanReportOpenDecisionV02(resolve(args["run-dir"]));
      if (!decision.ok) {
        this.log(`ERROR [${decision.reason}] ${decision.message}`);
        process.exitCode = decision.reason === "PLAN_REPORT_NOT_BUILT" ? 1 : 4;
        return;
      }
      const path = join(args["run-dir"], "plan-report.html");
      this.log(`Report: ${path}`);
      this.log(`Open in a browser: file://${resolve(path)}`);
      return;
    }
    const p = reportHtmlPath(args["run-dir"]);
    let reportIsRegular = false;
    try {
      const metadata = lstatSync(p);
      reportIsRegular = metadata.isFile() && !metadata.isSymbolicLink();
    } catch {
      reportIsRegular = false;
    }
    if (!reportIsRegular) {
      this.log(`ERROR  no report at ${p} — run \`loopeix report build ${args["run-dir"]}\` first`);
      process.exitCode = 1;
      return;
    }
    this.log(`Report: ${p}`);
    this.log(`Open in a browser: file://${resolve(p)}`);
  }
}

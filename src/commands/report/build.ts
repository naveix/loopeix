import { Args, Command } from "@oclif/core";
import { lstatSync } from "node:fs";
import { buildReportFromRunDir, RUN_DIR_FILES } from "../../run/run-dir.js";
import { join, resolve } from "node:path";
import { buildPlanReportV02 } from "../../report/build-plan-v02.js";

/**
 * `loopeix report build <run-dir>` — rebuild the Markdown + HTML report from a run's recorded
 * inputs (`report-input.json`, written during the run). Truthful by construction. Exit 0 on success.
 */
export default class ReportBuild extends Command {
  static summary = "Build the Markdown + HTML report for a run from its recorded inputs.";
  static description =
    "Reads <run-dir>/report-input.json and rebuilds report.md + report.html. The report is derived from the run's recorded evidence/gate/timeline inputs, so it cannot over-claim.";
  static args = {
    "run-dir": Args.string({ description: "path to the run directory (.loopeix/runs/<id>)", required: true }),
  };
  static examples = ["<%= config.bin %> report build .loopeix/runs/run_abc"];

  public async run(): Promise<void> {
    const { args } = await this.parse(ReportBuild);
    const dir = args["run-dir"];
    let hasResolvedPlan = false;
    try {
      const metadata = lstatSync(join(dir, "resolved-run-plan.json"));
      hasResolvedPlan = metadata.isFile() && !metadata.isSymbolicLink();
    } catch {
      hasResolvedPlan = false;
    }
    if (!hasResolvedPlan) {
      try {
        buildReportFromRunDir(dir);
        this.log(`OK  wrote ${RUN_DIR_FILES.reportMd} + ${RUN_DIR_FILES.reportHtml} in ${dir}`);
      } catch (e) {
        this.log(`ERROR  could not build a report from ${dir}: ${(e as Error).message}`);
        process.exitCode = 1;
      }
      return;
    }
    const planned = await buildPlanReportV02(resolve(dir));
    if (planned.ok) {
      this.log(`OK  wrote ${planned.members.join(" + ")} in ${dir}`);
      return;
    }
    if (planned.reason !== "NOT_V02_PLANNED_RUN") {
      this.log(`ERROR [${planned.reason}] ${planned.message}`);
      process.exitCode = planned.reason === "V02_RUN_LAYOUT_CONTAMINATED"
        || planned.reason === "REPORT_BUILD_STALE_LOCK"
        || planned.reason === "PLAN_REPORT_RENDERER_INVALID"
        ? 4
        : 1;
      return;
    }
    try {
      buildReportFromRunDir(dir);
      this.log(`OK  wrote ${RUN_DIR_FILES.reportMd} + ${RUN_DIR_FILES.reportHtml} in ${dir}`);
    } catch (e) {
      this.log(`ERROR  could not build a report from ${dir}: ${(e as Error).message}`);
      process.exitCode = 1;
    }
  }
}

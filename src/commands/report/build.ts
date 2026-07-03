import { Args, Command } from "@oclif/core";
import { buildReportFromRunDir, RUN_DIR_FILES } from "../../run/run-dir.js";

/**
 * `loopspec report build <run-dir>` — rebuild the Markdown + HTML report from a run's recorded
 * inputs (`report-input.json`, written during the run). Truthful by construction. Exit 0 on success.
 */
export default class ReportBuild extends Command {
  static summary = "Build the Markdown + HTML report for a run from its recorded inputs.";
  static description =
    "Reads <run-dir>/report-input.json and rebuilds report.md + report.html. The report is derived from the run's recorded evidence/gate/timeline inputs, so it cannot over-claim.";
  static args = {
    "run-dir": Args.string({ description: "path to the run directory (.loopspec/runs/<id>)", required: true }),
  };
  static examples = ["<%= config.bin %> report build .loopspec/runs/run_abc"];

  public async run(): Promise<void> {
    const { args } = await this.parse(ReportBuild);
    const dir = args["run-dir"];
    try {
      buildReportFromRunDir(dir);
      this.log(`OK  wrote ${RUN_DIR_FILES.reportMd} + ${RUN_DIR_FILES.reportHtml} in ${dir}`);
    } catch (e) {
      this.log(`ERROR  could not build a report from ${dir}: ${(e as Error).message}`);
      process.exitCode = 1;
    }
  }
}

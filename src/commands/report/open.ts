import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { Args, Command } from "@oclif/core";
import { reportHtmlPath } from "../../run/run-dir.js";

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
    const p = reportHtmlPath(args["run-dir"]);
    if (!existsSync(p)) {
      this.log(`ERROR  no report at ${p} — run \`loopeix report build ${args["run-dir"]}\` first`);
      process.exitCode = 1;
      return;
    }
    this.log(`Report: ${p}`);
    this.log(`Open in a browser: file://${resolve(p)}`);
  }
}

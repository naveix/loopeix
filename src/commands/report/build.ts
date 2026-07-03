import { Command } from "@oclif/core";

/** `loopspec report build` — stub. Real implementation lands in S12 (local report/timeline). */
export default class ReportBuild extends Command {
  static summary = "Build a Markdown + HTML report for a run (stub — implemented in S12).";
  static state = "beta";

  public async run(): Promise<void> {
    this.warn(
      "`report build` is not yet wired at the CLI. The report is implemented and tested in the buildReport library; the CLI command arrives with the run-execution layer.",
    );
  }
}

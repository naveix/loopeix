import { Command } from "@oclif/core";

/** `loopspec report open` — stub. Real implementation lands in S12. */
export default class ReportOpen extends Command {
  static summary = "Open or print the path to a local run report (stub — implemented in S12).";
  static state = "beta";

  public async run(): Promise<void> {
    this.warn(
      "`report open` is not yet wired at the CLI. The report renderer lives in the buildReport library; the CLI command arrives with the run-execution layer.",
    );
  }
}

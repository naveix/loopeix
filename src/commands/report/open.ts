import { Command } from "@oclif/core";

/** `loopspec report open` — stub. Real implementation lands in S12. */
export default class ReportOpen extends Command {
  static summary = "Open or print the path to a local run report (stub — implemented in S12).";
  static state = "beta";

  public async run(): Promise<void> {
    this.warn("`report open` is not implemented in this V0.1 skeleton; it arrives in S12.");
  }
}

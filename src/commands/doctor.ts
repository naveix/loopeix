import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "@oclif/core";

/** `loopeix doctor` — local install health: Node version, CLI version, bundled schema. */
export default class Doctor extends Command {
  static summary = "Check the local Loopeix install (Node version, CLI version, bundled schema).";
  static enableJsonFlag = true;

  public async run(): Promise<{ node: string; cli: string; schemaBundled: boolean }> {
    const here = dirname(fileURLToPath(import.meta.url));
    // dist/commands/doctor.js -> package root is ../.. ; schemas/ sits at the root.
    const schemaPath = join(here, "..", "..", "schemas", "loopeix.schema.json");
    const report = {
      node: process.version,
      cli: this.config.version,
      schemaBundled: existsSync(schemaPath),
    };
    if (!this.jsonEnabled()) {
      this.log("loopeix doctor");
      this.log(`  node:           ${report.node}`);
      this.log(`  cli:            ${report.cli}`);
      this.log(`  schema bundled: ${report.schemaBundled ? "yes" : "no"}`);
    }
    return report;
  }
}

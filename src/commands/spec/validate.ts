import { readFileSync } from "node:fs";
import { Args, Command } from "@oclif/core";
import { parse as parseYaml } from "yaml";
import { validateLoopeix, type ValidationResult } from "../../validate.js";

/**
 * `loopeix spec validate <file>` — validate a Loopeix against the schema contract.
 * Exit 0 = valid, 1 = validation failure (cli-command-spec.md exit codes).
 */
export default class SpecValidate extends Command {
  static summary = "Validate a Loopeix file against the schema contract.";
  static description =
    "Runs structural (schema) then relational (invariant) validation. Exit 0 if valid, 1 if invalid.";
  static args = {
    file: Args.string({ description: "path to the Loopeix YAML file", required: true }),
  };
  static examples = ["<%= config.bin %> spec validate ./my-loop.loop.yaml"];
  static enableJsonFlag = true;

  public async run(): Promise<ValidationResult> {
    const { args } = await this.parse(SpecValidate);
    const data: unknown = parseYaml(readFileSync(args.file, "utf8"));
    const result = validateLoopeix(data);

    if (!this.jsonEnabled()) {
      if (result.ok) {
        this.log(`OK  ${args.file} is a valid Loopeix spec`);
      } else {
        this.log(`INVALID  ${args.file} (${result.errors.length} issue${result.errors.length === 1 ? "" : "s"}):`);
        for (const e of result.errors) this.log(`  - ${e.path}: ${e.message}`);
      }
    }
    if (!result.ok) process.exitCode = 1;
    return result;
  }
}

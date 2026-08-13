import { extname } from "node:path";
import { Args, Command } from "@oclif/core";
import { captureStructuredFile } from "../../io/captured-file.js";
import { decodeStructuredDocumentV02 } from "../../schema/decode-envelope.js";
import { parseLoopeixDocument } from "../../schema/version-dispatch.js";
import type { ValidationResult } from "../../validate.js";

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
    const captured = await captureStructuredFile(args.file, null);
    let result: ValidationResult;
    if (!captured.ok) {
      result = { ok: false, errors: [{ path: "(file)", message: `${captured.reason}: ${captured.message}` }] };
    } else {
      const selected = await captured.capture.selectFamily("authoring");
      if (!selected.ok) {
        result = { ok: false, errors: [{ path: "schema_version", message: `${selected.reason}: ${selected.message}` }] };
      } else if (selected.schema_version === "0.1") {
        const parsed = await selected.capture.parseV01("authoring");
        result = parsed.ok
          ? { ok: true, errors: [] }
          : { ok: false, errors: [{ path: "(root)", message: `${parsed.reason}: ${parsed.message}` }] };
      } else {
        const snapshot = await selected.capture.snapshotBytes();
        if (!snapshot.ok) {
          result = { ok: false, errors: [{ path: "(file)", message: `${snapshot.reason}: ${snapshot.message}` }] };
        } else {
          const format = extname(args.file).toLowerCase() === ".json" ? "json" : "yaml";
          const decoded = decodeStructuredDocumentV02(snapshot.bytes, format);
          if (!decoded.ok) {
            result = { ok: false, errors: [{ path: "(root)", message: `${decoded.reason}: ${decoded.message}` }] };
          } else {
            const parsed = parseLoopeixDocument(decoded.value);
            result = parsed.ok
              ? { ok: true, errors: [] }
              : "issues" in parsed
                ? { ok: false, errors: [...parsed.issues] }
                : { ok: false, errors: [{ path: "schema_version", message: `${parsed.reason}: ${parsed.message}` }] };
          }
        }
      }
    }

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

import { extname } from "node:path";
import { Args, Command } from "@oclif/core";
import { captureStructuredFile } from "../../io/captured-file.js";
import { decodeStructuredDocumentV02 } from "../../schema/decode-envelope.js";
import type { LoopeixV01 } from "../../schema/loopeix-v01.js";
import type { LoopeixV02 } from "../../schema/loopeix-v02.js";
import { parseLoopeixDocument } from "../../schema/version-dispatch.js";

/** `loopeix spec inspect <file>` — show resolved roles, tasks, gates, and risk controls. */
export default class SpecInspect extends Command {
  static summary = "Show the roles, tasks, gates, and risk controls of a Loopeix.";
  static args = {
    file: Args.string({ description: "path to the Loopeix YAML file", required: true }),
  };
  static enableJsonFlag = true;

  public async run(): Promise<unknown> {
    const { args } = await this.parse(SpecInspect);
    const captured = await captureStructuredFile(args.file, null);
    if (!captured.ok) {
      this.error(`${captured.reason}: ${captured.message}`, { exit: 1 });
    }
    const selected = await captured.capture.selectFamily("authoring");
    if (!selected.ok) this.error(`${selected.reason}: ${selected.message}`, { exit: 1 });

    let s: LoopeixV01 | LoopeixV02;
    if (selected.schema_version === "0.1") {
      const parsed = await selected.capture.parseV01("authoring");
      if (!parsed.ok) this.error(`not a valid V01 Loopeix: ${parsed.reason}`, { exit: 1 });
      s = parsed.value as LoopeixV01;
    } else {
      const snapshot = await selected.capture.snapshotBytes();
      if (!snapshot.ok) this.error(`${snapshot.reason}: ${snapshot.message}`, { exit: 1 });
      const format = extname(args.file).toLowerCase() === ".json" ? "json" : "yaml";
      const decoded = decodeStructuredDocumentV02(snapshot.bytes, format);
      if (!decoded.ok) this.error(`${decoded.reason}: ${decoded.message}`, { exit: 1 });
      const parsed = parseLoopeixDocument(decoded.value);
      if (!parsed.ok || parsed.schema_version !== "0.2") {
        this.error(`not a valid V02 Loopeix — run 'loopeix spec validate ${args.file}'`, { exit: 1 });
      }
      s = parsed.value;
    }
    const summary = {
      schema_version: s.schema_version,
      loop_family: s.loop_family,
      version: s.version,
      workflow_pattern: s.workflow_pattern.type,
      roles: s.roles.map((r) => r.id),
      tasks: s.tasks.map((t) => t.id),
      gates: s.gates.map((g) => ({ id: g.id, blocking: g.blocking })),
      max_tier_without_approval: s.risk_controls.max_tier_without_approval,
    };
    if (!this.jsonEnabled()) {
      this.log(`${s.loop_family} ${s.version}  [${s.workflow_pattern.type}]`);
      this.log(`  roles: ${summary.roles.join(", ")}`);
      this.log(`  tasks: ${summary.tasks.join(", ")}`);
      this.log(`  gates: ${s.gates.map((g) => `${g.id}${g.blocking ? "*" : ""}`).join(", ")}  (* = blocking)`);
      this.log(`  max tier without approval: ${summary.max_tier_without_approval}`);
    }
    return summary;
  }
}

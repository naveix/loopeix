import { readFileSync } from "node:fs";
import { Args, Command } from "@oclif/core";
import { parse as parseYaml } from "yaml";
import { LoopeixShape } from "../../schema/loopeix.js";

/** `loopeix spec inspect <file>` — show resolved roles, tasks, gates, and risk controls. */
export default class SpecInspect extends Command {
  static summary = "Show the roles, tasks, gates, and risk controls of a Loopeix.";
  static args = {
    file: Args.string({ description: "path to the Loopeix YAML file", required: true }),
  };
  static enableJsonFlag = true;

  public async run(): Promise<unknown> {
    const { args } = await this.parse(SpecInspect);
    const data: unknown = parseYaml(readFileSync(args.file, "utf8"));
    const parsed = LoopeixShape.safeParse(data);
    if (!parsed.success) {
      this.error(`not a structurally valid Loopeix — run 'loopeix spec validate ${args.file}'`, { exit: 1 });
    }
    const s = parsed.data;
    const summary = {
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

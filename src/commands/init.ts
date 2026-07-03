import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Command, Flags } from "@oclif/core";

const WORKSPACE_YAML = `schema_version: "0.1"
workspace_version: "0.1"
loops_dir: "loops"
defaults:
  retention_class: "run"
  redaction_policy_version: "0.1"
engine_disclosure: >-
  Loopeix adds no telemetry and makes no hidden network calls. Codex CLI and
  Claude Code CLI may transmit data under their own settings; disclosed before each run.
`;

/** `loopeix init` — create a `.loopeix/` workspace in the current directory. */
export default class Init extends Command {
  static summary = "Create a .loopeix/ workspace (workspace.yaml + loops/) in the current directory.";
  static flags = {
    "dry-run": Flags.boolean({ description: "print what would be created without writing" }),
  };
  static enableJsonFlag = true;

  public async run(): Promise<{ created: string[]; dryRun: boolean }> {
    const { flags } = await this.parse(Init);
    const dryRun = flags["dry-run"];
    const root = join(process.cwd(), ".loopeix");
    const created: string[] = [];

    if (existsSync(root)) {
      this.warn(".loopeix already exists; nothing created.");
    } else if (dryRun) {
      if (!this.jsonEnabled()) {
        this.log("would create:");
        this.log("  .loopeix/");
        this.log("  .loopeix/loops/");
        this.log("  .loopeix/workspace.yaml");
      }
    } else {
      mkdirSync(join(root, "loops"), { recursive: true });
      writeFileSync(join(root, "workspace.yaml"), WORKSPACE_YAML);
      created.push(".loopeix/", ".loopeix/loops/", ".loopeix/workspace.yaml");
      if (!this.jsonEnabled()) {
        this.log("created:");
        for (const p of created) this.log(`  ${p}`);
      }
    }
    return { created, dryRun };
  }
}

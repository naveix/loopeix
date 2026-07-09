import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { Command, Flags } from "@oclif/core";
import { compilePrompt, type CompilePromptResult } from "../compiler/compile.js";

export interface CompileCommandResult extends CompilePromptResult {
  output_path?: string;
}

export default class Compile extends Command {
  static summary = "Compile a vague prompt into a bounded Loopeix loop or an explicit HOLD.";
  static description =
    "Routes a user prompt through the local item catalog. Safe, clear prompts produce a draft .loop.yaml; risky or ambiguous prompts return HOLD instead of fabricating authority.";
  static flags = {
    prompt: Flags.string({ description: "vague or scoped user prompt to compile", required: true }),
    out: Flags.string({ description: "write the generated .loop.yaml to this path" }),
    "workspace-root": Flags.string({
      description: "approved workspace root for the compiled loop",
      default: process.cwd(),
    }),
  };
  static examples = [
    '<%= config.bin %> compile --prompt "Fix the failing date parser test and prove the fix" --out .loopeix/loops/bugfix.loop.yaml',
  ];
  static enableJsonFlag = true;

  public async run(): Promise<CompileCommandResult> {
    const { flags } = await this.parse(Compile);
    const out = flags.out === undefined ? undefined : resolve(flags.out);
    const result = compilePrompt({
      prompt: flags.prompt,
      workspaceRoot: resolve(flags["workspace-root"]),
    });
    const commandResult: CompileCommandResult = out === undefined ? result : { ...result, output_path: out };

    if (result.ok && out !== undefined && result.yaml !== undefined) {
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, result.yaml);
    }

    if (!this.jsonEnabled()) {
      if (result.ok) {
        this.log(`COMPILED  ${result.catalog_resolution.selected_item_id}`);
        this.log(`Loop family: ${result.loop?.loop_family} ${result.loop?.version}`);
        if (out !== undefined) {
          this.log(`Wrote ${out}`);
        } else if (result.yaml !== undefined) {
          this.log(result.yaml);
        }
      } else {
        this.log(`HOLD  ${result.catalog_resolution.terminal_state}`);
        for (const evidence of result.catalog_resolution.selection_evidence) this.log(`  - ${evidence}`);
        for (const question of result.clarification_questions) this.log(`  ? ${question}`);
      }
    }

    if (!result.ok) process.exitCode = 1;
    return commandResult;
  }
}

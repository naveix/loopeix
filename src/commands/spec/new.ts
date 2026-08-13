import { Command, Flags } from "@oclif/core";
import Compile, { type CompileCommandResult } from "../compile.js";

export default class SpecNew extends Command {
  static summary = "Compile a prompt through the canonical V02 compiler path.";
  static description =
    "Delegates prompt-based authoring to loopeix compile without adding a second compiler, catalog, or output writer.";
  static enableJsonFlag = true;
  static flags = {
    "from-prompt": Flags.string({
      description: "prompt to compile into a bounded Loopeix document",
      required: true,
    }),
    "workspace-root": Flags.string({
      description: "approved workspace root for the compiled loop",
    }),
    bindings: Flags.string({
      description: "captured V02 binding-input JSON file",
    }),
    out: Flags.string({
      description: "write the generated .loop.yaml to this path",
    }),
    "include-internal": Flags.boolean({
      description: "include explicitly approved internal compiler detail",
      default: false,
    }),
  };

  public async run(): Promise<CompileCommandResult> {
    const { flags } = await this.parse(SpecNew);
    const argv = ["--prompt", flags["from-prompt"]];
    if (flags["workspace-root"] !== undefined) argv.push("--workspace-root", flags["workspace-root"]);
    if (flags.bindings !== undefined) argv.push("--bindings", flags.bindings);
    if (flags.out !== undefined) argv.push("--out", flags.out);
    if (flags["include-internal"]) argv.push("--include-internal");
    if (this.jsonEnabled()) argv.push("--json");
    return Compile.run(argv, this.config);
  }
}

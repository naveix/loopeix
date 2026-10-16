import { resolve } from "node:path";

import { Command, Flags } from "@oclif/core";

import {
  captureStructuredFile,
  releaseCapturedStructuredFile,
  type LegacyCompatibilityPolicy,
} from "../io/captured-file.js";
import {
  compileV02,
  type CompileRequestRejectReasonV02,
  type CompileRequestResultV02,
} from "../compiler/compile-v02.js";

const BINDING_CAPTURE_POLICY: LegacyCompatibilityPolicy = Object.freeze({
  mode: "operator-approved-finite",
  max_member_bytes: 4_194_304,
  max_total_bytes: 4_194_304,
  max_heap_bytes: 67_108_864,
  max_elapsed_ms: 30_000,
  approved_by: "operator",
});

type CompileCommandFailureReason = CompileRequestRejectReasonV02;
type SyntheticCompileFailureReason = Exclude<
  CompileRequestRejectReasonV02,
  "SENSITIVE_INPUT_REJECTED" | "SENSITIVE_OUTPUT_REJECTED"
>;

export type CompileCommandResult = CompileRequestResultV02;

const FAILURE_PRESENTATION: Readonly<
  Record<CompileCommandFailureReason, Readonly<{ exit: 1 | 4; message: string }>>
> = Object.freeze({
  INPUT_TOO_LARGE: { exit: 1, message: "Input exceeds its bounded size limit." },
  INVALID_DOCUMENT_ENVELOPE: { exit: 1, message: "Input document envelope is invalid." },
  INVALID_BINDING_INPUT: { exit: 1, message: "Approved binding input is invalid." },
  INVALID_CATALOG: { exit: 1, message: "Selected catalog data is invalid." },
  SENSITIVE_INPUT_REJECTED: { exit: 4, message: "Sensitive input was rejected." },
  SENSITIVE_OUTPUT_REJECTED: { exit: 4, message: "Sensitive generated output was rejected." },
  COMPILED_OUTPUT_TOO_LARGE: { exit: 1, message: "Compiled output exceeds its bounded size limit." },
  OUTPUT_SCAN_FAILED: { exit: 4, message: "Generated output could not be admitted safely." },
  OUTPUT_HASH_FAILED: { exit: 4, message: "Generated output could not be admitted safely." },
  OUTPUT_CAPTURE_FAILED: { exit: 4, message: "Generated output could not be admitted safely." },
  INVALID_V02_PROJECTION: { exit: 4, message: "Output projection is inconsistent with its source." },
  COMPILE_STORE_INVALID: { exit: 1, message: "Compile store is unavailable or invalid." },
  DESTINATION_EXISTS: { exit: 1, message: "Destination already exists." },
  COMPILE_ID_COLLISION_LIMIT: { exit: 1, message: "Compile identity allocation exhausted its collision limit." },
  IO_HELPER_UNAVAILABLE: { exit: 4, message: "Required filesystem helper is unavailable." },
  IO_IDENTITY_MISMATCH: { exit: 4, message: "Filesystem identity validation failed." },
  IO_DURABILITY_UNCONFIRMED: { exit: 4, message: "Filesystem durability could not be confirmed." },
});

function rejected(reason: SyntheticCompileFailureReason): CompileRequestResultV02 {
  return {
    ok: false,
    disposition: "rejected",
    terminal_state: null,
    reason,
    pack_ref: null,
    standalone_ref: null,
    findings: [],
  };
}

function mapBindingCaptureFailure(
  reason:
    | "INVALID_LEGACY_COMPATIBILITY_POLICY"
    | "INVALID_INPUT_FILE"
    | "INPUT_TOO_LARGE"
    | "LEGACY_REPLAY_RESOURCE_LIMIT"
    | "IO_IDENTITY_MISMATCH"
    | "IO_HELPER_UNAVAILABLE",
): CompileRequestResultV02 {
  switch (reason) {
    case "INPUT_TOO_LARGE":
      return rejected("INPUT_TOO_LARGE");
    case "INVALID_INPUT_FILE":
    case "IO_IDENTITY_MISMATCH":
      return rejected("IO_IDENTITY_MISMATCH");
    case "INVALID_LEGACY_COMPATIBILITY_POLICY":
    case "LEGACY_REPLAY_RESOURCE_LIMIT":
    case "IO_HELPER_UNAVAILABLE":
      return rejected("IO_HELPER_UNAVAILABLE");
  }
}

function holdMessage(result: Extract<CompileRequestResultV02, { disposition: "hold" }>): string {
  switch (result.reason) {
    case "CATALOG_AMBIGUOUS":
      return "Catalog selection requires clarification.";
    case "RISK_BOUNDARY_UNRESOLVED":
      return "Requested authority exceeds the resolved risk boundary.";
    case "NO_CATALOG_ITEM":
      return "No catalog item satisfies the admitted request.";
    case "PROJECT_BINDING_REQUIRED":
      return "Compilation requires approved project bindings.";
  }
}

export default class Compile extends Command {
  static summary = "Compile a new prompt into a bounded V02 loop or an explicit HOLD.";
  static description =
    "Compiles a new prompt through the fixed V02 catalog and writes a manifest-last local compile pack. It never selects or downgrades to V01.";
  static flags = {
    prompt: Flags.string({ description: "raw user request to compile", required: true }),
    "workspace-root": Flags.string({
      description: "approved workspace root containing .loopeix/compiles",
      default: process.cwd(),
    }),
    bindings: Flags.string({ description: "strict V02 binding-input JSON file" }),
    out: Flags.string({ description: "create a standalone generated .loop.yaml at this path" }),
    "include-internal": Flags.boolean({
      description: "request internal detail (reserved; the closed S35 result exposes no additional fields)",
      dependsOn: ["json"],
    }),
  };
  static examples = [
    '<%= config.bin %> compile --prompt "Fix the failing date parser test and prove the fix"',
  ];
  static enableJsonFlag = true;

  private present(result: CompileRequestResultV02, workspaceRoot: string, outputPath: string | undefined): void {
    if (result.ok) {
      process.exitCode = 0;
      if (!this.jsonEnabled()) {
        this.log(`COMPILED  ${result.pack_ref}`);
        this.log(`Pack ${resolve(workspaceRoot, ".loopeix", "compiles", result.pack_ref)}`);
        if (result.standalone_ref !== null && outputPath !== undefined) this.log(`Wrote ${outputPath}`);
      }
      return;
    }

    if (result.disposition === "hold") {
      process.exitCode = 1;
      if (!this.jsonEnabled()) {
        this.log(`HOLD  ${result.terminal_state} [${result.reason}] ${holdMessage(result)}`);
        this.log(`Pack ${resolve(workspaceRoot, ".loopeix", "compiles", result.pack_ref)}`);
      }
      return;
    }

    const presentation = FAILURE_PRESENTATION[result.reason];
    process.exitCode = presentation.exit;
    if (!this.jsonEnabled()) this.logToStderr(`ERROR [${result.reason}] ${presentation.message}`);
  }

  public async run(): Promise<CompileCommandResult> {
    const { flags } = await this.parse(Compile);
    const workspaceRoot = resolve(flags["workspace-root"]);
    const outputPath = flags.out === undefined ? undefined : resolve(flags.out);
    let result: CompileRequestResultV02;

    if (flags.bindings === undefined) {
      result = await compileV02({
        prompt: flags.prompt,
        workspace_root: workspaceRoot,
        ...(outputPath === undefined ? {} : { standalone_output_path: outputPath }),
      });
    } else {
      const captured = await captureStructuredFile(resolve(flags.bindings), BINDING_CAPTURE_POLICY);
      if (!captured.ok) {
        result = mapBindingCaptureFailure(captured.reason);
      } else {
        const snapshot = await captured.capture.snapshotBytes();
        const released = await releaseCapturedStructuredFile(captured.capture);
        if (!snapshot.ok || !released.ok) {
          result = rejected("IO_HELPER_UNAVAILABLE");
        } else {
          result = await compileV02({
            prompt: flags.prompt,
            workspace_root: workspaceRoot,
            binding_payload_bytes: snapshot.bytes,
            ...(outputPath === undefined ? {} : { standalone_output_path: outputPath }),
          });
        }
      }
    }

    this.present(result, workspaceRoot, outputPath);
    return result;
  }
}

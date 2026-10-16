import { chmod, lstat, mkdir, open as openFile, readdir, realpath, rmdir, stat, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { hashCanonical, hashRawBytes } from "../hash.js";
import { CompilePackManifest } from "../compiler/pack.js";
import { ApprovedIntakeBrief } from "../compiler/records.js";
import { ResolvedRunPlan } from "../schema/runtime.js";
import { detectCredentialV02 } from "../security/credential-detector-v02.js";
import { requestCompilerWriterHelper } from "./compiler-writer-helper.js";
import { replacePlanReportProjectionSetV02 } from "./plan-report-writer-v02.js";
import type {
  CompilerWriterHelperRequest,
  CompilerWriterHelperResponse,
} from "./compiler-writer-protocol.js";
import {
  captureStructuredFile,
  parseDirectChildName,
  releaseCapturedStructuredFile,
  type CapturedStructuredFileResult,
  type CapturedStructuredFile,
  type DirectChildName,
  type LegacyCompatibilityPolicy,
  type LegacyV01DocumentKind,
  type LegacyV01ParseResult,
} from "./captured-file.js";

export { parseDirectChildName } from "./captured-file.js";
export type { DirectChildName, LegacyCompatibilityPolicy } from "./captured-file.js";

type Hash = string;
type MachineId = string;
type HumanId = string;
type CompilerBundleId = string;
type CompilerTerminalStateV02 = string;

export type V02OutputPurpose = "standalone-loop" | "compile-pack" | "planned-run" | "plan-report";

export type ConfirmedV02CompilerProjection = {
  readonly schema_version: "0.2";
  readonly compiler_bundle_id: CompilerBundleId;
  readonly catalog_version_hash: Hash;
  readonly binding_input_hash: Hash;
  readonly requested_output_purposes:
    | readonly ["compile-pack"]
    | readonly ["standalone-loop", "compile-pack"];
  readonly output_budget_bytes: 33_554_432;
  readonly __confirmed_v02_compiler_projection: unique symbol;
};

export type ConfirmedV02PlanProjection = {
  readonly schema_version: "0.2";
  readonly source_pack_root_hash: Hash;
  readonly run_id: MachineId;
  readonly output_budget_bytes: 33_554_432;
  readonly __confirmed_v02_plan_projection: unique symbol;
};

export type ConfirmedV02ReportProjection = {
  readonly schema_version: "0.2";
  readonly run_id: MachineId;
  readonly resolved_run_plan_hash: Hash;
  readonly renderer_bundle_id: MachineId;
  readonly renderer_bundle_hash: Hash;
  readonly generation_id: MachineId;
  readonly output_budget_bytes: 33_554_432;
  readonly __confirmed_v02_report_projection: unique symbol;
};

export type ConfirmedV02OutputProjection =
  | ConfirmedV02CompilerProjection
  | ConfirmedV02PlanProjection
  | ConfirmedV02ReportProjection;

export type ConfirmedV02ProjectionResult<T extends ConfirmedV02OutputProjection> =
  | { ok: true; projection: T }
  | { ok: false; reason: "INVALID_V02_PROJECTION" | "COMPILE_STORE_INVALID"; message: string };

export type V02OutputAdmissionSession = {
  readonly schema_version: "0.2";
  readonly purpose: V02OutputPurpose;
  readonly allowed_members: readonly DirectChildName[];
  readonly max_member_bytes: 4_194_304;
  readonly max_total_bytes: 33_554_432;
  readonly budget_scope: "projection-operation";
  readonly __v02_output_admission_session: unique symbol;
};

export type V02OutputAdmissionSessionResult =
  | { ok: true; session: V02OutputAdmissionSession }
  | { ok: false; reason: "INVALID_V02_PROJECTION" | "INVALID_OUTPUT_PURPOSE"; message: string };

export type CapturedOutputBytesV02 = {
  readonly schema_version: "0.2";
  readonly purpose: V02OutputPurpose;
  readonly member_name: DirectChildName;
  readonly byte_length: number;
  readonly __captured_output_bytes_v02: unique symbol;
};

export type CapturedOutputBytesResult =
  | { ok: true; capture: CapturedOutputBytesV02 }
  | {
      ok: false;
      reason:
        | "INVALID_OUTPUT_BYTE_VIEW"
        | "INVALID_OUTPUT_CAPTURE"
        | "COMPILED_OUTPUT_TOO_LARGE"
        | "OUTPUT_CAPTURE_FAILED";
      message: string;
    };

export type AdmittedOutputBytes = {
  readonly schema_version: "0.2";
  readonly purpose: V02OutputPurpose;
  readonly member_name: DirectChildName;
  readonly byte_length: number;
  readonly sha256: Hash;
  readonly __admitted_output_bytes: unique symbol;
};

export type AdmittedOutputBytesResult =
  | { ok: true; output: AdmittedOutputBytes }
  | { ok: false; reason: "SENSITIVE_OUTPUT_REJECTED"; member_id: DirectChildName; rule_id: string }
  | {
      ok: false;
      reason:
        | "COMPILED_OUTPUT_TOO_LARGE"
        | "INVALID_OUTPUT_CAPTURE"
        | "OUTPUT_SCAN_FAILED"
        | "OUTPUT_HASH_FAILED";
      message: string;
    };

export type SealedV02OutputSet = {
  readonly schema_version: "0.2";
  readonly purpose: V02OutputPurpose;
  readonly ordered_members: readonly {
    readonly name: DirectChildName;
    readonly byte_length: number;
    readonly sha256: Hash;
  }[];
  readonly total_byte_length: number;
  readonly __sealed_v02_output_set: unique symbol;
};

export type SealedV02OutputSetResult =
  | { ok: true; output_set: SealedV02OutputSet }
  | { ok: false; reason: "INVALID_OUTPUT_CAPTURE" | "OUTPUT_SET_INCOMPLETE"; message: string };

export type AnchoredDestinationRootV02 = {
  readonly root_identity: { readonly device: string; readonly inode: string };
  readonly boundary_kind: "standalone-parent" | "compile-store" | "runs-root" | "run-directory";
  readonly __anchored_destination_root_v02: unique symbol;
};

export type V02StandaloneLoopWriteAuthority = {
  readonly purpose: "standalone-loop";
  readonly root_identity: { readonly device: string; readonly inode: string };
  readonly compile_id: MachineId;
  readonly source_authoring_hash: Hash;
  readonly generated_loop_hash: Hash;
  readonly __v02_standalone_loop_write_authority: unique symbol;
};

export type V02CompilePackWriteAuthority = {
  readonly purpose: "compile-pack";
  readonly root_identity: { readonly device: string; readonly inode: string };
  readonly compile_id: MachineId;
  readonly compiler_bundle_id: CompilerBundleId;
  readonly catalog_version_hash: Hash;
  readonly binding_input_hash: Hash;
  readonly terminal_state: CompilerTerminalStateV02;
  readonly ordered_member_hashes: readonly Hash[];
  readonly __v02_compile_pack_write_authority: unique symbol;
};

export type V02PlannedRunWriteAuthority = {
  readonly purpose: "planned-run";
  readonly root_identity: { readonly device: string; readonly inode: string };
  readonly source_pack_root_hash: Hash;
  readonly run_id: MachineId;
  readonly loop_family: HumanId;
  readonly workspace_root_hash: Hash;
  readonly engine: "codex" | "claude";
  readonly ordered_member_hashes: readonly Hash[];
  readonly __v02_planned_run_write_authority: unique symbol;
};

export type V02PlanReportWriteAuthority = {
  readonly purpose: "plan-report";
  readonly root_identity: { readonly device: string; readonly inode: string };
  readonly run_id: MachineId;
  readonly resolved_run_plan_hash: Hash;
  readonly compile_pack_manifest_hash: Hash;
  readonly generated_loop_hash: Hash;
  readonly report_projection_version: "0.1";
  readonly renderer_bundle_id: MachineId;
  readonly renderer_bundle_hash: Hash;
  readonly generation_id: MachineId;
  readonly __v02_plan_report_write_authority: unique symbol;
};

export type V02WriteAuthority =
  | V02StandaloneLoopWriteAuthority
  | V02CompilePackWriteAuthority
  | V02PlannedRunWriteAuthority
  | V02PlanReportWriteAuthority;

export type V02WriteAuthorityResult =
  | { ok: true; authority: V02WriteAuthority }
  | {
      ok: false;
      reason: "INVALID_V02_PROJECTION" | "INVALID_OUTPUT_CAPTURE" | "INVALID_INPUT_ROOT";
      message: string;
    };

export type V02CompilerWriteAuthoritySet = {
  readonly standalone_loop: V02StandaloneLoopWriteAuthority | null;
  readonly compile_pack: V02CompilePackWriteAuthority;
  readonly combined_output_bytes: number;
  readonly __v02_compiler_write_authority_set: unique symbol;
};

export type V02CompilerWriteAuthoritySetResult =
  | { ok: true; authorities: V02CompilerWriteAuthoritySet }
  | {
      ok: false;
      reason: "INVALID_V02_PROJECTION" | "INVALID_OUTPUT_CAPTURE" | "INVALID_INPUT_ROOT";
      message: string;
    };

export type CompilerOutputWriteResultV02 =
  | {
      readonly ok: true;
      readonly pack_ref: MachineId;
      readonly standalone_ref: DirectChildName | null;
    }
  | {
      readonly ok: false;
      readonly reason: "DESTINATION_EXISTS";
      readonly collision_destination: "compile-pack" | "standalone-loop";
      readonly message: string;
      readonly pack_ref: null;
      readonly standalone_ref: null;
    }
  | {
      readonly ok: false;
      readonly reason:
        | "INVALID_OUTPUT_CAPTURE"
        | "OUTPUT_CAPTURE_FAILED"
        | "IO_HELPER_UNAVAILABLE"
        | "IO_IDENTITY_MISMATCH"
        | "IO_DURABILITY_UNCONFIRMED";
      readonly message: string;
      readonly pack_ref: null;
      readonly standalone_ref: null;
    };

export type CompilerWriterOptions = Readonly<{
  runHelper?: (
    workingDirectory: string,
    request: CompilerWriterHelperRequest,
  ) => Promise<CompilerWriterHelperResponse>;
}>;

export type PrepareV02PlannedRunsRootResult =
  | { ok: true; root: AnchoredDestinationRootV02 }
  | {
      ok: false;
      reason: "INVALID_INPUT_ROOT" | "IO_IDENTITY_MISMATCH" | "IO_DURABILITY_UNCONFIRMED";
      message: string;
    };

export type PlannedRunOutputWriteResultV02 =
  | {
      readonly ok: true;
      readonly run_id: MachineId;
      readonly resolved_run_plan_hash: Hash;
      readonly run_ref: string;
    }
  | {
      readonly ok: false;
      readonly reason: "DESTINATION_EXISTS" | "INVALID_OUTPUT_CAPTURE" | "IO_IDENTITY_MISMATCH" | "IO_DURABILITY_UNCONFIRMED";
      readonly message: string;
      readonly run_id: null;
      readonly resolved_run_plan_hash: null;
      readonly run_ref: string | null;
    };

/** Package-internal deterministic fault seam; production callers omit it. */
export type PlannedRunWriterTestOptions = Readonly<{
  after_all_reservations?: () => void;
  after_member_fsync?: (name: DirectChildName) => void;
}>;

export type V02DestinationCapability = {
  readonly schema_version: "0.2";
  readonly purpose: V02OutputPurpose;
  readonly lineage_hash: Hash;
  readonly __v02_destination_capability: unique symbol;
};

export type V01DestinationCapability = {
  readonly schema_version: "0.1";
  readonly purpose: "replay-pack-copy" | "planned-run";
  readonly source_pack_root_hash: Hash;
  readonly catalog_version_hash: Hash;
  readonly __v01_destination_capability: unique symbol;
};

export type DestinationCapability = V02DestinationCapability | V01DestinationCapability;

export type AnchoredIoResult =
  | { ok: true }
  | {
      ok: false;
      reason:
        | "INVALID_INPUT_ROOT"
        | "INVALID_INPUT_FILE"
        | "DESTINATION_EXISTS"
        | "INPUT_TOO_LARGE"
        | "INVALID_OUTPUT_CAPTURE"
        | "OUTPUT_CAPTURE_FAILED"
        | "IO_HELPER_UNAVAILABLE"
        | "IO_IDENTITY_MISMATCH"
        | "IO_DURABILITY_UNCONFIRMED"
        | "REPORT_BUILD_BUSY"
        | "REPORT_BUILD_STALE_LOCK";
      message: string;
    };

export interface AnchoredReadSession {
  readonly root_identity: { device: string; inode: string };
  listDirectEntries(): Promise<
    | { ok: true; entries: readonly AnchoredDirectoryEntry[] }
    | { ok: false; reason: "INVALID_INPUT_ROOT" | "IO_IDENTITY_MISMATCH"; message: string }
  >;
  captureFile(
    name: DirectChildName,
    max_member_bytes: number,
    remaining_total_bytes: number,
  ): Promise<CapturedStructuredFileResult>;
  close(): Promise<AnchoredIoResult>;
}

export type AnchoredDirectoryEntry = {
  readonly name: string;
  readonly kind: "regular-file" | "directory" | "symlink" | "other";
};

export interface AnchoredWriteSession<TCapability extends DestinationCapability> {
  readonly root_identity: { device: string; inode: string };
  readonly destination: TCapability extends V02DestinationCapability
    ? { readonly schema_version: "0.2"; readonly purpose: V02OutputPurpose; readonly lineage_hash: Hash }
    : {
        readonly schema_version: "0.1";
        readonly purpose: "replay-pack-copy" | "planned-run";
        readonly source_pack_root_hash: Hash;
        readonly catalog_version_hash: Hash;
      };
  createFileExclusive(request: unknown): Promise<AnchoredIoResult>;
  createChildDirectorySession(
    name: DirectChildName,
    mode: 0o700,
  ): Promise<
    | { ok: true; session: AnchoredWriteSession<TCapability> }
    | {
        ok: false;
        reason: "DESTINATION_EXISTS" | "IO_HELPER_UNAVAILABLE" | "IO_IDENTITY_MISMATCH" | "IO_DURABILITY_UNCONFIRMED";
        message: string;
      }
  >;
  replacePlanReportProjectionSet(request: { readonly generation_id: MachineId }): Promise<AnchoredIoResult>;
  close(): Promise<AnchoredIoResult>;
}

export type CapturedCompilePack = {
  readonly schema_version: "0.1" | "0.2";
  readonly replay_capture_origin: "captured-source" | "frozen-regeneration" | null;
  readonly total_byte_length: number;
  readonly source_pack_root_hash: Hash;
  readonly __captured_compile_pack: unique symbol;
  memberNames(): readonly DirectChildName[];
  memberByteLength(name: DirectChildName): number;
  snapshotMemberBytes(name: DirectChildName): Promise<
    | { ok: true; bytes: Uint8Array }
    | { ok: false; reason: "LEGACY_REPLAY_RESOURCE_LIMIT" | "IO_HELPER_UNAVAILABLE"; message: string }
  >;
  parseV01Member(name: DirectChildName, kind: LegacyV01DocumentKind): Promise<LegacyV01ParseResult>;
};

export type V01SourcePackRegistrationAdapter = {
  readonly origin: "captured-source";
  readonly __v01_source_pack_registration_adapter: unique symbol;
};
export type V01RegeneratedPackRegistrationAdapter = {
  readonly origin: "frozen-regeneration";
  readonly source_pack_root_hash: Hash;
  readonly catalog_version_hash: Hash;
  readonly __v01_regenerated_pack_registration_adapter: unique symbol;
};
export type CapturedPackIdentityV01 = {
  readonly selector: V01ReplaySelector;
  readonly source_pack_root_hash: Hash;
  readonly members: readonly { name: DirectChildName; byte_length: number; sha256: Hash }[];
  readonly __captured_pack_identity_v01: unique symbol;
};
export type V01ReplaySelector = { readonly schema_version: "0.1"; readonly catalog_version_hash: Hash };
export type V01SourcePackAccess = { readonly origin: "captured-source"; readonly __v01_source_pack_access: unique symbol };
export type V01RegeneratedPackAccess = { readonly origin: "frozen-regeneration"; readonly __v01_regenerated_pack_access: unique symbol };
export type ExactV01ReplaySuccess = {
  readonly captured_pack_identity: CapturedPackIdentityV01;
  readonly selector: V01ReplaySelector;
  readonly source_pack_root_hash: Hash;
  readonly __exact_v01_replay_success: unique symbol;
};
export type V01ReplayOutputAuthority = {
  readonly selector: V01ReplaySelector;
  readonly source_pack_root_hash: Hash;
  mintPackMemberCopy(name: DirectChildName): Promise<VerifiedV01ReplayOutputBytesResult>;
  mintFrozenPlanProjection(request: FrozenV01PlanProjectionRequest): Promise<VerifiedV01ReplayOutputBytesResult>;
  mintDestinationCapability(root_path: string, purpose: "replay-pack-copy" | "planned-run"): Promise<V01DestinationCapabilityResult>;
};

export type V01PackRegistrationAdapterResult<TAdapter> =
  | { ok: true; adapter: TAdapter }
  | { ok: false; reason: "INVALID_V01_REPLAY_OUTPUT" | "LEGACY_REPLAY_RESOURCE_LIMIT" | "IO_HELPER_UNAVAILABLE"; message: string };
export interface FrozenV01RegenerationCaptureSession {
  readonly source_pack_root_hash: Hash;
  readonly catalog_version_hash: Hash;
  captureMember(name: DirectChildName, bytes: Uint8Array): Promise<AnchoredIoResult>;
  seal(): Promise<V01PackRegistrationAdapterResult<V01RegeneratedPackRegistrationAdapter>>;
  abort(): Promise<AnchoredIoResult>;
}
export type RegisteredCapturedCompilePackV01Result =
  | { ok: true; pack: CapturedCompilePack }
  | { ok: false; reason: "INVALID_V01_REPLAY_OUTPUT" | "LEGACY_REPLAY_RESOURCE_LIMIT" | "IO_HELPER_UNAVAILABLE"; message: string };
export type V01PlanProjectionName = "approved-intake-brief" | "resolved-run-plan";
export type FrozenV01PlanProjectionRequest =
  | { readonly projection_name: "approved-intake-brief" }
  | { readonly projection_name: "resolved-run-plan"; readonly input: { readonly engine: "codex" | "claude"; readonly workspace_root: string; readonly created_at: string } };
export type VerifiedV01ReplayOutputBytes = {
  readonly schema_version: "0.1";
  readonly byte_length: number;
  readonly sha256: Hash;
  readonly source_pack_root_hash: Hash;
  readonly catalog_version_hash: Hash;
  readonly projection_kind: "pack-member-copy" | "frozen-plan-projection";
  readonly source_member_name: DirectChildName | null;
  readonly projection_name: V01PlanProjectionName | null;
  readonly __verified_v01_replay_output_bytes: unique symbol;
};
export type VerifiedV01ReplayOutputBytesResult =
  | { ok: true; output: VerifiedV01ReplayOutputBytes }
  | { ok: false; reason: "INVALID_OUTPUT_CAPTURE" | "INVALID_V01_REPLAY_OUTPUT" | "OUTPUT_HASH_FAILED"; message: string };
export type V01DestinationCapabilityResult =
  | { ok: true; capability: V01DestinationCapability }
  | { ok: false; reason: "INVALID_INPUT_ROOT" | "INVALID_V01_REPLAY_OUTPUT" | "IO_HELPER_UNAVAILABLE" | "IO_IDENTITY_MISMATCH"; message: string };

const STANDALONE_MEMBERS = ["generated.loop.yaml"] as const;
const PLANNED_RUN_MEMBERS = ["work-item.json", "binding-input.json", "intake-record.json", "catalog-resolution.json", "compilation-record.json", "compile-pack-manifest.json", "generated.loop.yaml", "intake-brief.json", "resolved-run-plan.json"] as const;
const PLAN_REPORT_MEMBERS = ["plan-report.md", "plan-report.html", "plan-report-input.json"] as const;
const COMPILED_PACK_MEMBERS = ["work-item.json", "binding-input.json", "intake-record.json", "catalog-resolution.json", "compilation-record.json", "compile-report.md", "generated.loop.yaml", "pack-manifest.json"] as const;
const HOLD_PACK_MEMBERS = ["work-item.json", "binding-input.json", "intake-record.json", "catalog-resolution.json", "compile-report.md", "pack-manifest.json"] as const;

type ProducerDescriptor =
  | { kind: "compiler"; schema_version: "0.2"; compiler_bundle_id: string; catalog_version_hash: Hash; binding_input_hash: Hash; requested_output_purposes: readonly V02OutputPurpose[]; output_budget_bytes: 33_554_432; compile_id: string; source_authoring_hash: Hash; terminal_state: string }
  | { kind: "plan"; schema_version: "0.2"; source_pack_root_hash: Hash; run_id: string; output_budget_bytes: 33_554_432; loop_family: string; workspace_root_hash: Hash; engine: "codex" | "claude" }
  | { kind: "report"; schema_version: "0.2"; run_id: string; resolved_run_plan_hash: Hash; renderer_bundle_id: string; renderer_bundle_hash: Hash; generation_id: string; output_budget_bytes: 33_554_432; compile_pack_manifest_hash: Hash; generated_loop_hash: Hash };
type ProjectionState = { descriptor: ProducerDescriptor; allowed: ReadonlyMap<V02OutputPurpose, readonly DirectChildName[]>; charged: number; poisoned: boolean; opened: Set<V02OutputPurpose>; sessions: Set<V02OutputAdmissionSession>; consumed: boolean };
type AdmissionState = { projection: ConfirmedV02OutputProjection; purpose: V02OutputPurpose; ordered: readonly DirectChildName[]; status: "open" | "poisoned" | "sealed"; members: Map<DirectChildName, { status: "unseen" | "reserved" | "admitted"; length?: number; admitted?: AdmittedOutputBytes }> };
type CaptureState = { session: V02OutputAdmissionSession; name: DirectChildName; bytes: Uint8Array; consumed: boolean };
type AdmittedState = { session: V02OutputAdmissionSession; name: DirectChildName; bytes: Uint8Array; sha256: Hash; consumed: boolean };
type SealedState = { projection: ConfirmedV02OutputProjection; purpose: V02OutputPurpose; ordered: readonly { name: DirectChildName; byte_length: number; sha256: Hash }[]; bytes: ReadonlyMap<DirectChildName, Uint8Array>; consumed: boolean };

const consumedProducerInputs = new WeakSet<object>();
const projectionRegistry = new WeakMap<object, ProjectionState>();
const admissionRegistry = new WeakMap<object, AdmissionState>();
const captureRegistry = new WeakMap<object, CaptureState>();
const admittedRegistry = new WeakMap<object, AdmittedState>();
const sealedRegistry = new WeakMap<object, SealedState>();
const rootRegistry = new WeakMap<object, {
  path: string;
  device: string;
  inode: string;
  boundary: AnchoredDestinationRootV02["boundary_kind"];
  prepared_planned_loop_family: string | null;
}>();
const readSessionRegistry = new WeakMap<object, { path: string; open: boolean }>();
const authorityRegistry = new WeakMap<object, {
  projection: ConfirmedV02OutputProjection;
  root: AnchoredDestinationRootV02;
  output: SealedState;
  resolved_run_plan_hash: Hash | null;
  consumed: boolean;
}>();
const compilerAuthoritySetRegistry = new WeakMap<object, {
  compile: V02CompilePackWriteAuthority;
  standalone: V02StandaloneLoopWriteAuthority | null;
  consumed: boolean;
}>();
const capabilityRegistry = new WeakMap<object, {
  path: string;
  device: string;
  inode: string;
  purpose: V02OutputPurpose;
  output: SealedState;
  report_authority: V02PlanReportWriteAuthority | null;
  consumed: boolean;
}>();

type V01MemberStore =
  | { kind: "helper-capture"; capture: CapturedStructuredFile }
  | {
      kind: "captured-source";
      bytes: Uint8Array;
      parse_kind: LegacyV01DocumentKind | null;
      parse_result: LegacyV01ParseResult | null;
    }
  | { kind: "private-bytes"; bytes: Uint8Array };
type V01PackState = {
  origin: "captured-source" | "frozen-regeneration";
  members: ReadonlyMap<DirectChildName, V01MemberStore>;
  rows: readonly { name: DirectChildName; byte_length: number; sha256: Hash }[];
  rootHash: Hash;
  boundIdentity: CapturedPackIdentityV01 | null;
  accessIssued: boolean;
};
type V01IdentityState = { pack: CapturedCompilePack; packState: V01PackState; selector: V01ReplaySelector; exactIssued: boolean; authorityIssued: boolean };
const sourceAdapterRegistry = new WeakMap<object, { members: ReadonlyMap<DirectChildName, V01MemberStore>; policy: LegacyCompatibilityPolicy; consumed: boolean }>();
const regenerationSessionRegistry = new WeakMap<object, { identity: CapturedPackIdentityV01; expected: readonly DirectChildName[]; policy: LegacyCompatibilityPolicy; members: Map<DirectChildName, Uint8Array>; total: number; state: "open" | "sealed" | "aborted" }>();
const regenerationAdapterRegistry = new WeakMap<object, { identity: CapturedPackIdentityV01; members: ReadonlyMap<DirectChildName, Uint8Array>; policy: LegacyCompatibilityPolicy; consumed: boolean }>();
const v01PackRegistry = new WeakMap<object, V01PackState>();
const sourceAccessRegistry = new WeakMap<object, { pack: CapturedCompilePack; consumed: boolean }>();
const regeneratedAccessRegistry = new WeakMap<object, { pack: CapturedCompilePack; identity: CapturedPackIdentityV01; consumed: boolean }>();
const v01IdentityRegistry = new WeakMap<object, V01IdentityState>();
const exactReplayRegistry = new WeakMap<object, { identity: CapturedPackIdentityV01; consumed: boolean }>();
const v01AuthorityRegistry = new WeakMap<object, { identity: CapturedPackIdentityV01; memberMints: Set<DirectChildName>; projectionMints: Set<V01PlanProjectionName>; destinationPurposes: Set<string> }>();
const verifiedV01OutputRegistry = new WeakMap<object, { identity: CapturedPackIdentityV01; bytes: Uint8Array; consumed: boolean }>();
const v01CapabilityRegistry = new WeakMap<object, { path: string; device: string; inode: string; identity: CapturedPackIdentityV01; purpose: "replay-pack-copy" | "planned-run"; consumed: boolean }>();

const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const MACHINE_RE = /^[a-z]+_[a-z0-9]+(?:_[a-z0-9]+)*$/;
const HUMAN_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
function isRecord(input: unknown): input is Record<string, unknown> { return typeof input === "object" && input !== null && !Array.isArray(input); }
function exactKeys(input: Record<string, unknown>, keys: readonly string[]): boolean { const actual = Object.keys(input).sort(); const expected = [...keys].sort(); return actual.length === expected.length && actual.every((key, index) => key === expected[index]); }
function directNames(values: readonly string[]): readonly DirectChildName[] { return values.map((name) => parseDirectChildName(name)!).filter((name): name is DirectChildName => name !== null); }

function parseV02ProducerProjectionInput(input: unknown): ProducerDescriptor | null {
  if (!isRecord(input) || typeof input.kind !== "string") return null;
  const hash = (value: unknown): value is string => typeof value === "string" && HASH_RE.test(value);
  const machine = (value: unknown): value is string => typeof value === "string" && MACHINE_RE.test(value);
  let descriptor: ProducerDescriptor | null = null;
  if (input.kind === "compiler" && exactKeys(input, ["kind", "schema_version", "compiler_bundle_id", "catalog_version_hash", "binding_input_hash", "requested_output_purposes", "output_budget_bytes", "compile_id", "source_authoring_hash", "terminal_state"])) {
    const purposes = input.requested_output_purposes;
    const validPurposes = Array.isArray(purposes) && (purposes.join("|") === "compile-pack" || purposes.join("|") === "standalone-loop|compile-pack");
    const terminal = input.terminal_state;
    if (input.schema_version === "0.2" && machine(input.compiler_bundle_id) && hash(input.catalog_version_hash) && hash(input.binding_input_hash) && validPurposes && input.output_budget_bytes === 33_554_432 && machine(input.compile_id) && hash(input.source_authoring_hash) && typeof terminal === "string" && ["compiled", "hold-ambiguous", "hold-risk", "hold-no-item", "hold-project-binding-required"].includes(terminal) && (terminal === "compiled" || !(purposes as unknown[]).includes("standalone-loop"))) descriptor = input as ProducerDescriptor;
  } else if (input.kind === "plan" && exactKeys(input, ["kind", "schema_version", "source_pack_root_hash", "run_id", "output_budget_bytes", "loop_family", "workspace_root_hash", "engine"])) {
    if (input.schema_version === "0.2" && hash(input.source_pack_root_hash) && machine(input.run_id) && input.output_budget_bytes === 33_554_432 && typeof input.loop_family === "string" && HUMAN_RE.test(input.loop_family) && hash(input.workspace_root_hash) && (input.engine === "codex" || input.engine === "claude")) descriptor = input as ProducerDescriptor;
  } else if (input.kind === "report" && exactKeys(input, ["kind", "schema_version", "run_id", "resolved_run_plan_hash", "renderer_bundle_id", "renderer_bundle_hash", "generation_id", "output_budget_bytes", "compile_pack_manifest_hash", "generated_loop_hash"])) {
    if (input.schema_version === "0.2" && machine(input.run_id) && hash(input.resolved_run_plan_hash) && machine(input.renderer_bundle_id) && hash(input.renderer_bundle_hash) && machine(input.generation_id) && input.output_budget_bytes === 33_554_432 && hash(input.compile_pack_manifest_hash) && hash(input.generated_loop_hash)) descriptor = input as ProducerDescriptor;
  }
  return descriptor === null ? null : Object.freeze({ ...descriptor });
}

function allowedFor(descriptor: ProducerDescriptor): ReadonlyMap<V02OutputPurpose, readonly DirectChildName[]> {
  if (descriptor.kind === "compiler") {
    const rows: [V02OutputPurpose, readonly DirectChildName[]][] = [["compile-pack", directNames(descriptor.terminal_state === "compiled" ? COMPILED_PACK_MEMBERS : HOLD_PACK_MEMBERS)]];
    if (descriptor.requested_output_purposes[0] === "standalone-loop") rows.unshift(["standalone-loop", directNames(STANDALONE_MEMBERS)]);
    return new Map(rows);
  }
  return new Map([[descriptor.kind === "plan" ? "planned-run" : "plan-report", directNames(descriptor.kind === "plan" ? PLANNED_RUN_MEMBERS : PLAN_REPORT_MEMBERS)]]);
}

function poisonProjection(projection: ConfirmedV02OutputProjection): void {
  const state = projectionRegistry.get(projection);
  if (state === undefined) return;
  state.poisoned = true;
  for (const session of state.sessions) { const sessionState = admissionRegistry.get(session); if (sessionState?.status === "open") sessionState.status = "poisoned"; }
}

function invalidV02Projection<T extends ConfirmedV02OutputProjection>(): ConfirmedV02ProjectionResult<T> {
  return { ok: false, reason: "INVALID_V02_PROJECTION", message: "The V02 projection is not registered." };
}

export function confirmV02CompilerProjection(input: unknown): ConfirmedV02ProjectionResult<ConfirmedV02CompilerProjection> {
  if (!isRecord(input) || consumedProducerInputs.has(input)) return invalidV02Projection();
  const descriptor = parseV02ProducerProjectionInput(input);
  if (descriptor?.kind !== "compiler") return invalidV02Projection();
  consumedProducerInputs.add(input);
  const projection = Object.freeze({ schema_version: "0.2", compiler_bundle_id: descriptor.compiler_bundle_id, catalog_version_hash: descriptor.catalog_version_hash, binding_input_hash: descriptor.binding_input_hash, requested_output_purposes: Object.freeze([...descriptor.requested_output_purposes]), output_budget_bytes: 33_554_432 }) as ConfirmedV02CompilerProjection;
  projectionRegistry.set(projection, { descriptor, allowed: allowedFor(descriptor), charged: 0, poisoned: false, opened: new Set(), sessions: new Set(), consumed: false });
  return { ok: true, projection };
}

export function confirmV02PlanProjection(input: unknown): ConfirmedV02ProjectionResult<ConfirmedV02PlanProjection> {
  if (!isRecord(input) || consumedProducerInputs.has(input)) return invalidV02Projection();
  const descriptor = parseV02ProducerProjectionInput(input);
  if (descriptor?.kind !== "plan") return invalidV02Projection();
  consumedProducerInputs.add(input);
  const projection = Object.freeze({ schema_version: "0.2", source_pack_root_hash: descriptor.source_pack_root_hash, run_id: descriptor.run_id, output_budget_bytes: 33_554_432 }) as ConfirmedV02PlanProjection;
  projectionRegistry.set(projection, { descriptor, allowed: allowedFor(descriptor), charged: 0, poisoned: false, opened: new Set(), sessions: new Set(), consumed: false });
  return { ok: true, projection };
}

export function confirmV02ReportProjection(input: unknown): ConfirmedV02ProjectionResult<ConfirmedV02ReportProjection> {
  if (!isRecord(input) || consumedProducerInputs.has(input)) return invalidV02Projection();
  const descriptor = parseV02ProducerProjectionInput(input);
  if (descriptor?.kind !== "report") return invalidV02Projection();
  consumedProducerInputs.add(input);
  const projection = Object.freeze({ schema_version: "0.2", run_id: descriptor.run_id, resolved_run_plan_hash: descriptor.resolved_run_plan_hash, renderer_bundle_id: descriptor.renderer_bundle_id, renderer_bundle_hash: descriptor.renderer_bundle_hash, generation_id: descriptor.generation_id, output_budget_bytes: 33_554_432 }) as ConfirmedV02ReportProjection;
  projectionRegistry.set(projection, { descriptor, allowed: allowedFor(descriptor), charged: 0, poisoned: false, opened: new Set(), sessions: new Set(), consumed: false });
  return { ok: true, projection };
}

export function openV02OutputAdmissionSession(
  authority: ConfirmedV02OutputProjection,
  purpose: V02OutputPurpose,
): V02OutputAdmissionSessionResult {
  const projection = projectionRegistry.get(authority);
  if (projection === undefined || projection.poisoned || projection.consumed) {
    return { ok: false, reason: "INVALID_V02_PROJECTION", message: "The V02 projection is not registered." };
  }
  const ordered = projection.allowed.get(purpose);
  if (ordered === undefined || projection.opened.has(purpose)) return { ok: false, reason: "INVALID_OUTPUT_PURPOSE", message: "The output purpose is unavailable or already opened." };
  const session = Object.freeze({ schema_version: "0.2", purpose, allowed_members: Object.freeze([...ordered]), max_member_bytes: 4_194_304, max_total_bytes: 33_554_432, budget_scope: "projection-operation" }) as V02OutputAdmissionSession;
  admissionRegistry.set(session, { projection: authority, purpose, ordered, status: "open", members: new Map(ordered.map((name) => [name, { status: "unseen" as const }])) });
  projection.opened.add(purpose);
  projection.sessions.add(session);
  return { ok: true, session };
}

export function captureOutputBytes(
  session: V02OutputAdmissionSession,
  member_name: DirectChildName,
  input: Uint8Array,
): CapturedOutputBytesResult {
  const state = admissionRegistry.get(session);
  if (state === undefined || state.status !== "open") return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The output session is not registered or open." };
  const projection = projectionRegistry.get(state.projection)!;
  const member = state.members.get(member_name);
  const validView = input instanceof Uint8Array && Object.getPrototypeOf(input) === Uint8Array.prototype && !(input.buffer instanceof SharedArrayBuffer) && input.byteLength > 0;
  if (!validView) { poisonProjection(state.projection); return { ok: false, reason: "INVALID_OUTPUT_BYTE_VIEW", message: "The output must be an attached private Uint8Array." }; }
  if (member === undefined || member.status !== "unseen") { poisonProjection(state.projection); return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The output member is not allowed or was already reserved." }; }
  member.status = "reserved";
  member.length = input.byteLength;
  projection.charged += input.byteLength;
  if (input.byteLength > 4_194_304 || projection.charged > 33_554_432) { poisonProjection(state.projection); return { ok: false, reason: "COMPILED_OUTPUT_TOO_LARGE", message: "The output exceeds its projection budget." }; }
  let bytes: Uint8Array;
  try { bytes = new Uint8Array(input); } catch { poisonProjection(state.projection); return { ok: false, reason: "OUTPUT_CAPTURE_FAILED", message: "The output could not be copied." }; }
  const capture = Object.freeze({ schema_version: "0.2", purpose: state.purpose, member_name, byte_length: bytes.byteLength }) as CapturedOutputBytesV02;
  captureRegistry.set(capture, { session, name: member_name, bytes, consumed: false });
  return { ok: true, capture };
}

export function scanAndAdmitOutputBytes(input: CapturedOutputBytesV02): AdmittedOutputBytesResult {
  const captured = captureRegistry.get(input);
  if (captured === undefined || captured.consumed) return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The output capture is not registered or was reused." };
  captured.consumed = true;
  const session = admissionRegistry.get(captured.session);
  if (session === undefined || session.status !== "open") return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The output session is not open." };
  const text = new TextDecoder("utf-8", { fatal: false }).decode(captured.bytes);
  const sensitive = detectCredentialV02(text);
  if (sensitive !== null) { poisonProjection(session.projection); return { ok: false, reason: "SENSITIVE_OUTPUT_REJECTED", member_id: captured.name, rule_id: sensitive.rule_id }; }
  let sha256: string;
  try { sha256 = hashRawBytes(captured.bytes); } catch { poisonProjection(session.projection); return { ok: false, reason: "OUTPUT_HASH_FAILED", message: "The output could not be hashed." }; }
  const output = Object.freeze({ schema_version: "0.2", purpose: session.purpose, member_name: captured.name, byte_length: captured.bytes.byteLength, sha256 }) as AdmittedOutputBytes;
  admittedRegistry.set(output, { session: captured.session, name: captured.name, bytes: captured.bytes, sha256, consumed: false });
  const member = session.members.get(captured.name)!;
  member.status = "admitted";
  member.admitted = output;
  return { ok: true, output };
}

export function sealV02OutputAdmissionSession(session: V02OutputAdmissionSession): SealedV02OutputSetResult {
  const state = admissionRegistry.get(session);
  if (state === undefined || state.status !== "open") return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The output session is not registered or open." };
  const rows: { name: DirectChildName; byte_length: number; sha256: Hash }[] = [];
  const bytes = new Map<DirectChildName, Uint8Array>();
  for (const name of state.ordered) {
    const member = state.members.get(name)!;
    if (member.status !== "admitted" || member.admitted === undefined) return { ok: false, reason: "OUTPUT_SET_INCOMPLETE", message: "The output set is incomplete." };
    const admitted = admittedRegistry.get(member.admitted);
    if (admitted === undefined || admitted.consumed || admitted.session !== session) { poisonProjection(state.projection); return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "An admitted output handle is invalid or reused." }; }
    admitted.consumed = true;
    rows.push({ name, byte_length: admitted.bytes.byteLength, sha256: admitted.sha256 });
    bytes.set(name, admitted.bytes);
  }
  state.status = "sealed";
  const total = rows.reduce((sum, row) => sum + row.byte_length, 0);
  const output_set = Object.freeze({ schema_version: "0.2", purpose: state.purpose, ordered_members: Object.freeze(rows.map((row) => Object.freeze(row))), total_byte_length: total }) as SealedV02OutputSet;
  sealedRegistry.set(output_set, { projection: state.projection, purpose: state.purpose, ordered: rows, bytes, consumed: false });
  return { ok: true, output_set };
}

export async function anchorDestinationRootV02(
  root_path: string,
  boundary_kind: AnchoredDestinationRootV02["boundary_kind"],
): Promise<
  | { ok: true; root: AnchoredDestinationRootV02 }
  | { ok: false; reason: "INVALID_INPUT_ROOT" | "IO_HELPER_UNAVAILABLE" | "IO_IDENTITY_MISMATCH"; message: string }
> {
  try {
    const metadata = await lstat(root_path, { bigint: true });
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The destination root must be a direct directory." };
    }
    const path = await realpath(root_path);
    const identity = await stat(path, { bigint: true });
    const root = Object.freeze({
      root_identity: Object.freeze({ device: identity.dev.toString(), inode: identity.ino.toString() }),
      boundary_kind,
    }) as AnchoredDestinationRootV02;
    rootRegistry.set(root, {
      path,
      device: identity.dev.toString(),
      inode: identity.ino.toString(),
      boundary: boundary_kind,
      prepared_planned_loop_family: null,
    });
    return { ok: true, root };
  } catch {
    return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The destination root is unavailable." };
  }
}

function filesystemErrorCode(error: unknown): string | null {
  return isRecord(error) && typeof error.code === "string" ? error.code : null;
}

type DirectoryIdentity = Readonly<{ path: string; device: string; inode: string; uid: string }>;

async function inspectDirectDirectory(path: string, expectedUid: string | null): Promise<DirectoryIdentity | null> {
  const metadata = await lstat(path, { bigint: true });
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || (expectedUid !== null && metadata.uid.toString() !== expectedUid)) return null;
  const canonical = await realpath(path);
  if (canonical !== path) return null;
  const identity = await stat(canonical, { bigint: true });
  if (!identity.isDirectory() || identity.dev !== metadata.dev || identity.ino !== metadata.ino) return null;
  return Object.freeze({
    path,
    device: identity.dev.toString(),
    inode: identity.ino.toString(),
    uid: identity.uid.toString(),
  });
}

async function fsyncVerifiedDirectory(identity: DirectoryIdentity): Promise<void> {
  const handle = await openFile(identity.path, "r");
  try {
    const current = await handle.stat({ bigint: true });
    if (!current.isDirectory() || current.dev.toString() !== identity.device || current.ino.toString() !== identity.inode) {
      throw new Error("directory identity changed");
    }
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function ensurePreparedChildDirectory(
  parent: DirectoryIdentity,
  basename: string,
): Promise<
  | { ok: true; identity: DirectoryIdentity }
  | { ok: false; reason: "IO_IDENTITY_MISMATCH" | "IO_DURABILITY_UNCONFIRMED" }
> {
  const childPath = join(parent.path, basename);
  let created = false;
  try {
    await mkdir(childPath, { mode: 0o700 });
    created = true;
  } catch (error: unknown) {
    if (filesystemErrorCode(error) !== "EEXIST") return { ok: false, reason: "IO_DURABILITY_UNCONFIRMED" };
  }
  let identity: DirectoryIdentity | null;
  try {
    identity = await inspectDirectDirectory(childPath, parent.uid);
  } catch {
    return { ok: false, reason: "IO_IDENTITY_MISMATCH" };
  }
  if (identity === null) return { ok: false, reason: "IO_IDENTITY_MISMATCH" };
  try {
    if (created) await chmod(childPath, 0o700);
    await fsyncVerifiedDirectory(parent);
  } catch {
    return { ok: false, reason: "IO_DURABILITY_UNCONFIRMED" };
  }
  return { ok: true, identity };
}

export async function prepareV02PlannedRunsRoot(
  workspace_root: string,
  loop_family: string,
): Promise<PrepareV02PlannedRunsRootResult> {
  if (typeof workspace_root !== "string" || resolve(workspace_root) !== workspace_root || !HUMAN_RE.test(loop_family)) {
    return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The workspace root or loop family is invalid." };
  }
  let workspace: DirectoryIdentity | null;
  try { workspace = await inspectDirectDirectory(workspace_root, null); }
  catch { workspace = null; }
  if (workspace === null) return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The workspace root is unavailable or non-canonical." };

  let loopeix: DirectoryIdentity | null;
  let loops: DirectoryIdentity | null;
  try {
    loopeix = await inspectDirectDirectory(join(workspace.path, ".loopeix"), workspace.uid);
    loops = loopeix === null ? null : await inspectDirectDirectory(join(loopeix.path, "loops"), workspace.uid);
  } catch {
    loopeix = null;
    loops = null;
  }
  if (loopeix === null || loops === null) {
    return { ok: false, reason: "IO_IDENTITY_MISMATCH", message: "The workspace control-directory identity could not be verified." };
  }

  const family = await ensurePreparedChildDirectory(loops, loop_family);
  if (!family.ok) {
    return {
      ok: false,
      reason: family.reason,
      message: family.reason === "IO_IDENTITY_MISMATCH" ? "The loop-family directory identity could not be verified." : "The loop-family directory durability could not be confirmed.",
    };
  }
  const runs = await ensurePreparedChildDirectory(family.identity, "runs");
  if (!runs.ok) {
    return {
      ok: false,
      reason: runs.reason,
      message: runs.reason === "IO_IDENTITY_MISMATCH" ? "The runs-root identity could not be verified." : "The runs-root durability could not be confirmed.",
    };
  }
  const root = Object.freeze({
    root_identity: Object.freeze({ device: runs.identity.device, inode: runs.identity.inode }),
    boundary_kind: "runs-root",
  }) as AnchoredDestinationRootV02;
  rootRegistry.set(root, {
    path: runs.identity.path,
    device: runs.identity.device,
    inode: runs.identity.inode,
    boundary: "runs-root",
    prepared_planned_loop_family: loop_family,
  });
  return { ok: true, root };
}

function invalidWriteAuthority(): V02WriteAuthorityResult {
  return { ok: false, reason: "INVALID_V02_PROJECTION", message: "The V02 projection is not registered." };
}

export function createV02CompilerWriteAuthoritySet(
  projection: ConfirmedV02CompilerProjection,
  roots: { readonly standalone_loop: AnchoredDestinationRootV02 | null; readonly compile_pack: AnchoredDestinationRootV02 },
  output_sets: readonly SealedV02OutputSet[],
): V02CompilerWriteAuthoritySetResult {
  const projectionState = projectionRegistry.get(projection);
  if (projectionState === undefined || projectionState.descriptor.kind !== "compiler" || projectionState.poisoned || projectionState.consumed) {
    return { ok: false, reason: "INVALID_V02_PROJECTION", message: "The V02 projection is not registered." };
  }
  const compileRoot = rootRegistry.get(roots.compile_pack);
  const needsStandalone = projectionState.allowed.has("standalone-loop");
  const standaloneRoot = roots.standalone_loop === null ? undefined : rootRegistry.get(roots.standalone_loop);
  if (compileRoot?.boundary !== "compile-store" || (needsStandalone ? standaloneRoot?.boundary !== "standalone-parent" : roots.standalone_loop !== null)) {
    return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The destination root boundary does not match the compiler purpose." };
  }
  const expectedPurposes = [...projectionState.allowed.keys()];
  if (output_sets.length !== expectedPurposes.length) return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The compiler output-set inventory is incomplete." };
  const states = output_sets.map((set) => sealedRegistry.get(set));
  if (states.some((state) => state === undefined || state.consumed || state.projection !== projection) || expectedPurposes.some((purpose) => !states.some((state) => state?.purpose === purpose))) {
    return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "An output set is unregistered, reused, or belongs to another projection." };
  }
  const descriptor = projectionState.descriptor;
  const compileState = states.find((state) => state!.purpose === "compile-pack")!;
  const compileAuthority = Object.freeze({ purpose: "compile-pack", root_identity: roots.compile_pack.root_identity, compile_id: descriptor.compile_id, compiler_bundle_id: descriptor.compiler_bundle_id, catalog_version_hash: descriptor.catalog_version_hash, binding_input_hash: descriptor.binding_input_hash, terminal_state: descriptor.terminal_state, ordered_member_hashes: Object.freeze(compileState!.ordered.map((row) => row.sha256)) }) as V02CompilePackWriteAuthority;
  authorityRegistry.set(compileAuthority, { projection, root: roots.compile_pack, output: compileState!, resolved_run_plan_hash: null, consumed: false });
  let standaloneAuthority: V02StandaloneLoopWriteAuthority | null = null;
  if (needsStandalone && roots.standalone_loop !== null) {
    const state = states.find((candidate) => candidate!.purpose === "standalone-loop")!;
    const standaloneYaml = state!.bytes.get(directNames(STANDALONE_MEMBERS)[0]!);
    const packYaml = compileState!.bytes.get(parseDirectChildName("generated.loop.yaml")!);
    if (standaloneYaml === undefined || packYaml === undefined || !Buffer.from(standaloneYaml).equals(packYaml)) {
      return { ok: false, reason: "INVALID_V02_PROJECTION", message: "The standalone and compile-pack generated loop outputs differ." };
    }
    standaloneAuthority = Object.freeze({ purpose: "standalone-loop", root_identity: roots.standalone_loop.root_identity, compile_id: descriptor.compile_id, source_authoring_hash: descriptor.source_authoring_hash, generated_loop_hash: state!.ordered[0]!.sha256 }) as V02StandaloneLoopWriteAuthority;
    authorityRegistry.set(standaloneAuthority, { projection, root: roots.standalone_loop, output: state!, resolved_run_plan_hash: null, consumed: false });
  }
  for (const state of states) state!.consumed = true;
  projectionState.consumed = true;
  const combined = states.reduce((sum, state) => sum + state!.ordered.reduce((inner, row) => inner + row.byte_length, 0), 0);
  const authorities = Object.freeze({ standalone_loop: standaloneAuthority, compile_pack: compileAuthority, combined_output_bytes: combined }) as V02CompilerWriteAuthoritySet;
  compilerAuthoritySetRegistry.set(authorities, { compile: compileAuthority, standalone: standaloneAuthority, consumed: false });
  return { ok: true, authorities };
}

function compilerWriteFailure(
  reason: Exclude<Extract<CompilerOutputWriteResultV02, { ok: false }>["reason"], "DESTINATION_EXISTS">,
  message: string,
): CompilerOutputWriteResultV02 {
  return { ok: false, reason, message, pack_ref: null, standalone_ref: null };
}

function compilerWriterFailureMessage(
  reason: Exclude<Extract<CompilerOutputWriteResultV02, { ok: false }>["reason"], "OUTPUT_CAPTURE_FAILED">,
): string {
  return {
    DESTINATION_EXISTS: "Destination already exists.",
    INVALID_OUTPUT_CAPTURE: "The compiler output authority or captured output is invalid.",
    IO_HELPER_UNAVAILABLE: "Required filesystem helper is unavailable.",
    IO_IDENTITY_MISMATCH: "Filesystem identity validation failed.",
    IO_DURABILITY_UNCONFIRMED: "Filesystem durability could not be confirmed.",
  }[reason];
}

export async function writeV02CompilerOutputs(
  authorities: V02CompilerWriteAuthoritySet,
  standalone_basename: DirectChildName | null,
  options: CompilerWriterOptions = {},
): Promise<CompilerOutputWriteResultV02> {
  const authoritySet = compilerAuthoritySetRegistry.get(authorities);
  if (authoritySet === undefined || authoritySet.consumed ||
      (authoritySet.standalone === null) !== (standalone_basename === null)) {
    return compilerWriteFailure("INVALID_OUTPUT_CAPTURE", "The compiler writer authority set is invalid or reused.");
  }
  const compileState = authorityRegistry.get(authoritySet.compile);
  const standaloneState = authoritySet.standalone === null ? null : authorityRegistry.get(authoritySet.standalone) ?? null;
  const compileRoot = compileState === undefined ? undefined : rootRegistry.get(compileState.root);
  const standaloneRoot = standaloneState === null ? null : rootRegistry.get(standaloneState.root) ?? null;
  if (compileState === undefined || compileState.consumed || compileRoot?.boundary !== "compile-store" ||
      (authoritySet.standalone !== null && (standaloneState === null || standaloneState.consumed || standaloneRoot?.boundary !== "standalone-parent"))) {
    return compilerWriteFailure("INVALID_OUTPUT_CAPTURE", "The compiler writer authority set is invalid or reused.");
  }
  if (standalone_basename !== null && parseDirectChildName(standalone_basename) === null) {
    return compilerWriteFailure("INVALID_OUTPUT_CAPTURE", "The standalone destination basename is invalid.");
  }

  authoritySet.consumed = true;
  compileState.consumed = true;
  if (standaloneState !== null) standaloneState.consumed = true;

  let request: CompilerWriterHelperRequest;
  try {
    const packMembers = compileState.output.ordered.map((row) => {
      const bytes = compileState.output.bytes.get(row.name);
      if (bytes === undefined) throw new Error("missing private output bytes");
      return Object.freeze({ name: row.name, bytes_base64: Buffer.from(new Uint8Array(bytes)).toString("base64") });
    });
    if (packMembers.at(-1)?.name !== "pack-manifest.json") {
      return compilerWriteFailure("INVALID_OUTPUT_CAPTURE", "The compile-pack manifest is not the final member.");
    }
    let standalone: CompilerWriterHelperRequest["standalone"] = null;
    if (standaloneState !== null && standaloneRoot !== null && standalone_basename !== null) {
      const row = standaloneState.output.ordered[0];
      const bytes = row === undefined ? undefined : standaloneState.output.bytes.get(row.name);
      if (row?.name !== "generated.loop.yaml" || bytes === undefined) throw new Error("missing private standalone bytes");
      standalone = Object.freeze({
        parent_path: standaloneRoot.path,
        parent_identity: Object.freeze({ device: standaloneRoot.device, inode: standaloneRoot.inode }),
        basename: standalone_basename,
        bytes_base64: Buffer.from(new Uint8Array(bytes)).toString("base64"),
      });
    }
    request = Object.freeze({
      version: "0.1",
      compile_store_identity: Object.freeze({ device: compileRoot.device, inode: compileRoot.inode }),
      pack_basename: authoritySet.compile.compile_id,
      pack_members: Object.freeze(packMembers),
      standalone,
    });
  } catch {
    return compilerWriteFailure("OUTPUT_CAPTURE_FAILED", "The compiler output could not be copied for persistence.");
  }

  const runHelper = options.runHelper ?? requestCompilerWriterHelper;
  let result: CompilerWriterHelperResponse;
  try { result = await runHelper(compileRoot.path, request); }
  catch { return compilerWriteFailure("IO_HELPER_UNAVAILABLE", "Required filesystem helper is unavailable."); }
  if (!isRecord(result) || typeof result.ok !== "boolean") {
    return compilerWriteFailure("IO_HELPER_UNAVAILABLE", "Required filesystem helper is unavailable.");
  }
  if (!result.ok) {
    const reasons = new Set(["DESTINATION_EXISTS", "INVALID_OUTPUT_CAPTURE", "IO_HELPER_UNAVAILABLE", "IO_IDENTITY_MISMATCH", "IO_DURABILITY_UNCONFIRMED"]);
    if (result.reason === "DESTINATION_EXISTS") {
      return result.collision_destination === "compile-pack" || result.collision_destination === "standalone-loop"
        ? {
            ok: false,
            reason: "DESTINATION_EXISTS",
            collision_destination: result.collision_destination,
            message: "Destination already exists.",
            pack_ref: null,
            standalone_ref: null,
          }
        : compilerWriteFailure("IO_HELPER_UNAVAILABLE", "Required filesystem helper is unavailable.");
    }
    return reasons.has(result.reason)
      ? compilerWriteFailure(result.reason, compilerWriterFailureMessage(result.reason))
      : compilerWriteFailure("IO_HELPER_UNAVAILABLE", "Required filesystem helper is unavailable.");
  }
  return {
    ok: true,
    pack_ref: authoritySet.compile.compile_id,
    standalone_ref: standalone_basename,
  };
}

export function createV02PlannedRunWriteAuthority(
  projection: ConfirmedV02PlanProjection,
  root: AnchoredDestinationRootV02,
  output_set: SealedV02OutputSet,
): V02WriteAuthorityResult {
  const state = projectionRegistry.get(projection);
  if (state === undefined || state.descriptor.kind !== "plan" || state.poisoned || state.consumed) return invalidWriteAuthority();
  const rootState = rootRegistry.get(root);
  const descriptor = state.descriptor;
  if (rootState?.boundary !== "runs-root" || rootState.prepared_planned_loop_family !== descriptor.loop_family) {
    return { ok: false, reason: "INVALID_INPUT_ROOT", message: "A planned-run authority requires its securely prepared family runs root." };
  }
  const output = sealedRegistry.get(output_set);
  if (output === undefined || output.consumed || output.projection !== projection || output.purpose !== "planned-run") return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The planned-run output set is invalid or reused." };
  if (output.ordered.length !== PLANNED_RUN_MEMBERS.length || output.ordered.some((row, index) => row.name !== PLANNED_RUN_MEMBERS[index])) {
    state.poisoned = true;
    output.consumed = true;
    return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The planned-run output inventory is not canonical." };
  }
  const clonedBytes = new Map<DirectChildName, Uint8Array>();
  try {
    for (const row of output.ordered) {
      const bytes = output.bytes.get(row.name);
      if (bytes === undefined || bytes.byteLength !== row.byte_length || hashRawBytes(bytes) !== row.sha256) throw new Error("invalid retained bytes");
      clonedBytes.set(row.name, new Uint8Array(bytes));
    }
  } catch {
    state.poisoned = true;
    output.consumed = true;
    return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The planned-run output bytes could not be privately retained." };
  }
  const retainedOutput: SealedState = {
    projection,
    purpose: "planned-run",
    ordered: output.ordered.map((row) => Object.freeze({ ...row })),
    bytes: clonedBytes,
    consumed: false,
  };
  const resolvedPlanHash = retainedOutput.ordered[retainedOutput.ordered.length - 1]!.sha256;
  const authority = Object.freeze({ purpose: "planned-run", root_identity: root.root_identity, source_pack_root_hash: descriptor.source_pack_root_hash, run_id: descriptor.run_id, loop_family: descriptor.loop_family, workspace_root_hash: descriptor.workspace_root_hash, engine: descriptor.engine, ordered_member_hashes: Object.freeze(retainedOutput.ordered.map((row) => row.sha256)) }) as V02PlannedRunWriteAuthority;
  output.consumed = true; state.consumed = true;
  authorityRegistry.set(authority, { projection, root, output: retainedOutput, resolved_run_plan_hash: resolvedPlanHash, consumed: false });
  return { ok: true, authority };
}

function plannedWriteFailure(
  reason: Extract<PlannedRunOutputWriteResultV02, { ok: false }>['reason'],
  message: string,
  run_ref: string | null,
): PlannedRunOutputWriteResultV02 {
  return { ok: false, reason, message, run_id: null, resolved_run_plan_hash: null, run_ref };
}

export async function writeV02PlannedRunOutputs(
  authority: V02PlannedRunWriteAuthority,
  options: PlannedRunWriterTestOptions = {},
): Promise<PlannedRunOutputWriteResultV02> {
  const authorityState = authorityRegistry.get(authority);
  const root = authorityState === undefined ? undefined : rootRegistry.get(authorityState.root);
  if (authorityState === undefined || authorityState.consumed || authority.purpose !== "planned-run" ||
      root?.boundary !== "runs-root" || root.prepared_planned_loop_family !== authority.loop_family ||
      authorityState.resolved_run_plan_hash === null || authorityState.output.purpose !== "planned-run" ||
      authorityState.output.ordered.length !== PLANNED_RUN_MEMBERS.length ||
      authorityState.output.ordered.some((row, index) => row.name !== PLANNED_RUN_MEMBERS[index] || row.sha256 !== authority.ordered_member_hashes[index])) {
    return plannedWriteFailure("INVALID_OUTPUT_CAPTURE", "The planned-run output authority is invalid or reused.", null);
  }
  authorityState.consumed = true;
  const runRef = `.loopeix/loops/${authority.loop_family}/runs/${authority.run_id}`;
  const runPath = join(root.path, authority.run_id);
  let runsIdentity: DirectoryIdentity;
  try {
    const inspected = await inspectDirectDirectory(root.path, null);
    if (inspected === null || inspected.device !== root.device || inspected.inode !== root.inode) {
      return plannedWriteFailure("IO_IDENTITY_MISMATCH", "Filesystem identity validation failed.", null);
    }
    runsIdentity = inspected;
  } catch {
    return plannedWriteFailure("IO_IDENTITY_MISMATCH", "Filesystem identity validation failed.", null);
  }

  try {
    await mkdir(runPath, { mode: 0o700 });
  } catch (error: unknown) {
    return filesystemErrorCode(error) === "EEXIST"
      ? plannedWriteFailure("DESTINATION_EXISTS", "Destination already exists.", null)
      : plannedWriteFailure("IO_DURABILITY_UNCONFIRMED", "Filesystem durability could not be confirmed.", null);
  }

  type Reservation = {
    name: DirectChildName;
    handle: Awaited<ReturnType<typeof openFile>>;
    device: string;
    inode: string;
    closed: boolean;
  };
  const reservations: Reservation[] = [];
  let runIdentity: DirectoryIdentity | null = null;
  let contentStarted = false;
  try {
    await chmod(runPath, 0o700);
    runIdentity = await inspectDirectDirectory(runPath, runsIdentity.uid);
    if (runIdentity === null) throw new Error("run directory identity mismatch");

    for (const expectedName of PLANNED_RUN_MEMBERS) {
      const name = parseDirectChildName(expectedName);
      if (name === null) throw new Error("invalid canonical member name");
      const handle = await openFile(join(runPath, name), "wx", 0o600);
      let captured = false;
      try {
        await handle.chmod(0o600);
        const identity = await handle.stat({ bigint: true });
        if (!identity.isFile()) throw new Error("reserved member is not a regular file");
        reservations.push({ name, handle, device: identity.dev.toString(), inode: identity.ino.toString(), closed: false });
        captured = true;
      } finally {
        if (!captured) await handle.close().catch(() => undefined);
      }
    }
    options.after_all_reservations?.();

    for (const reservation of reservations) {
      const bytes = authorityState.output.bytes.get(reservation.name);
      const row = authorityState.output.ordered.find((candidate) => candidate.name === reservation.name);
      if (bytes === undefined || row === undefined || hashRawBytes(bytes) !== row.sha256) throw new Error("retained output bytes changed");
      contentStarted = true;
      await reservation.handle.writeFile(bytes);
      await reservation.handle.sync();
      options.after_member_fsync?.(reservation.name);
      await reservation.handle.close();
      reservation.closed = true;
    }
    await fsyncVerifiedDirectory(runIdentity);
    await fsyncVerifiedDirectory(runsIdentity);
    return {
      ok: true,
      run_id: authority.run_id,
      resolved_run_plan_hash: authorityState.resolved_run_plan_hash,
      run_ref: runRef,
    };
  } catch {
    for (const reservation of reservations) {
      if (!reservation.closed) await reservation.handle.close().catch(() => undefined);
      reservation.closed = true;
    }
    if (!contentStarted && runIdentity !== null) {
      let cleanupSafe = true;
      for (const reservation of reservations) {
        try {
          const current = await lstat(join(runPath, reservation.name), { bigint: true });
          if (!current.isFile() || current.isSymbolicLink() || current.dev.toString() !== reservation.device || current.ino.toString() !== reservation.inode) {
            cleanupSafe = false;
            break;
          }
        } catch {
          cleanupSafe = false;
          break;
        }
      }
      if (cleanupSafe) {
        for (const reservation of reservations) await unlink(join(runPath, reservation.name)).catch(() => undefined);
        try {
          const current = await lstat(runPath, { bigint: true });
          if (current.isDirectory() && !current.isSymbolicLink() && current.dev.toString() === runIdentity.device && current.ino.toString() === runIdentity.inode) {
            await rmdir(runPath);
          }
        } catch { /* Retain ambiguous state. */ }
      }
    }
    return plannedWriteFailure("IO_DURABILITY_UNCONFIRMED", "Filesystem durability could not be confirmed.", runRef);
  }
}

export function createV02PlanReportWriteAuthority(
  projection: ConfirmedV02ReportProjection,
  root: AnchoredDestinationRootV02,
  output_set: SealedV02OutputSet,
): V02WriteAuthorityResult {
  const state = projectionRegistry.get(projection);
  if (state === undefined || state.descriptor.kind !== "report" || state.poisoned || state.consumed) return invalidWriteAuthority();
  const rootState = rootRegistry.get(root);
  if (rootState?.boundary !== "run-directory") return { ok: false, reason: "INVALID_INPUT_ROOT", message: "A plan-report authority requires a run-directory anchor." };
  const output = sealedRegistry.get(output_set);
  if (output === undefined || output.consumed || output.projection !== projection || output.purpose !== "plan-report") return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The plan-report output set is invalid or reused." };
  const descriptor = state.descriptor;
  const authority = Object.freeze({ purpose: "plan-report", root_identity: root.root_identity, run_id: descriptor.run_id, resolved_run_plan_hash: descriptor.resolved_run_plan_hash, compile_pack_manifest_hash: descriptor.compile_pack_manifest_hash, generated_loop_hash: descriptor.generated_loop_hash, report_projection_version: "0.1", renderer_bundle_id: descriptor.renderer_bundle_id, renderer_bundle_hash: descriptor.renderer_bundle_hash, generation_id: descriptor.generation_id }) as V02PlanReportWriteAuthority;
  output.consumed = true; state.consumed = true;
  authorityRegistry.set(authority, { projection, root, output, resolved_run_plan_hash: null, consumed: false });
  return { ok: true, authority };
}

export async function issueV02DestinationCapability(
  authority: V02WriteAuthority,
): Promise<
  | { ok: true; capability: V02DestinationCapability }
  | {
      ok: false;
      reason: "INVALID_INPUT_ROOT" | "INVALID_OUTPUT_CAPTURE" | "IO_HELPER_UNAVAILABLE" | "IO_IDENTITY_MISMATCH";
      message: string;
    }
> {
  const state = authorityRegistry.get(authority);
  if (state === undefined || state.consumed) {
    return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The V02 write authority is not registered." };
  }
  const root = rootRegistry.get(state.root);
  if (root === undefined) return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The authority root is unavailable." };
  try {
    const current = await stat(root.path, { bigint: true });
    if (current.dev.toString() !== root.device || current.ino.toString() !== root.inode) return { ok: false, reason: "IO_IDENTITY_MISMATCH", message: "The authority root identity changed." };
  } catch { return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The authority root is unavailable." }; }
  const commonLineage = {
    purpose: authority.purpose,
    root_device: root.device,
    root_inode: root.inode,
    ordered_members: state.output.ordered.map((row) => ({ name: row.name, hash: row.sha256 })),
  } as const;
  const lineagePreimage = (() => {
    switch (authority.purpose) {
      case "standalone-loop": return {
        ...commonLineage,
        compile_id: authority.compile_id,
        source_authoring_hash: authority.source_authoring_hash,
        generated_loop_hash: authority.generated_loop_hash,
      };
      case "compile-pack": return {
        ...commonLineage,
        compile_id: authority.compile_id,
        compiler_bundle_id: authority.compiler_bundle_id,
        catalog_version_hash: authority.catalog_version_hash,
        binding_input_hash: authority.binding_input_hash,
        terminal_state: authority.terminal_state,
        ordered_member_hashes: authority.ordered_member_hashes,
      };
      case "planned-run": return {
        ...commonLineage,
        source_pack_root_hash: authority.source_pack_root_hash,
        run_id: authority.run_id,
        loop_family: authority.loop_family,
        workspace_root_hash: authority.workspace_root_hash,
        engine: authority.engine,
        ordered_member_hashes: authority.ordered_member_hashes,
      };
      case "plan-report": return {
        ...commonLineage,
        run_id: authority.run_id,
        resolved_run_plan_hash: authority.resolved_run_plan_hash,
        compile_pack_manifest_hash: authority.compile_pack_manifest_hash,
        generated_loop_hash: authority.generated_loop_hash,
        report_projection_version: authority.report_projection_version,
        renderer_bundle_id: authority.renderer_bundle_id,
        renderer_bundle_hash: authority.renderer_bundle_hash,
        generation_id: authority.generation_id,
      };
    }
  })();
  const lineage_hash = hashCanonical(lineagePreimage);
  const capability = Object.freeze({ schema_version: "0.2", purpose: authority.purpose, lineage_hash }) as V02DestinationCapability;
  capabilityRegistry.set(capability, {
    path: root.path,
    device: root.device,
    inode: root.inode,
    purpose: authority.purpose,
    output: state.output,
    report_authority: authority.purpose === "plan-report" ? authority : null,
    consumed: false,
  });
  state.consumed = true;
  return { ok: true, capability };
}

export async function openAnchoredReadSession(root_path: string): Promise<
  | { ok: true; session: AnchoredReadSession }
  | { ok: false; reason: "INVALID_INPUT_ROOT" | "IO_HELPER_UNAVAILABLE" | "IO_IDENTITY_MISMATCH"; message: string }
> {
  try {
    const metadata = await lstat(root_path, { bigint: true });
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The input root must be a direct directory." };
    }
    const path = await realpath(root_path);
    const identity = await stat(path, { bigint: true });
    let session: AnchoredReadSession;
    session = Object.freeze({
      root_identity: Object.freeze({ device: identity.dev.toString(), inode: identity.ino.toString() }),
      listDirectEntries: async () => {
        const state = readSessionRegistry.get(session);
        if (state === undefined || !state.open) {
          return { ok: false as const, reason: "INVALID_INPUT_ROOT" as const, message: "The read session is not open." };
        }
        try {
          const before = await stat(state.path, { bigint: true });
          if (before.dev.toString() !== identity.dev.toString() || before.ino.toString() !== identity.ino.toString()) {
            return { ok: false as const, reason: "IO_IDENTITY_MISMATCH" as const, message: "The input root identity changed." };
          }
          const direct = await readdir(state.path, { withFileTypes: true });
          const entries: AnchoredDirectoryEntry[] = direct.map((entry) => ({
            name: entry.name,
            kind: entry.isSymbolicLink()
              ? "symlink"
              : entry.isFile()
                ? "regular-file"
                : entry.isDirectory()
                  ? "directory"
                  : "other",
          }));
          const after = await stat(state.path, { bigint: true });
          if (after.dev.toString() !== identity.dev.toString() || after.ino.toString() !== identity.ino.toString()) {
            return { ok: false as const, reason: "IO_IDENTITY_MISMATCH" as const, message: "The input root identity changed during enumeration." };
          }
          return { ok: true as const, entries: Object.freeze(entries.map((entry) => Object.freeze(entry))) };
        } catch {
          return { ok: false as const, reason: "IO_IDENTITY_MISMATCH" as const, message: "The input root could not be enumerated with stable identity." };
        }
      },
      captureFile: async (name: DirectChildName, max_member_bytes: number, remaining_total_bytes: number) => {
        const state = readSessionRegistry.get(session);
        if (state === undefined || !state.open || max_member_bytes <= 0 || remaining_total_bytes < max_member_bytes) {
          return { ok: false as const, reason: "INVALID_INPUT_FILE" as const, message: "The read session or byte budget is invalid." };
        }
        try {
          const before = await stat(state.path, { bigint: true });
          if (before.dev.toString() !== identity.dev.toString() || before.ino.toString() !== identity.ino.toString()) {
            return { ok: false as const, reason: "IO_IDENTITY_MISMATCH" as const, message: "The input root identity changed before member capture." };
          }
          const captured = await captureStructuredFile(join(state.path, name), {
          mode: "operator-approved-finite",
          max_member_bytes,
          max_total_bytes: remaining_total_bytes,
          max_heap_bytes: Math.max(16_777_216, max_member_bytes * 3),
          max_elapsed_ms: 30_000,
          approved_by: "operator",
          }, { device: identity.dev.toString(), inode: identity.ino.toString() });
          const after = await stat(state.path, { bigint: true });
          if (after.dev.toString() !== identity.dev.toString() || after.ino.toString() !== identity.ino.toString()) {
            if (captured.ok) await releaseCapturedStructuredFile(captured.capture);
            return { ok: false as const, reason: "IO_IDENTITY_MISMATCH" as const, message: "The input root identity changed during member capture." };
          }
          return captured;
        } catch {
          return { ok: false as const, reason: "IO_IDENTITY_MISMATCH" as const, message: "The input root identity could not be revalidated." };
        }
      },
      close: async () => {
        const state = readSessionRegistry.get(session);
        if (state === undefined || !state.open) {
          return { ok: false as const, reason: "INVALID_INPUT_ROOT" as const, message: "The read session is already closed." };
        }
        state.open = false;
        return { ok: true as const };
      },
    });
    readSessionRegistry.set(session, { path, open: true });
    return { ok: true, session };
  } catch {
    return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The input root is unavailable." };
  }
}

export async function openAnchoredWriteSession<TCapability extends DestinationCapability>(
  root_path: string,
  capability: TCapability,
): Promise<
  | { ok: true; session: AnchoredWriteSession<TCapability> }
  | {
      ok: false;
      reason: "INVALID_INPUT_ROOT" | "INVALID_OUTPUT_CAPTURE" | "IO_HELPER_UNAVAILABLE" | "IO_IDENTITY_MISMATCH";
      message: string;
    }
> {
  const v01State = v01CapabilityRegistry.get(capability);
  if (v01State !== undefined) {
    if (v01State.consumed) {
      return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The V01 destination capability is already consumed." };
    }
    try {
      const metadata = await lstat(root_path, { bigint: true });
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The V01 write root must be a direct directory." };
      const path = await realpath(root_path);
      const identity = await stat(path, { bigint: true });
      if (path !== v01State.path || identity.dev.toString() !== v01State.device || identity.ino.toString() !== v01State.inode) return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The V01 write root does not match the capability root." };
      v01State.consumed = true;
      const destination = Object.freeze({
        schema_version: "0.1",
        purpose: v01State.purpose,
        source_pack_root_hash: v01State.identity.source_pack_root_hash,
        catalog_version_hash: v01State.identity.selector.catalog_version_hash,
      });
      const makeV01Session = (sessionPath: string, device: string, inode: string): AnchoredWriteSession<TCapability> => {
        let isOpen = true;
        const checkIdentity = async (): Promise<boolean> => {
          try {
            const metadata = await lstat(sessionPath, { bigint: true });
            if (!metadata.isDirectory() || metadata.isSymbolicLink() || await realpath(sessionPath) !== sessionPath) return false;
            const current = await stat(sessionPath, { bigint: true });
            return current.dev.toString() === device && current.ino.toString() === inode;
          } catch {
            return false;
          }
        };
        const session = Object.freeze({
          root_identity: Object.freeze({ device, inode }),
          destination,
          createFileExclusive: async (request: unknown): Promise<AnchoredIoResult> => {
            if (!isOpen || !isRecord(request) || !exactKeys(request, ["bytes", "mode"]) || request.mode !== 0o600 || !isRecord(request.bytes)) {
              return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The V01 create request must contain only a registered byte handle and mode." };
            }
            const output = request.bytes as VerifiedV01ReplayOutputBytes;
            const outputState = verifiedV01OutputRegistry.get(output);
            if (outputState === undefined || outputState.consumed || outputState.identity !== v01State.identity) {
              return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The V01 output byte handle is unregistered, reused, or bound to another identity." };
            }
            if ((v01State.purpose === "replay-pack-copy" && output.projection_kind !== "pack-member-copy") ||
                (v01State.purpose === "planned-run" && output.projection_kind !== "frozen-plan-projection")) {
              return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The V01 output byte handle does not match the destination purpose." };
            }
            const candidateName = output.projection_kind === "pack-member-copy"
              ? output.source_member_name
              : output.projection_name === "approved-intake-brief"
                ? "intake-brief.json"
                : output.projection_name === "resolved-run-plan"
                  ? "resolved-run-plan.json"
                  : null;
            const name = candidateName === null ? null : parseDirectChildName(candidateName);
            if (name === null) return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The V01 authority did not derive a valid destination basename." };
            if (!(await checkIdentity())) return { ok: false, reason: "IO_IDENTITY_MISMATCH", message: "The V01 destination root identity changed before reservation." };
            outputState.consumed = true;
            let handle: Awaited<ReturnType<typeof openFile>> | null = null;
            try {
              handle = await openFile(join(sessionPath, name), "wx", 0o600);
              await handle.writeFile(outputState.bytes);
              await handle.sync();
              await handle.close();
              handle = null;
              return { ok: true };
            } catch (error: unknown) {
              if (handle !== null) await handle.close().catch(() => undefined);
              const code = isRecord(error) && typeof error.code === "string" ? error.code : "";
              return code === "EEXIST"
                ? { ok: false, reason: "DESTINATION_EXISTS", message: "The V01 destination member already exists." }
                : { ok: false, reason: "IO_DURABILITY_UNCONFIRMED", message: "The V01 destination member could not be durably created." };
            }
          },
          createChildDirectorySession: async (name: DirectChildName, mode: 0o700) => {
            if (!isOpen || mode !== 0o700 || v01State.purpose !== "planned-run" || parseDirectChildName(name) === null || !(await checkIdentity())) {
              return { ok: false as const, reason: "IO_IDENTITY_MISMATCH" as const, message: "The V01 child directory request does not match this capability." };
            }
            try {
              const childPath = join(sessionPath, name);
              await mkdir(childPath, { mode: 0o700 });
              const child = await stat(childPath, { bigint: true });
              return { ok: true as const, session: makeV01Session(childPath, child.dev.toString(), child.ino.toString()) };
            } catch (error: unknown) {
              const code = isRecord(error) && typeof error.code === "string" ? error.code : "";
              return code === "EEXIST"
                ? { ok: false as const, reason: "DESTINATION_EXISTS" as const, message: "The V01 destination directory already exists." }
                : { ok: false as const, reason: "IO_DURABILITY_UNCONFIRMED" as const, message: "The V01 destination directory could not be created." };
            }
          },
          replacePlanReportProjectionSet: async (): Promise<AnchoredIoResult> => ({ ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "V01 replay capabilities cannot replace a plan-report set." }),
          close: async () => {
            if (!isOpen) return { ok: false as const, reason: "INVALID_INPUT_ROOT" as const, message: "The V01 write session is already closed." };
            isOpen = false;
            return { ok: true as const };
          },
        }) as unknown as AnchoredWriteSession<TCapability>;
        return session;
      };
      return { ok: true, session: makeV01Session(path, v01State.device, v01State.inode) };
    } catch {
      return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The V01 write root is unavailable." };
    }
  }
  const state = capabilityRegistry.get(capability);
  if (state === undefined || state.consumed) {
    return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The destination capability is not registered." };
  }
  try {
    const metadata = await lstat(root_path, { bigint: true });
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The write root must be a direct directory." };
    const path = await realpath(root_path);
    const identity = await stat(path, { bigint: true });
    if (path !== state.path || identity.dev.toString() !== state.device || identity.ino.toString() !== state.inode) return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The write root does not match the capability root." };
    state.consumed = true;
    const destination = Object.freeze({ schema_version: "0.2", purpose: state.purpose, lineage_hash: (capability as V02DestinationCapability).lineage_hash });
    const makeSession = (sessionPath: string, device: string, inode: string): AnchoredWriteSession<TCapability> => {
      let isOpen = true;
      let nextMember = 0;
      const checkIdentity = async (): Promise<boolean> => {
        try { const current = await stat(sessionPath, { bigint: true }); return current.dev.toString() === device && current.ino.toString() === inode; }
        catch { return false; }
      };
      let session: AnchoredWriteSession<TCapability>;
      session = Object.freeze({
        root_identity: Object.freeze({ device, inode }),
        destination,
        createFileExclusive: async (request: unknown): Promise<AnchoredIoResult> => {
          if (!isOpen || state.purpose === "plan-report" || !isRecord(request) || !exactKeys(request, ["member_name", "mode"]) || request.mode !== 0o600 || typeof request.member_name !== "string") return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The create request does not match this write capability." };
          const name = parseDirectChildName(request.member_name);
          const expected = state.output.ordered[nextMember];
          if (name === null || expected?.name !== name || !(await checkIdentity())) return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The output member is out of order or the root identity changed." };
          const bytes = state.output.bytes.get(name);
          if (bytes === undefined) return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The retained output member is unavailable." };
          let handle: Awaited<ReturnType<typeof openFile>> | null = null;
          try {
            handle = await openFile(join(sessionPath, name), "wx", 0o600);
            await handle.writeFile(bytes);
            await handle.sync();
            await handle.close();
            handle = null;
            nextMember += 1;
            return { ok: true };
          } catch (error: unknown) {
            if (handle !== null) await handle.close().catch(() => undefined);
            const code = isRecord(error) && typeof error.code === "string" ? error.code : "";
            return code === "EEXIST" ? { ok: false, reason: "DESTINATION_EXISTS", message: "The destination member already exists." } : { ok: false, reason: "IO_DURABILITY_UNCONFIRMED", message: "The destination member could not be durably created." };
          }
        },
        createChildDirectorySession: async (name: DirectChildName, mode: 0o700) => {
          if (!isOpen || mode !== 0o700 || (state.purpose !== "compile-pack" && state.purpose !== "planned-run") || nextMember !== 0 || !(await checkIdentity())) return { ok: false as const, reason: "IO_IDENTITY_MISMATCH" as const, message: "The child directory request does not match this capability." };
          try {
            const childPath = join(sessionPath, name);
            await mkdir(childPath, { mode: 0o700 });
            const child = await stat(childPath, { bigint: true });
            return { ok: true as const, session: makeSession(childPath, child.dev.toString(), child.ino.toString()) };
          } catch (error: unknown) {
            const code = isRecord(error) && typeof error.code === "string" ? error.code : "";
            return code === "EEXIST" ? { ok: false as const, reason: "DESTINATION_EXISTS" as const, message: "The destination directory already exists." } : { ok: false as const, reason: "IO_DURABILITY_UNCONFIRMED" as const, message: "The destination directory could not be created." };
          }
        },
        replacePlanReportProjectionSet: async (request: { readonly generation_id: MachineId }): Promise<AnchoredIoResult> => {
          const authority = state.report_authority;
          if (!isOpen || state.purpose !== "plan-report" || authority === null || request.generation_id !== authority.generation_id || !(await checkIdentity())) return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The plan-report replacement request does not match this capability." };
          const ordered = state.output.ordered;
          if (ordered.length !== 3 || ordered[0]?.name !== "plan-report.md" || ordered[1]?.name !== "plan-report.html" || ordered[2]?.name !== "plan-report-input.json") return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The plan-report output order is invalid." };
          return replacePlanReportProjectionSetV02(sessionPath, {
            run_id: authority.run_id,
            generation_id: authority.generation_id,
            resolved_run_plan_hash: authority.resolved_run_plan_hash,
            compile_pack_manifest_hash: authority.compile_pack_manifest_hash,
            generated_loop_hash: authority.generated_loop_hash,
            report_projection_version: authority.report_projection_version,
            renderer_bundle_id: authority.renderer_bundle_id,
            renderer_bundle_hash: authority.renderer_bundle_hash,
            ordered: ordered as readonly { name: "plan-report.md" | "plan-report.html" | "plan-report-input.json"; sha256: string }[],
            bytes: state.output.bytes as ReadonlyMap<"plan-report.md" | "plan-report.html" | "plan-report-input.json", Uint8Array>,
          });
        },
        close: async () => {
          if (!isOpen) return { ok: false as const, reason: "INVALID_INPUT_ROOT" as const, message: "The write session is already closed." };
          isOpen = false;
          return { ok: true as const };
        },
      }) as unknown as AnchoredWriteSession<TCapability>;
      return session;
    };
    const session = makeSession(path, state.device, state.inode);
    return { ok: true, session };
  } catch { return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The write root is unavailable." }; }
}

type InvalidV01Result = { ok: false; reason: "INVALID_V01_REPLAY_OUTPUT"; message: string };
function invalidV01(): InvalidV01Result {
  return { ok: false, reason: "INVALID_V01_REPLAY_OUTPUT", message: "The V01 replay object is not registered." };
}

function v01AdapterPlan(engine: "codex" | "claude"): Record<string, unknown> {
  return engine === "claude"
    ? { engine: "claude_code_cli", command: "claude -p --output-format stream-json --include-hook-events", permission_mode: "default", known_gaps: ["token and usage counts may be incomplete", "raw transcript is not primary evidence"] }
    : { engine: "codex_cli", command: "codex exec --json", permission_mode: "workspace-write", known_gaps: ["token and usage counts may be incomplete", "raw transcript is not primary evidence"] };
}

async function buildFrozenV01PlanProjection(
  identityState: V01IdentityState,
  request: FrozenV01PlanProjectionRequest,
): Promise<{ ok: true; name: V01PlanProjectionName; bytes: Uint8Array } | InvalidV01Result> {
  const parseMember = async (file: string, kind: LegacyV01DocumentKind): Promise<unknown | null> => {
    const name = parseDirectChildName(file)!;
    const parsed = await identityState.pack.parseV01Member(name, kind);
    return parsed.ok ? parsed.value : null;
  };
  const [workRaw, compilationRaw, loopRaw] = await Promise.all([
    parseMember("work-item.json", "work-item"),
    parseMember("compilation-record.json", "compilation-record"),
    parseMember("generated.loop.yaml", "generated-loop"),
  ]);
  if (!isRecord(workRaw) || !isRecord(compilationRaw) || !isRecord(loopRaw) || typeof workRaw.prompt !== "string" || typeof workRaw.workspace_root !== "string" || typeof workRaw.work_item_id !== "string" || typeof compilationRaw.compilation_id !== "string") return invalidV01();
  const token = compilationRaw.compilation_id.startsWith("compilation_") ? compilationRaw.compilation_id.slice("compilation_".length) : compilationRaw.compilation_id.replace(/^[a-z]+_/, "");
  const intakeBrief = {
    schema_version: "0.1", intake_brief_id: `ib_${token}`, objective: workRaw.prompt,
    scope: [(loopRaw.outcome as { summary?: unknown } | undefined)?.summary],
    allowed_context: (loopRaw.context_contract as { required?: unknown } | undefined)?.required,
    forbidden_context: (loopRaw.context_contract as { forbidden?: unknown } | undefined)?.forbidden,
    allowed_tools: Array.isArray(loopRaw.tool_grants) ? loopRaw.tool_grants.map((grant) => isRecord(grant) ? grant.id : null) : [],
    allowed_connectors: [], max_risk_tier: (loopRaw.risk_controls as { max_tier_without_approval?: unknown } | undefined)?.max_tier_without_approval,
    approval_bindings: ["compiler-pack-approved"], terminal_states: ["compiled"],
  };
  const brief = ApprovedIntakeBrief.safeParse(intakeBrief);
  if (!brief.success) return invalidV01();
  if (request.projection_name === "approved-intake-brief") return { ok: true, name: request.projection_name, bytes: new TextEncoder().encode(`${JSON.stringify(brief.data, null, 2)}\n`) };
  if (!isRecord(request.input) || !exactKeys(request.input, ["engine", "workspace_root", "created_at"]) || (request.input.engine !== "codex" && request.input.engine !== "claude") || typeof request.input.workspace_root !== "string" || typeof request.input.created_at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(request.input.created_at) || Number.isNaN(Date.parse(request.input.created_at))) return invalidV01();
  const workspaceRoot = resolve(request.input.workspace_root);
  if (workspaceRoot !== resolve(workRaw.workspace_root)) return invalidV01();
  const generatedName = parseDirectChildName("generated.loop.yaml")!;
  const generatedRow = identityState.packState.rows.find((row) => row.name === generatedName);
  if (generatedRow === undefined) return invalidV01();
  const roles = Array.isArray(loopRaw.roles) ? loopRaw.roles : [];
  const tasks = Array.isArray(loopRaw.tasks) ? loopRaw.tasks : [];
  const gates = Array.isArray(loopRaw.gates) ? loopRaw.gates : [];
  const evaluations = Array.isArray(loopRaw.evaluations) ? loopRaw.evaluations : [];
  const resolved = ResolvedRunPlan.safeParse({
    schema_version: "0.1", run_id: `run_${token}`, loop_family: loopRaw.loop_family,
    loopeix_version: loopRaw.version, loopeix_version_hash: generatedRow.sha256,
    work_item_id: workRaw.work_item_id, intake_brief_id: brief.data.intake_brief_id, created_at: request.input.created_at,
    assurance_profile: { id: "base", tightens: [] }, context_snapshot: loopRaw.context_contract,
    role_assignments: roles.map((role) => isRecord(role) ? { role: role.id, actor_id: `actor_${String(role.id).replaceAll("-", "_")}`, actor_type: "ai_agent" } : role),
    task_plan: tasks.map((task) => isRecord(task) ? { task_id: task.id, role: task.role, depends_on: task.depends_on, artifacts: task.artifacts, acceptance_checks: task.acceptance_checks } : task),
    tool_grants: loopRaw.tool_grants,
    workspace_boundary: { workspace_root: workspaceRoot, read: ["."], write: ["artifacts", "evidence", "evaluations", "handoffs", "findings"] },
    adapter_plan: v01AdapterPlan(request.input.engine),
    gate_plan: gates.map((gate) => isRecord(gate) ? { gate_id: gate.id, blocking: gate.blocking, inputs_required: gate.inputs_required, waiver_allowed: gate.waiver_allowed } : gate),
    evaluation_plan: evaluations.map((evaluation) => isRecord(evaluation) ? { evaluation_id: evaluation.id, type: evaluation.type, required: evaluation.required, ...(evaluation.command === undefined ? {} : { command: evaluation.command }) } : evaluation),
    risk_controls: loopRaw.risk_controls,
  });
  return resolved.success ? { ok: true, name: request.projection_name, bytes: new TextEncoder().encode(`${JSON.stringify(resolved.data, null, 2)}\n`) } : invalidV01();
}

const AUTOMATIC_V01_POLICY: LegacyCompatibilityPolicy = Object.freeze({ mode: "operator-approved-finite", max_member_bytes: 67_108_864, max_total_bytes: 268_435_456, max_heap_bytes: 536_870_912, max_elapsed_ms: 30_000, approved_by: "operator" });
const V01_COMPILED_PACK_NAMES = ["catalog-resolution.json", "compilation-record.json", "compile-report.md", "generated.loop.yaml", "intake-record.json", "pack-manifest.json", "work-item.json"] as const;
const V01_HOLD_PACK_NAMES = ["catalog-resolution.json", "compile-report.md", "intake-record.json", "pack-manifest.json", "work-item.json"] as const;
const FROZEN_V01_CATALOG_VERSION_HASH = "sha256:4bba5fca6ce73a6d21598890001a45e03c349a3a1fa78148b802497a22eda823";

function resolveV01Policy(policy: LegacyCompatibilityPolicy | null): LegacyCompatibilityPolicy | null {
  if (policy === null) return AUTOMATIC_V01_POLICY;
  const positive = (value: number): boolean => Number.isSafeInteger(value) && value > 0;
  if (policy.mode !== "operator-approved-finite" || policy.approved_by !== "operator" || !positive(policy.max_member_bytes) || !positive(policy.max_total_bytes) || !positive(policy.max_heap_bytes) || !positive(policy.max_elapsed_ms) || policy.max_total_bytes < policy.max_member_bytes || policy.max_heap_bytes < policy.max_member_bytes) return null;
  return Object.freeze({ ...policy });
}

function sortedV01Names(names: readonly DirectChildName[]): readonly DirectChildName[] | null {
  if (names.length === 0 || new Set(names).size !== names.length || names.some((name) => parseDirectChildName(name) !== name)) return null;
  const sorted = [...names].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  const signature = sorted.join("\n");
  if (signature !== [...V01_COMPILED_PACK_NAMES].sort().join("\n") && signature !== [...V01_HOLD_PACK_NAMES].sort().join("\n")) return null;
  return sorted;
}

async function snapshotV01Member(member: V01MemberStore): Promise<{ ok: true; bytes: Uint8Array } | { ok: false; reason: "LEGACY_REPLAY_RESOURCE_LIMIT" | "IO_HELPER_UNAVAILABLE"; message: string }> {
  return member.kind === "helper-capture" ? member.capture.snapshotBytes() : { ok: true, bytes: new Uint8Array(member.bytes) };
}

function sourceMemberParseKind(name: DirectChildName): LegacyV01DocumentKind | null {
  switch (name) {
    case "catalog-resolution.json": return "catalog-resolution";
    case "compilation-record.json": return "compilation-record";
    case "generated.loop.yaml": return "generated-loop";
    case "intake-record.json": return "intake-record";
    case "work-item.json": return "work-item";
    case "compile-report.md":
    case "pack-manifest.json": return null;
  }
  return null;
}

function cloneV01ParseResult(result: LegacyV01ParseResult): LegacyV01ParseResult {
  if (!result.ok) return { ...result };
  try {
    return { ...result, value: structuredClone(result.value) };
  } catch {
    return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "The captured V01 parse result could not be copied." };
  }
}

async function buildRegisteredV01Pack(
  origin: "captured-source" | "frozen-regeneration",
  members: ReadonlyMap<DirectChildName, V01MemberStore>,
  boundIdentity: CapturedPackIdentityV01 | null,
): Promise<RegisteredCapturedCompilePackV01Result> {
  const names = sortedV01Names([...members.keys()]);
  if (names === null) return invalidV01();
  const rows: Array<{ name: DirectChildName; byte_length: number; sha256: Hash }> = [];
  for (const name of names) {
    const member = members.get(name);
    if (member === undefined) return invalidV01();
    const snapshot = await snapshotV01Member(member);
    if (!snapshot.ok) return snapshot;
    rows.push({ name, byte_length: snapshot.bytes.byteLength, sha256: hashRawBytes(snapshot.bytes) });
  }
  const rootHash = hashCanonical(rows.map((row) => ({ byte_length: row.byte_length, name: row.name, sha256: row.sha256 })));
  const total = rows.reduce((sum, row) => sum + row.byte_length, 0);
  let pack: CapturedCompilePack;
  pack = Object.freeze({
    schema_version: "0.1",
    replay_capture_origin: origin,
    total_byte_length: total,
    source_pack_root_hash: rootHash,
    memberNames: () => Object.freeze([...names]),
    memberByteLength: (name: DirectChildName) => rows.find((row) => row.name === name)?.byte_length ?? -1,
    snapshotMemberBytes: async (name: DirectChildName) => {
      const member = members.get(name);
      return member === undefined ? { ok: false as const, reason: "IO_HELPER_UNAVAILABLE" as const, message: "The captured pack member is unavailable." } : snapshotV01Member(member);
    },
    parseV01Member: async (name: DirectChildName, kind: LegacyV01DocumentKind) => {
      const member = members.get(name);
      if (member?.kind === "helper-capture") return member.capture.parseV01(kind);
      if (member?.kind === "captured-source" && member.parse_kind === kind && member.parse_result !== null) {
        return cloneV01ParseResult(member.parse_result);
      }
      return { ok: false as const, reason: "INVALID_V01_DOCUMENT" as const, message: "Regenerated members are validated only through exact replay." };
    },
  }) as CapturedCompilePack;
  v01PackRegistry.set(pack, { origin, members, rows: Object.freeze(rows.map((row) => Object.freeze(row))), rootHash, boundIdentity, accessIssued: false });
  return { ok: true, pack };
}

export async function issueV01SourcePackRegistrationAdapter(
  session: AnchoredReadSession,
  recognized_members: readonly DirectChildName[],
  legacy_policy: LegacyCompatibilityPolicy | null,
): Promise<V01PackRegistrationAdapterResult<V01SourcePackRegistrationAdapter>> {
  const read = readSessionRegistry.get(session);
  const policy = resolveV01Policy(legacy_policy);
  const names = sortedV01Names(recognized_members);
  if (read === undefined || !read.open || policy === null || names === null) return invalidV01();
  const members = new Map<DirectChildName, V01MemberStore>();
  let remaining = policy.max_total_bytes;
  for (const name of names) {
    const captured = await captureStructuredFile(join(read.path, name), {
      ...policy,
      max_total_bytes: remaining,
    });
    if (!captured.ok) {
      return captured.reason === "LEGACY_REPLAY_RESOURCE_LIMIT" || captured.reason === "INPUT_TOO_LARGE"
        ? { ok: false, reason: "LEGACY_REPLAY_RESOURCE_LIMIT", message: captured.message }
        : { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: captured.message };
    }
    const snapshot = await captured.capture.snapshotBytes();
    if (!snapshot.ok) {
      await releaseCapturedStructuredFile(captured.capture);
      return snapshot;
    }
    const parseKind = sourceMemberParseKind(name);
    const parseResult = parseKind === null ? null : await captured.capture.parseV01(parseKind);
    const released = await releaseCapturedStructuredFile(captured.capture);
    if (!released.ok) return released;
    remaining -= captured.capture.byte_length;
    if (remaining < 0) return { ok: false, reason: "LEGACY_REPLAY_RESOURCE_LIMIT", message: "The V01 pack exceeds the aggregate byte limit." };
    members.set(name, {
      kind: "captured-source",
      bytes: new Uint8Array(snapshot.bytes),
      parse_kind: parseKind,
      parse_result: parseResult,
    });
  }
  const adapter = Object.freeze({ origin: "captured-source" }) as V01SourcePackRegistrationAdapter;
  sourceAdapterRegistry.set(adapter, { members, policy, consumed: false });
  return { ok: true, adapter };
}

export function issueCapturedV01SourcePackRegistrationAdapter(
  captured_members: readonly Readonly<{
    name: DirectChildName;
    bytes: Uint8Array;
    parse_kind: LegacyV01DocumentKind | null;
    parse_result: LegacyV01ParseResult | null;
  }>[],
  legacy_policy: LegacyCompatibilityPolicy | null,
): V01PackRegistrationAdapterResult<V01SourcePackRegistrationAdapter> {
  const policy = resolveV01Policy(legacy_policy);
  const names = sortedV01Names(captured_members.map(({ name }) => name));
  if (policy === null || names === null || captured_members.length !== names.length) return invalidV01();

  const byName = new Map(captured_members.map((member) => [member.name, member]));
  const members = new Map<DirectChildName, V01MemberStore>();
  let total = 0;
  for (const name of names) {
    const captured = byName.get(name);
    const expectedKind = sourceMemberParseKind(name);
    if (captured === undefined || captured.parse_kind !== expectedKind
      || !(captured.bytes instanceof Uint8Array)
      || !(captured.bytes.buffer instanceof ArrayBuffer)
      || Object.getPrototypeOf(captured.bytes) !== Uint8Array.prototype
      || captured.bytes.byteLength > policy.max_member_bytes) return invalidV01();
    total += captured.bytes.byteLength;
    if (!Number.isSafeInteger(total) || total > policy.max_total_bytes) return invalidV01();

    if (expectedKind === null) {
      if (captured.parse_result !== null) return invalidV01();
    } else {
      const parsed = captured.parse_result;
      if (parsed === null || (parsed.ok && (
        parsed.schema_version !== "0.1" || parsed.kind !== expectedKind
        || parsed.byte_length !== captured.bytes.byteLength
        || parsed.raw_hash !== hashRawBytes(captured.bytes)
      ))) return invalidV01();
    }
    members.set(name, {
      kind: "captured-source",
      bytes: new Uint8Array(captured.bytes),
      parse_kind: expectedKind,
      parse_result: captured.parse_result === null ? null : cloneV01ParseResult(captured.parse_result),
    });
  }
  const adapter = Object.freeze({ origin: "captured-source" }) as V01SourcePackRegistrationAdapter;
  sourceAdapterRegistry.set(adapter, { members, policy, consumed: false });
  return { ok: true, adapter };
}

export async function openFrozenV01RegenerationCapture(
  identity: CapturedPackIdentityV01,
  expected_members: readonly DirectChildName[],
  legacy_policy: LegacyCompatibilityPolicy | null,
): Promise<
  | { ok: true; session: FrozenV01RegenerationCaptureSession }
  | { ok: false; reason: "INVALID_V01_REPLAY_OUTPUT" | "LEGACY_REPLAY_RESOURCE_LIMIT" | "IO_HELPER_UNAVAILABLE"; message: string }
> {
  const identityState = v01IdentityRegistry.get(identity);
  const policy = resolveV01Policy(legacy_policy);
  const names = sortedV01Names(expected_members);
  if (identityState === undefined || policy === null || names === null || names.join("\n") !== identity.members.map((row) => row.name).join("\n")) return invalidV01();
  let session: FrozenV01RegenerationCaptureSession;
  session = Object.freeze({
    source_pack_root_hash: identity.source_pack_root_hash,
    catalog_version_hash: identity.selector.catalog_version_hash,
    captureMember: async (name: DirectChildName, bytes: Uint8Array): Promise<AnchoredIoResult> => {
      const state = regenerationSessionRegistry.get(session);
      if (state === undefined || state.state !== "open" || !state.expected.includes(name) || state.members.has(name) || !(bytes instanceof Uint8Array) || !(bytes.buffer instanceof ArrayBuffer) || Object.getPrototypeOf(bytes) !== Uint8Array.prototype) return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The regenerated member capture is invalid or reused." };
      state.total += bytes.byteLength;
      if (bytes.byteLength > state.policy.max_member_bytes || state.total > state.policy.max_total_bytes) { state.state = "aborted"; return { ok: false, reason: "INPUT_TOO_LARGE", message: "The regenerated member exceeds the finite replay policy." }; }
      state.members.set(name, new Uint8Array(bytes));
      return { ok: true };
    },
    seal: async () => {
      const state = regenerationSessionRegistry.get(session);
      if (state === undefined || state.state !== "open" || state.expected.some((name) => !state.members.has(name)) || state.members.size !== state.expected.length) return invalidV01();
      state.state = "sealed";
      const adapter = Object.freeze({ origin: "frozen-regeneration", source_pack_root_hash: identity.source_pack_root_hash, catalog_version_hash: identity.selector.catalog_version_hash }) as V01RegeneratedPackRegistrationAdapter;
      regenerationAdapterRegistry.set(adapter, { identity, members: new Map([...state.members].map(([name, bytes]) => [name, new Uint8Array(bytes)])), policy: state.policy, consumed: false });
      return { ok: true as const, adapter };
    },
    abort: async () => {
      const state = regenerationSessionRegistry.get(session);
      if (state === undefined || state.state !== "open") return { ok: false as const, reason: "INVALID_OUTPUT_CAPTURE" as const, message: "The regeneration session is not open." };
      state.state = "aborted";
      state.members.clear();
      return { ok: true as const };
    },
  });
  regenerationSessionRegistry.set(session, { identity, expected: names, policy, members: new Map(), total: 0, state: "open" });
  return { ok: true, session };
}

export async function createRegisteredSourceCompilePackV01(
  adapter: V01SourcePackRegistrationAdapter,
): Promise<RegisteredCapturedCompilePackV01Result> {
  const state = sourceAdapterRegistry.get(adapter);
  if (state === undefined || state.consumed) return invalidV01();
  state.consumed = true;
  return buildRegisteredV01Pack("captured-source", new Map(state.members), null);
}

export async function createRegisteredRegeneratedCompilePackV01(
  adapter: V01RegeneratedPackRegistrationAdapter,
  identity: CapturedPackIdentityV01,
): Promise<RegisteredCapturedCompilePackV01Result> {
  const state = regenerationAdapterRegistry.get(adapter);
  if (state === undefined || state.consumed || state.identity !== identity || !v01IdentityRegistry.has(identity)) return invalidV01();
  state.consumed = true;
  return buildRegisteredV01Pack("frozen-regeneration", new Map([...state.members].map(([name, bytes]) => [name, { kind: "private-bytes" as const, bytes: new Uint8Array(bytes) }])), identity);
}

export function issueV01SourcePackAccess(pack: CapturedCompilePack): { ok: true; access: V01SourcePackAccess } | InvalidV01Result {
  const state = v01PackRegistry.get(pack);
  if (state === undefined || state.origin !== "captured-source" || state.accessIssued) return invalidV01();
  state.accessIssued = true;
  const access = Object.freeze({ origin: "captured-source" }) as V01SourcePackAccess;
  sourceAccessRegistry.set(access, { pack, consumed: false });
  return { ok: true, access };
}

export function issueV01RegeneratedPackAccess(
  pack: CapturedCompilePack,
  identity: CapturedPackIdentityV01,
): { ok: true; access: V01RegeneratedPackAccess } | InvalidV01Result {
  const state = v01PackRegistry.get(pack);
  if (state === undefined || state.origin !== "frozen-regeneration" || state.accessIssued || state.boundIdentity !== identity || !v01IdentityRegistry.has(identity)) return invalidV01();
  state.accessIssued = true;
  const access = Object.freeze({ origin: "frozen-regeneration" }) as V01RegeneratedPackAccess;
  regeneratedAccessRegistry.set(access, { pack, identity, consumed: false });
  return { ok: true, access };
}

export async function registerCapturedPackIdentityV01(
  access: V01SourcePackAccess,
  selector: V01ReplaySelector,
  legacy_policy: LegacyCompatibilityPolicy | null,
): Promise<
  | { ok: true; identity: CapturedPackIdentityV01 }
  | { ok: false; reason: "INVALID_V01_REPLAY_OUTPUT" | "LEGACY_REPLAY_RESOURCE_LIMIT" | "IO_HELPER_UNAVAILABLE"; message: string }
> {
  const accessState = sourceAccessRegistry.get(access);
  const policy = resolveV01Policy(legacy_policy);
  if (accessState === undefined || accessState.consumed || policy === null || !isRecord(selector) || !exactKeys(selector, ["schema_version", "catalog_version_hash"]) || selector.schema_version !== "0.1" || selector.catalog_version_hash !== FROZEN_V01_CATALOG_VERSION_HASH) return invalidV01();
  accessState.consumed = true;
  const packState = v01PackRegistry.get(accessState.pack);
  if (packState === undefined || packState.origin !== "captured-source" || packState.rows.some((row) => row.byte_length > policy.max_member_bytes) || accessState.pack.total_byte_length > policy.max_total_bytes) return invalidV01();
  const catalogName = parseDirectChildName("catalog-resolution.json")!;
  const manifestName = parseDirectChildName("pack-manifest.json")!;
  const catalogMember = packState.members.get(catalogName);
  const manifestMember = packState.members.get(manifestName);
  if (catalogMember === undefined || manifestMember === undefined) return invalidV01();
  const catalog = await accessState.pack.parseV01Member(catalogName, "catalog-resolution");
  if (!catalog.ok || !isRecord(catalog.value) || catalog.value.schema_version !== "0.1" || catalog.value.catalog_version_hash !== selector.catalog_version_hash || typeof catalog.value.terminal_state !== "string") return invalidV01();
  const manifestSnapshot = await snapshotV01Member(manifestMember);
  if (!manifestSnapshot.ok) return manifestSnapshot;
  let manifestValue: unknown;
  try { manifestValue = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifestSnapshot.bytes)); }
  catch { return invalidV01(); }
  const manifest = CompilePackManifest.safeParse(manifestValue);
  if (!manifest.success || manifest.data.schema_version !== "0.1" || manifest.data.terminal_state !== catalog.value.terminal_state) return invalidV01();
  const expectedNames = manifest.data.terminal_state === "compiled" ? V01_COMPILED_PACK_NAMES : V01_HOLD_PACK_NAMES;
  if ([...packState.rows.map((row) => row.name)].sort().join("\n") !== [...expectedNames].sort().join("\n")) return invalidV01();
  const hashes = new Map(packState.rows.map((row) => [row.name, row.sha256]));
  const expectedHashes: Array<[string, string | undefined]> = [
    ["work-item.json", manifest.data.file_hashes.work_item], ["intake-record.json", manifest.data.file_hashes.intake],
    ["catalog-resolution.json", manifest.data.file_hashes.catalog_resolution], ["compile-report.md", manifest.data.file_hashes.report],
    ["compilation-record.json", manifest.data.file_hashes.compilation], ["generated.loop.yaml", manifest.data.file_hashes.generated_loop],
  ];
  if (expectedHashes.some(([name, expected]) => expected !== undefined && hashes.get(name as DirectChildName) !== expected)) return invalidV01();
  const frozenSelector = Object.freeze({ schema_version: "0.1", catalog_version_hash: selector.catalog_version_hash }) as V01ReplaySelector;
  const identity = Object.freeze({ selector: frozenSelector, source_pack_root_hash: packState.rootHash, members: Object.freeze(packState.rows.map((row) => Object.freeze({ name: row.name, byte_length: row.byte_length, sha256: row.sha256 }))) }) as CapturedPackIdentityV01;
  v01IdentityRegistry.set(identity, { pack: accessState.pack, packState, selector: frozenSelector, exactIssued: false, authorityIssued: false });
  return { ok: true, identity };
}

export async function registerExactV01ReplaySuccess(
  identity: CapturedPackIdentityV01,
  regenerated: V01RegeneratedPackAccess,
): Promise<
  | { ok: true; replay: ExactV01ReplaySuccess }
  | { ok: false; reason: "INVALID_V01_REPLAY_OUTPUT" | "LEGACY_REPLAY_RESOURCE_LIMIT" | "IO_HELPER_UNAVAILABLE"; message: string }
> {
  const identityState = v01IdentityRegistry.get(identity);
  const access = regeneratedAccessRegistry.get(regenerated);
  if (identityState === undefined || identityState.exactIssued || access === undefined || access.consumed || access.identity !== identity) return invalidV01();
  access.consumed = true;
  identityState.exactIssued = true;
  const regeneratedState = v01PackRegistry.get(access.pack);
  if (regeneratedState === undefined || regeneratedState.boundIdentity !== identity || regeneratedState.rows.length !== identityState.packState.rows.length) return invalidV01();
  for (let index = 0; index < identityState.packState.rows.length; index += 1) {
    const sourceRow = identityState.packState.rows[index]!;
    const regeneratedRow = regeneratedState.rows[index];
    if (regeneratedRow === undefined || regeneratedRow.name !== sourceRow.name || regeneratedRow.byte_length !== sourceRow.byte_length || regeneratedRow.sha256 !== sourceRow.sha256) return invalidV01();
    const sourceMember = identityState.packState.members.get(sourceRow.name);
    const regeneratedMember = regeneratedState.members.get(sourceRow.name);
    if (sourceMember === undefined || regeneratedMember === undefined) return invalidV01();
    const [sourceBytes, regeneratedBytes] = await Promise.all([snapshotV01Member(sourceMember), snapshotV01Member(regeneratedMember)]);
    if (!sourceBytes.ok) return sourceBytes;
    if (!regeneratedBytes.ok) return regeneratedBytes;
    if (!Buffer.from(sourceBytes.bytes).equals(Buffer.from(regeneratedBytes.bytes))) return invalidV01();
  }
  const replay = Object.freeze({ captured_pack_identity: identity, selector: identity.selector, source_pack_root_hash: identity.source_pack_root_hash }) as ExactV01ReplaySuccess;
  exactReplayRegistry.set(replay, { identity, consumed: false });
  return { ok: true, replay };
}

export function createV01ReplayOutputAuthority(
  identity: CapturedPackIdentityV01,
  replay: ExactV01ReplaySuccess,
): { ok: true; authority: V01ReplayOutputAuthority } | InvalidV01Result {
  const identityState = v01IdentityRegistry.get(identity);
  const replayState = exactReplayRegistry.get(replay);
  if (identityState === undefined || identityState.authorityIssued || replayState === undefined || replayState.consumed || replayState.identity !== identity || replay.captured_pack_identity !== identity || replay.selector !== identity.selector || replay.source_pack_root_hash !== identity.source_pack_root_hash) return invalidV01();
  replayState.consumed = true;
  identityState.authorityIssued = true;
  let authority: V01ReplayOutputAuthority;
  authority = Object.freeze({
    selector: identity.selector,
    source_pack_root_hash: identity.source_pack_root_hash,
    mintPackMemberCopy: async (name: DirectChildName): Promise<VerifiedV01ReplayOutputBytesResult> => {
      const state = v01AuthorityRegistry.get(authority);
      const member = identityState.packState.members.get(name);
      const row = identityState.packState.rows.find((candidate) => candidate.name === name);
      if (state === undefined || member === undefined || row === undefined || state.memberMints.has(name)) return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The V01 member handle is invalid or reused." };
      state.memberMints.add(name);
      const snapshot = await snapshotV01Member(member);
      if (!snapshot.ok) return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: snapshot.message };
      if (snapshot.bytes.byteLength !== row.byte_length || hashRawBytes(snapshot.bytes) !== row.sha256) return { ok: false, reason: "OUTPUT_HASH_FAILED", message: "The retained V01 member no longer matches its identity." };
      const output = Object.freeze({ schema_version: "0.1", byte_length: row.byte_length, sha256: row.sha256, source_pack_root_hash: identity.source_pack_root_hash, catalog_version_hash: identity.selector.catalog_version_hash, projection_kind: "pack-member-copy", source_member_name: name, projection_name: null }) as VerifiedV01ReplayOutputBytes;
      verifiedV01OutputRegistry.set(output, { identity, bytes: new Uint8Array(snapshot.bytes), consumed: false });
      return { ok: true, output };
    },
    mintFrozenPlanProjection: async (request: FrozenV01PlanProjectionRequest): Promise<VerifiedV01ReplayOutputBytesResult> => {
      const state = v01AuthorityRegistry.get(authority);
      if (state === undefined || !isRecord(request) || typeof request.projection_name !== "string" || (request.projection_name !== "approved-intake-brief" && request.projection_name !== "resolved-run-plan") || state.projectionMints.has(request.projection_name)) return { ok: false, reason: "INVALID_V01_REPLAY_OUTPUT", message: "The frozen V01 plan projection request is invalid or reused." };
      state.projectionMints.add(request.projection_name);
      const built = await buildFrozenV01PlanProjection(identityState, request);
      if (!built.ok) return built;
      const sha256 = hashRawBytes(built.bytes);
      const output = Object.freeze({ schema_version: "0.1", byte_length: built.bytes.byteLength, sha256, source_pack_root_hash: identity.source_pack_root_hash, catalog_version_hash: identity.selector.catalog_version_hash, projection_kind: "frozen-plan-projection", source_member_name: null, projection_name: built.name }) as VerifiedV01ReplayOutputBytes;
      verifiedV01OutputRegistry.set(output, { identity, bytes: new Uint8Array(built.bytes), consumed: false });
      return { ok: true, output };
    },
    mintDestinationCapability: async (root_path: string, purpose: "replay-pack-copy" | "planned-run"): Promise<V01DestinationCapabilityResult> => {
      const state = v01AuthorityRegistry.get(authority);
      if (state === undefined || state.destinationPurposes.has(purpose)) return invalidV01();
      try {
        const metadata = await lstat(root_path, { bigint: true });
        if (!metadata.isDirectory() || metadata.isSymbolicLink()) return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The V01 destination root must be a direct directory." };
        const path = await realpath(root_path);
        const current = await stat(path, { bigint: true });
        state.destinationPurposes.add(purpose);
        const capability = Object.freeze({ schema_version: "0.1", purpose, source_pack_root_hash: identity.source_pack_root_hash, catalog_version_hash: identity.selector.catalog_version_hash }) as V01DestinationCapability;
        v01CapabilityRegistry.set(capability, { path, device: current.dev.toString(), inode: current.ino.toString(), identity, purpose, consumed: false });
        return { ok: true, capability };
      } catch { return { ok: false, reason: "INVALID_INPUT_ROOT", message: "The V01 destination root is unavailable." }; }
    },
  });
  v01AuthorityRegistry.set(authority, { identity, memberMints: new Set(), projectionMints: new Set(), destinationPurposes: new Set() });
  return { ok: true, authority };
}

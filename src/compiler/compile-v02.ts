import { basename, dirname, join, resolve } from "node:path";

import {
  DEFAULT_CATALOG_SNAPSHOT_V02,
  S35_COMPILER_BUNDLE_ID_V02,
} from "../catalog/default-items.js";
import { compareUtf8BytesV02 } from "../catalog/item-v02.js";
import {
  CREDENTIAL_RULE_IDS_V02,
  type CredentialRuleIdV02,
} from "../security/credential-detector-v02.js";
import {
  anchorDestinationRootV02,
  captureOutputBytes,
  confirmV02CompilerProjection,
  createV02CompilerWriteAuthoritySet,
  openV02OutputAdmissionSession,
  parseDirectChildName,
  scanAndAdmitOutputBytes,
  sealV02OutputAdmissionSession,
  writeV02CompilerOutputs,
  type AnchoredDestinationRootV02,
  type CompilerWriterOptions,
  type DirectChildName,
  type SealedV02OutputSet,
  type V02OutputPurpose,
} from "../io/output-capabilities.js";
import {
  bindPreflightedCompileBindingPayloadV02,
  preflightCompileBindingPayloadV02,
  type BindingInputRecordV02,
} from "./binding-input-v02.js";
import {
  allocateAndCommitCompileIdentityV02,
  type CompileIdentityV02,
} from "./compile-id.js";
import { verifyCompileStoreV02 } from "./compile-store.js";
import { lookupRegisteredCatalogV02 } from "../catalog/registry.js";
import { WorkItemRecordV02 } from "./records.js";
import { regenerateCompilePackV02, type RegenerateCompilePackV02Success } from "./serialize-v02.js";

export type PublicFindingV02 = Readonly<{
  code: string;
  message: string;
  field: string | null;
}>;

export type CompileRequestRejectReasonV02 =
  | "INPUT_TOO_LARGE"
  | "INVALID_DOCUMENT_ENVELOPE"
  | "INVALID_BINDING_INPUT"
  | "INVALID_CATALOG"
  | "SENSITIVE_INPUT_REJECTED"
  | "SENSITIVE_OUTPUT_REJECTED"
  | "COMPILED_OUTPUT_TOO_LARGE"
  | "OUTPUT_SCAN_FAILED"
  | "OUTPUT_HASH_FAILED"
  | "OUTPUT_CAPTURE_FAILED"
  | "INVALID_V02_PROJECTION"
  | "COMPILE_STORE_INVALID"
  | "DESTINATION_EXISTS"
  | "COMPILE_ID_COLLISION_LIMIT"
  | "IO_HELPER_UNAVAILABLE"
  | "IO_IDENTITY_MISMATCH"
  | "IO_DURABILITY_UNCONFIRMED";

type NonSensitiveRejectReasonV02 = Exclude<
  CompileRequestRejectReasonV02,
  "SENSITIVE_INPUT_REJECTED" | "SENSITIVE_OUTPUT_REJECTED"
>;

export type CompileRequestResultV02 =
  | {
      ok: true;
      disposition: "compiled";
      terminal_state: "compiled";
      reason: null;
      pack_ref: string;
      standalone_ref: string | null;
      findings: [];
    }
  | ({
      ok: false;
      pack_ref: string;
      standalone_ref: null;
      findings: PublicFindingV02[];
    } & (
      | { disposition: "hold"; terminal_state: "hold-ambiguous"; reason: "CATALOG_AMBIGUOUS" }
      | { disposition: "hold"; terminal_state: "hold-risk"; reason: "RISK_BOUNDARY_UNRESOLVED" }
      | { disposition: "hold"; terminal_state: "hold-no-item"; reason: "NO_CATALOG_ITEM" }
      | { disposition: "hold"; terminal_state: "hold-project-binding-required"; reason: "PROJECT_BINDING_REQUIRED" }
    ))
  | {
      ok: false;
      disposition: "rejected";
      terminal_state: null;
      reason: "SENSITIVE_INPUT_REJECTED";
      pack_ref: null;
      standalone_ref: null;
      findings: [];
      location: "prompt" | "binding-source-ref" | "binding-value";
      rule_id: CredentialRuleIdV02;
    }
  | {
      ok: false;
      disposition: "rejected";
      terminal_state: null;
      reason: "SENSITIVE_OUTPUT_REJECTED";
      pack_ref: null;
      standalone_ref: null;
      findings: [];
      member_id: DirectChildName;
      rule_id: CredentialRuleIdV02;
    }
  | {
      ok: false;
      disposition: "rejected";
      terminal_state: null;
      reason: NonSensitiveRejectReasonV02;
      pack_ref: null;
      standalone_ref: null;
      findings: PublicFindingV02[];
    };

export type CompileV02Request = Readonly<{
  prompt: string;
  workspace_root: string;
  binding_payload_bytes?: Uint8Array;
  standalone_output_path?: string;
}>;

type CompileV02TestOptions = Readonly<{
  now?: () => number;
  randomBytes?: (size: 8) => Uint8Array;
  writer?: CompilerWriterOptions;
}>;

function rejected(reason: NonSensitiveRejectReasonV02): CompileRequestResultV02 {
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

function normalizePrivateFailureReason(
  reason:
    | NonSensitiveRejectReasonV02
    | "INVALID_OUTPUT_CAPTURE"
    | "INVALID_OUTPUT_BYTE_VIEW"
    | "INVALID_INPUT_ROOT",
): NonSensitiveRejectReasonV02 {
  if (reason === "INVALID_OUTPUT_CAPTURE" || reason === "INVALID_OUTPUT_BYTE_VIEW") return "OUTPUT_CAPTURE_FAILED";
  if (reason === "INVALID_INPUT_ROOT") return "IO_IDENTITY_MISMATCH";
  return reason;
}

function mapCandidateFailure(
  failure:
    | Exclude<CompileRequestResultV02, { ok: true } | { disposition: "hold" }>
    | { reason: NonSensitiveRejectReasonV02 },
): CompileRequestResultV02 {
  return "disposition" in failure ? failure : rejected(failure.reason);
}

function sensitiveInputResult(
  location: "prompt" | "binding-source-ref" | "binding-value",
  ruleId: CredentialRuleIdV02,
): CompileRequestResultV02 {
  return {
    ok: false,
    disposition: "rejected",
    terminal_state: null,
    reason: "SENSITIVE_INPUT_REJECTED",
    pack_ref: null,
    standalone_ref: null,
    findings: [],
    location,
    rule_id: ruleId,
  };
}

function credentialRuleId(value: string): CredentialRuleIdV02 | null {
  return (CREDENTIAL_RULE_IDS_V02 as readonly string[]).includes(value)
    ? value as CredentialRuleIdV02
    : null;
}

async function resolveStandaloneOutput(
  outputPath: string | undefined,
): Promise<
  | { ok: true; root: AnchoredDestinationRootV02 | null; basename: DirectChildName | null }
  | { ok: false; result: CompileRequestResultV02 }
> {
  if (outputPath === undefined) return { ok: true, root: null, basename: null };
  const resolved = resolve(outputPath);
  const name = parseDirectChildName(basename(resolved));
  if (name === null || join(dirname(resolved), name) !== resolved) {
    return { ok: false, result: rejected("IO_IDENTITY_MISMATCH") };
  }
  const anchored = await anchorDestinationRootV02(dirname(resolved), "standalone-parent");
  return anchored.ok
    ? { ok: true, root: anchored.root, basename: name }
    : { ok: false, result: rejected("IO_IDENTITY_MISMATCH") };
}

function createWorkItem(input: CompileV02Request, identity: CompileIdentityV02, bindingInput: BindingInputRecordV02) {
  const sourceContext = [...new Set(bindingInput.bindings
    .filter(({ source, source_ref }) => source === "workspace-observation" && source_ref !== null)
    .map(({ source_ref }) => source_ref!))]
    .sort(compareUtf8BytesV02);
  return WorkItemRecordV02.parse({
    schema_version: "0.2",
    work_item_id: identity.work_item_id,
    submitted_at: identity.submitted_at,
    prompt: input.prompt,
    workspace_root: input.workspace_root,
    operator_constraints: [],
    source_context: sourceContext,
  });
}

function admitOutputSet(
  projection: Parameters<typeof openV02OutputAdmissionSession>[0],
  purpose: V02OutputPurpose,
  regenerated: RegenerateCompilePackV02Success,
):
  | { ok: true; output_set: SealedV02OutputSet }
  | { ok: false; result: CompileRequestResultV02 } {
  const opened = openV02OutputAdmissionSession(projection, purpose);
  if (!opened.ok) {
    return {
      ok: false,
      result: rejected(opened.reason === "INVALID_V02_PROJECTION" ? opened.reason : "OUTPUT_CAPTURE_FAILED"),
    };
  }
  for (const name of opened.session.allowed_members) {
    const member = purpose === "standalone-loop"
      ? regenerated.pack_members.find((candidate) => candidate.name === "generated.loop.yaml")
      : regenerated.pack_members.find((candidate) => candidate.name === name);
    if (member === undefined) return { ok: false, result: rejected("INVALID_V02_PROJECTION") };
    const captured = captureOutputBytes(opened.session, name, member.bytes);
    if (!captured.ok) return { ok: false, result: rejected(normalizePrivateFailureReason(captured.reason)) };
    const admitted = scanAndAdmitOutputBytes(captured.capture);
    if (!admitted.ok) {
      if (admitted.reason === "SENSITIVE_OUTPUT_REJECTED") {
        const ruleId = credentialRuleId(admitted.rule_id);
        if (ruleId === null) return { ok: false, result: rejected("OUTPUT_CAPTURE_FAILED") };
        return {
          ok: false,
          result: {
            ok: false,
            disposition: "rejected",
            terminal_state: null,
            reason: admitted.reason,
            pack_ref: null,
            standalone_ref: null,
            findings: [],
            member_id: admitted.member_id,
            rule_id: ruleId,
          },
        };
      }
      return { ok: false, result: rejected(normalizePrivateFailureReason(admitted.reason)) };
    }
  }
  const sealed = sealV02OutputAdmissionSession(opened.session);
  return sealed.ok
    ? { ok: true, output_set: sealed.output_set }
    : { ok: false, result: rejected("OUTPUT_CAPTURE_FAILED") };
}

/** Internal deterministic harness. Never export this symbol from the package root. */
export async function compileV02ForTest(
  input: CompileV02Request,
  options: CompileV02TestOptions = {},
): Promise<CompileRequestResultV02> {
  const registered = lookupRegisteredCatalogV02({
    schema_version: "0.2",
    compiler_bundle_id: S35_COMPILER_BUNDLE_ID_V02,
    catalog_version_hash: DEFAULT_CATALOG_SNAPSHOT_V02.catalog_hash,
  });
  if (!registered.ok) return rejected("INVALID_CATALOG");

  const preflight = preflightCompileBindingPayloadV02({
    prompt: input.prompt,
    binding_payload_bytes: input.binding_payload_bytes,
  });
  if (!preflight.ok) {
    return preflight.reason === "SENSITIVE_INPUT_REJECTED"
      ? sensitiveInputResult(preflight.location, preflight.rule_id)
      : rejected(preflight.reason);
  }

  const store = await verifyCompileStoreV02(input.workspace_root);
  if (!store.ok) return rejected(store.reason);
  const compileRoot = await anchorDestinationRootV02(join(input.workspace_root, ".loopeix", "compiles"), "compile-store");
  if (!compileRoot.ok) return rejected("COMPILE_STORE_INVALID");
  const standalone = await resolveStandaloneOutput(input.standalone_output_path);
  if (!standalone.ok) return standalone.result;

  type CandidateFailure = Exclude<CompileRequestResultV02, { ok: true } | { disposition: "hold" }>;
  let committed: RegenerateCompilePackV02Success | null = null;
  const allocation = await allocateAndCommitCompileIdentityV02<CandidateFailure>(store.store, {
    now: options.now,
    randomBytes: options.randomBytes,
    commitCandidate: async (_store, identity) => {
      const binding = bindPreflightedCompileBindingPayloadV02(preflight.preflight, {
        binding_input_id: identity.binding_input_id,
        work_item_id: identity.work_item_id,
        submitted_at: identity.submitted_at,
      });
      if (!binding.ok) {
        const failure = binding.reason === "SENSITIVE_INPUT_REJECTED"
          ? sensitiveInputResult(binding.location, binding.rule_id)
          : rejected(binding.reason);
        return { ok: false, reason: "CANDIDATE_ABORTED", failure: failure as CandidateFailure };
      }

      let workItem;
      try {
        workItem = createWorkItem(input, identity, binding.record);
      } catch {
        return { ok: false, reason: "CANDIDATE_ABORTED", failure: rejected("INVALID_BINDING_INPUT") as CandidateFailure };
      }
      const regenerated = regenerateCompilePackV02({
        work_item: workItem,
        binding_input: binding.record,
        compiler_bundle_id: S35_COMPILER_BUNDLE_ID_V02,
        catalog_version_hash: DEFAULT_CATALOG_SNAPSHOT_V02.catalog_hash,
      });
      if (!regenerated.ok) {
        const reason = regenerated.reason === "INVALID_V02_PROJECTION" || regenerated.reason === "OUTPUT_HASH_FAILED"
          ? regenerated.reason
          : regenerated.reason === "INVALID_CATALOG" ? "INVALID_CATALOG" : "INVALID_BINDING_INPUT";
        return { ok: false, reason: "CANDIDATE_ABORTED", failure: rejected(reason) as CandidateFailure };
      }

      const wantsStandalone = regenerated.catalog_resolution.terminal_state === "compiled" && standalone.root !== null;
      const purposes: readonly V02OutputPurpose[] = wantsStandalone
        ? ["standalone-loop", "compile-pack"]
        : ["compile-pack"];
      const projection = confirmV02CompilerProjection({
        kind: "compiler",
        schema_version: "0.2",
        compiler_bundle_id: S35_COMPILER_BUNDLE_ID_V02,
        catalog_version_hash: DEFAULT_CATALOG_SNAPSHOT_V02.catalog_hash,
        binding_input_hash: regenerated.binding_input_member.sha256,
        requested_output_purposes: purposes,
        output_budget_bytes: 33_554_432,
        compile_id: identity.compile_id,
        source_authoring_hash: regenerated.source_authoring_hash,
        terminal_state: regenerated.catalog_resolution.terminal_state,
      });
      if (!projection.ok) return { ok: false, reason: "CANDIDATE_ABORTED", failure: rejected("INVALID_V02_PROJECTION") as CandidateFailure };

      const outputSets: SealedV02OutputSet[] = [];
      for (const purpose of purposes) {
        const admitted = admitOutputSet(projection.projection, purpose, regenerated);
        if (!admitted.ok) return { ok: false, reason: "CANDIDATE_ABORTED", failure: admitted.result as CandidateFailure };
        outputSets.push(admitted.output_set);
      }
      const authorities = createV02CompilerWriteAuthoritySet(projection.projection, {
        compile_pack: compileRoot.root,
        standalone_loop: wantsStandalone ? standalone.root : null,
      }, outputSets);
      if (!authorities.ok) return {
        ok: false,
        reason: "CANDIDATE_ABORTED",
        failure: rejected(normalizePrivateFailureReason(authorities.reason)) as CandidateFailure,
      };
      const written = await writeV02CompilerOutputs(
        authorities.authorities,
        wantsStandalone ? standalone.basename : null,
        options.writer,
      );
      if (!written.ok) {
        if (written.reason === "DESTINATION_EXISTS" && written.collision_destination === "standalone-loop") {
          return {
            ok: false,
            reason: "CANDIDATE_ABORTED",
            failure: rejected("DESTINATION_EXISTS") as CandidateFailure,
          };
        }
        return written;
      }
      committed = regenerated;
      return written;
    },
  });

  if (!allocation.ok) {
    return allocation.reason === "CANDIDATE_ABORTED"
      ? mapCandidateFailure(allocation.failure)
      : rejected(normalizePrivateFailureReason(allocation.reason));
  }
  if (committed === null) return rejected("INVALID_V02_PROJECTION");
  const persisted = committed as RegenerateCompilePackV02Success;
  if (persisted.catalog_resolution.terminal_state === "compiled") {
    return {
      ok: true,
      disposition: "compiled",
      terminal_state: "compiled",
      reason: null,
      pack_ref: allocation.identity.compile_id,
      standalone_ref: standalone.basename,
      findings: [],
    };
  }
  const common = {
    ok: false as const,
    disposition: "hold" as const,
    pack_ref: allocation.identity.compile_id,
    standalone_ref: null,
    findings: [] as PublicFindingV02[],
  };
  switch (persisted.catalog_resolution.terminal_state) {
    case "hold-ambiguous": return { ...common, terminal_state: "hold-ambiguous", reason: "CATALOG_AMBIGUOUS" };
    case "hold-risk": return { ...common, terminal_state: "hold-risk", reason: "RISK_BOUNDARY_UNRESOLVED" };
    case "hold-no-item": return { ...common, terminal_state: "hold-no-item", reason: "NO_CATALOG_ITEM" };
    case "hold-project-binding-required": return {
      ...common,
      terminal_state: "hold-project-binding-required",
      reason: "PROJECT_BINDING_REQUIRED",
    };
    default: return rejected("INVALID_V02_PROJECTION");
  }
}

export async function compileV02(input: CompileV02Request): Promise<CompileRequestResultV02> {
  return compileV02ForTest(input);
}

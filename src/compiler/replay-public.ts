import {
  openCompilePackCaptureSessionV02,
  type CompilePackCaptureSessionV02,
} from "../io/compile-pack-capture-v02.js";
import {
  parseDirectChildName,
  type LegacyCompatibilityPolicy,
} from "../io/captured-file.js";
import { decodeStructuredDocumentV02 } from "../schema/decode-envelope.js";
import type { PublicFindingV02 } from "./compile-v02.js";
import { readCompilePackV01FromCapture, type ReadCompilePackV01Result } from "./read-pack.js";
import {
  readCompilePackV02FromCapture,
  type ReadCompilePackV02Result,
} from "./read-pack-v02.js";
import { replayCompilePackV01 } from "./replay-v01.js";
import { replayCompilePackV02 } from "./replay-v02.js";

type CompilePackReadFailureReason =
  | "INVALID_COMPILE_PACK"
  | "MISSING_SCHEMA_VERSION"
  | "MALFORMED_SCHEMA_VERSION"
  | "UNSUPPORTED_SCHEMA_VERSION"
  | "MIXED_SCHEMA_VERSION"
  | "INVALID_DOCUMENT_ENVELOPE"
  | "INPUT_TOO_LARGE"
  | "LEGACY_REPLAY_RESOURCE_LIMIT"
  | "IO_HELPER_UNAVAILABLE"
  | "IO_IDENTITY_MISMATCH";

type CompilePackReadFailureReasonNonLegacy = Exclude<
  CompilePackReadFailureReason,
  "LEGACY_REPLAY_RESOURCE_LIMIT"
>;

type CompilerPackTerminalOutcomeV01 =
  | { readonly terminal_state: "compiled"; readonly reason: null }
  | { readonly terminal_state: "hold-ambiguous"; readonly reason: "CATALOG_AMBIGUOUS" }
  | { readonly terminal_state: "hold-risk"; readonly reason: "RISK_BOUNDARY_UNRESOLVED" }
  | { readonly terminal_state: "hold-no-item"; readonly reason: "NO_CATALOG_ITEM" }
  | { readonly terminal_state: "failed-invalid-catalog"; readonly reason: "INVALID_CATALOG" };

type CompilerPackTerminalOutcomeV02 =
  | { readonly terminal_state: "compiled"; readonly reason: null }
  | { readonly terminal_state: "hold-ambiguous"; readonly reason: "CATALOG_AMBIGUOUS" }
  | { readonly terminal_state: "hold-risk"; readonly reason: "RISK_BOUNDARY_UNRESOLVED" }
  | { readonly terminal_state: "hold-no-item"; readonly reason: "NO_CATALOG_ITEM" }
  | {
      readonly terminal_state: "hold-project-binding-required";
      readonly reason: "PROJECT_BINDING_REQUIRED";
    };

export type CompilePackReadResult =
  | ({
      readonly ok: true;
      readonly disposition: "accepted";
      readonly schema_version: "0.1";
      readonly source_pack_root_hash: string;
      readonly findings: readonly [];
    } & CompilerPackTerminalOutcomeV01)
  | ({
      readonly ok: true;
      readonly disposition: "accepted";
      readonly schema_version: "0.2";
      readonly source_pack_root_hash: string;
      readonly findings: readonly [];
    } & CompilerPackTerminalOutcomeV02)
  | {
      readonly ok: false;
      readonly disposition: "hold";
      readonly schema_version: "0.1";
      readonly source_pack_root_hash: null;
      readonly terminal_state: null;
      readonly reason: CompilePackReadFailureReason;
      readonly findings: readonly PublicFindingV02[];
    }
  | {
      readonly ok: false;
      readonly disposition: "hold";
      readonly schema_version: "0.2" | null;
      readonly source_pack_root_hash: null;
      readonly terminal_state: null;
      readonly reason: CompilePackReadFailureReasonNonLegacy;
      readonly findings: readonly PublicFindingV02[];
    };

type ReplayFailureReasonV01 =
  | CompilePackReadFailureReason
  | "UNAVAILABLE_REPLAY_BUNDLE"
  | "INVALID_V01_REPLAY_OUTPUT";
type ReplayFailureReasonV02 = CompilePackReadFailureReasonNonLegacy | "UNAVAILABLE_REPLAY_BUNDLE";

export type ReplayResult =
  | {
      readonly ok: true;
      readonly disposition: "replayed";
      readonly schema_version: "0.1" | "0.2";
      readonly source_pack_root_hash: string;
      readonly compared_member_count: number;
      readonly reason: null;
      readonly findings: readonly [];
    }
  | {
      readonly ok: false;
      readonly disposition: "hold";
      readonly schema_version: "0.1";
      readonly source_pack_root_hash: null;
      readonly compared_member_count: 0;
      readonly reason: ReplayFailureReasonV01;
      readonly findings: readonly PublicFindingV02[];
    }
  | {
      readonly ok: false;
      readonly disposition: "hold";
      readonly schema_version: "0.2";
      readonly source_pack_root_hash: null;
      readonly compared_member_count: 0;
      readonly reason: ReplayFailureReasonV02;
      readonly findings: readonly PublicFindingV02[];
    }
  | {
      readonly ok: false;
      readonly disposition: "hold";
      readonly schema_version: null;
      readonly source_pack_root_hash: null;
      readonly compared_member_count: 0;
      readonly reason: CompilePackReadFailureReasonNonLegacy;
      readonly findings: readonly PublicFindingV02[];
    };

const EMPTY_FINDINGS = Object.freeze([]) as readonly [];

function hold(
  schemaVersion: "0.1" | "0.2" | null,
  reason: ReplayFailureReasonV01 | ReplayFailureReasonV02,
): ReplayResult {
  return Object.freeze({
    ok: false,
    disposition: "hold",
    schema_version: schemaVersion,
    source_pack_root_hash: null,
    compared_member_count: 0,
    reason,
    findings: EMPTY_FINDINGS,
  }) as ReplayResult;
}

async function abortOrHelperHold(
  session: CompilePackCaptureSessionV02,
  schemaVersion: "0.1" | "0.2" | null,
  reason: ReplayFailureReasonV01 | ReplayFailureReasonV02,
): Promise<ReplayResult> {
  const aborted = await session.abort();
  return aborted.ok ? hold(schemaVersion, reason) : hold(schemaVersion, "IO_HELPER_UNAVAILABLE");
}

function literalVersion(value: unknown):
  | { readonly ok: true; readonly schema_version: "0.1" | "0.2" }
  | {
      readonly ok: false;
      readonly reason: "MISSING_SCHEMA_VERSION" | "MALFORMED_SCHEMA_VERSION" | "UNSUPPORTED_SCHEMA_VERSION";
    } {
  if (typeof value !== "object" || value === null || Array.isArray(value) || !("schema_version" in value)) {
    return { ok: false, reason: "MISSING_SCHEMA_VERSION" };
  }
  const version = (value as { schema_version?: unknown }).schema_version;
  if (typeof version !== "string" || !/^\d+\.\d+$/.test(version)) {
    return { ok: false, reason: "MALFORMED_SCHEMA_VERSION" };
  }
  return version === "0.1" || version === "0.2"
    ? { ok: true, schema_version: version }
    : { ok: false, reason: "UNSUPPORTED_SCHEMA_VERSION" };
}

function readFailureReason(result: ReadCompilePackV01Result | ReadCompilePackV02Result): ReplayFailureReasonV01 {
  return result.ok ? "INVALID_COMPILE_PACK" : result.reason;
}

export async function replayCompilePack(
  packRoot: string,
  legacyPolicy: LegacyCompatibilityPolicy | null = null,
): Promise<ReplayResult> {
  if (typeof packRoot !== "string" || packRoot.length === 0) return hold(null, "INVALID_COMPILE_PACK");
  const opened = await openCompilePackCaptureSessionV02(packRoot);
  if (!opened.ok) return hold(null, opened.reason);
  const session = opened.value;
  const listed = await session.listDirectEntries();
  if (!listed.ok) return abortOrHelperHold(session, null, listed.reason);

  const manifestName = parseDirectChildName("pack-manifest.json");
  if (manifestName === null) return abortOrHelperHold(session, null, "IO_HELPER_UNAVAILABLE");
  const captured = await session.captureMember(manifestName);
  if (!captured.ok) return hold(null, captured.reason);
  const snapshot = session.snapshotCapturedManifest();
  if (!snapshot.ok) return abortOrHelperHold(session, null, snapshot.reason);
  const decoded = decodeStructuredDocumentV02(snapshot.value, "json");
  if (!decoded.ok) return abortOrHelperHold(session, null, decoded.reason);
  const dispatch = literalVersion(decoded.value);
  if (!dispatch.ok) return abortOrHelperHold(session, null, dispatch.reason);

  if (dispatch.schema_version === "0.1") {
    const read = await readCompilePackV01FromCapture(packRoot, session, listed.value, legacyPolicy);
    if (!read.ok) return hold("0.1", readFailureReason(read));
    const replayed = await replayCompilePackV01(read, legacyPolicy);
    if (!replayed.ok) return hold("0.1", replayed.reason);
    return Object.freeze({
      ok: true,
      disposition: "replayed",
      schema_version: "0.1",
      source_pack_root_hash: replayed.authority.source_pack_root_hash,
      compared_member_count: read.identity.members.length,
      reason: null,
      findings: EMPTY_FINDINGS,
    });
  }

  const read = await readCompilePackV02FromCapture(packRoot, session, listed.value);
  if (!read.ok) return hold("0.2", readFailureReason(read) as ReplayFailureReasonV02);
  const replayed = replayCompilePackV02(read);
  if (!replayed.ok) return hold("0.2", replayed.reason);
  return Object.freeze({
    ok: true,
    disposition: "replayed",
    schema_version: "0.2",
    source_pack_root_hash: replayed.replay.source_pack_root_hash,
    compared_member_count: replayed.replay.compared_member_count,
    reason: null,
    findings: EMPTY_FINDINGS,
  });
}

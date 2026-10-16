import {
  captureStructuredFile,
  releaseCapturedStructuredFile,
  type CapturedStructuredFile,
  type LegacyCompatibilityPolicy,
} from "./captured-file.js";
import { decodeStructuredDocumentV02 } from "../schema/decode-envelope.js";

export type LegacyPolicyFailureReason =
  | "INVALID_LEGACY_COMPATIBILITY_POLICY"
  | "LEGACY_REPLAY_RESOURCE_LIMIT"
  | "IO_HELPER_UNAVAILABLE"
  | "IO_IDENTITY_MISMATCH";

export type LegacyPolicyCommandFailure = {
  ok: false;
  reason: LegacyPolicyFailureReason;
  message: string;
};

export type LoadedLegacyPolicyResult =
  | { ok: true; policy: LegacyCompatibilityPolicy }
  | LegacyPolicyCommandFailure;

export type CapturedLegacyLedgerResult =
  | { ok: true; ledgerText: string }
  | LegacyPolicyCommandFailure;

export type LegacyPolicyCaptureIo = Readonly<{
  captureStructuredFile: typeof captureStructuredFile;
  releaseCapturedStructuredFile: typeof releaseCapturedStructuredFile;
}>;

export const LEGACY_POLICY_FAILURE_PRESENTATION = Object.freeze({
  INVALID_LEGACY_COMPATIBILITY_POLICY: {
    exit: 2,
    message: "Legacy replay policy is invalid for this command or input family.",
  },
  LEGACY_REPLAY_RESOURCE_LIMIT: {
    exit: 1,
    message: "Legacy replay exceeded its approved finite resource policy.",
  },
  IO_HELPER_UNAVAILABLE: {
    exit: 4,
    message: "Required filesystem helper is unavailable.",
  },
  IO_IDENTITY_MISMATCH: {
    exit: 4,
    message: "Filesystem identity validation failed.",
  },
} as const satisfies Record<LegacyPolicyFailureReason, { exit: 1 | 2 | 4; message: string }>);

const POLICY_KEYS = Object.freeze([
  "deadline_ms",
  "max_heap_bytes",
  "max_member_bytes",
  "max_pack_bytes",
] as const);
const PARSER_OVERHEAD_BYTES = 67_108_864;
const POLICY_FILE_CAPTURE: LegacyCompatibilityPolicy = Object.freeze({
  mode: "operator-approved-finite",
  max_member_bytes: 4_194_304,
  max_total_bytes: 16_777_216,
  max_heap_bytes: 134_217_728,
  max_elapsed_ms: 30_000,
  approved_by: "operator",
});
const DEFAULT_CAPTURE_IO: LegacyPolicyCaptureIo = Object.freeze({
  captureStructuredFile,
  releaseCapturedStructuredFile,
});

function commandFailure(reason: LegacyPolicyFailureReason): LegacyPolicyCommandFailure {
  return { ok: false, reason, message: LEGACY_POLICY_FAILURE_PRESENTATION[reason].message };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function mapCaptureFailure(reason: string, policyFile: boolean): LegacyPolicyCommandFailure {
  if (reason === "IO_HELPER_UNAVAILABLE") return commandFailure("IO_HELPER_UNAVAILABLE");
  if (reason === "IO_IDENTITY_MISMATCH" || reason === "INVALID_INPUT_FILE") {
    return commandFailure("IO_IDENTITY_MISMATCH");
  }
  if (!policyFile && (reason === "INPUT_TOO_LARGE" || reason === "LEGACY_REPLAY_RESOURCE_LIMIT")) {
    return commandFailure("LEGACY_REPLAY_RESOURCE_LIMIT");
  }
  return commandFailure("INVALID_LEGACY_COMPATIBILITY_POLICY");
}

function parsePolicyEnvelope(value: unknown): LegacyCompatibilityPolicy | null {
  if (!isRecord(value)) return null;
  const keys = Object.keys(value).sort();
  if (keys.length !== POLICY_KEYS.length || keys.some((key, index) => key !== POLICY_KEYS[index])) return null;
  const member = value.max_member_bytes;
  const total = value.max_pack_bytes;
  const heap = value.max_heap_bytes;
  const elapsed = value.deadline_ms;
  if (
    !isPositiveSafeInteger(member) ||
    !isPositiveSafeInteger(total) ||
    !isPositiveSafeInteger(heap) ||
    !isPositiveSafeInteger(elapsed) ||
    total < member ||
    member > Number.MAX_SAFE_INTEGER - PARSER_OVERHEAD_BYTES ||
    heap < member + PARSER_OVERHEAD_BYTES
  ) {
    return null;
  }
  return Object.freeze({
    mode: "operator-approved-finite",
    max_member_bytes: member,
    max_total_bytes: total,
    max_heap_bytes: heap,
    max_elapsed_ms: elapsed,
    approved_by: "operator",
  });
}

async function releaseCapture(
  capture: CapturedStructuredFile,
  io: LegacyPolicyCaptureIo,
): Promise<LegacyPolicyCommandFailure | null> {
  try {
    const released = await io.releaseCapturedStructuredFile(capture);
    return released.ok ? null : commandFailure("IO_HELPER_UNAVAILABLE");
  } catch {
    return commandFailure("IO_HELPER_UNAVAILABLE");
  }
}

async function useCapturedFile<Result>(
  capture: CapturedStructuredFile,
  io: LegacyPolicyCaptureIo,
  operation: () => Promise<Result>,
): Promise<Result | LegacyPolicyCommandFailure> {
  let outcome: Result;
  try {
    outcome = await operation();
  } catch (error: unknown) {
    const releaseFailure = await releaseCapture(capture, io);
    if (releaseFailure !== null) return releaseFailure;
    throw error;
  }
  const releaseFailure = await releaseCapture(capture, io);
  return releaseFailure ?? outcome;
}

export async function loadLegacyReplayPolicy(
  path: string,
  io: LegacyPolicyCaptureIo = DEFAULT_CAPTURE_IO,
): Promise<LoadedLegacyPolicyResult> {
  const captured = await io.captureStructuredFile(path, POLICY_FILE_CAPTURE);
  if (!captured.ok) return mapCaptureFailure(captured.reason, true);
  return useCapturedFile(captured.capture, io, async () => {
    const snapshot = await captured.capture.snapshotBytes();
    if (!snapshot.ok) return mapCaptureFailure(snapshot.reason, true);
    const decoded = decodeStructuredDocumentV02(snapshot.bytes, "json");
    if (!decoded.ok) return commandFailure("INVALID_LEGACY_COMPATIBILITY_POLICY");
    const policy = parsePolicyEnvelope(decoded.value);
    return policy === null
      ? commandFailure("INVALID_LEGACY_COMPATIBILITY_POLICY")
      : { ok: true, policy };
  });
}

export function selectV01ReceiptRunId(receiptText: string): string | null {
  try {
    const value: unknown = JSON.parse(receiptText);
    if (!isRecord(value) || value.receipt_version !== "0.1" || !isRecord(value.run)) return null;
    const runId = value.run.run_id;
    return typeof runId === "string" && runId.length > 0 ? runId : null;
  } catch {
    return null;
  }
}

export async function captureV01LedgerForReceipt(
  ledgerPath: string,
  receiptRunId: string,
  policy: LegacyCompatibilityPolicy,
  io: LegacyPolicyCaptureIo = DEFAULT_CAPTURE_IO,
): Promise<CapturedLegacyLedgerResult> {
  const captured = await io.captureStructuredFile(ledgerPath, policy);
  if (!captured.ok) return mapCaptureFailure(captured.reason, false);
  return useCapturedFile(captured.capture, io, async () => {
    const lineage = await captured.capture.selectLedgerV01Lineage(receiptRunId);
    if (!lineage.ok) {
      return lineage.reason === "LEGACY_REPLAY_RESOURCE_LIMIT" || lineage.reason === "IO_HELPER_UNAVAILABLE"
        ? mapCaptureFailure(lineage.reason, false)
        : commandFailure("INVALID_LEGACY_COMPATIBILITY_POLICY");
    }
    const parsed = await captured.capture.parseV01("ledger-jsonl");
    if (!parsed.ok && (parsed.reason === "LEGACY_REPLAY_RESOURCE_LIMIT" || parsed.reason === "IO_HELPER_UNAVAILABLE")) {
      return mapCaptureFailure(parsed.reason, false);
    }
    const snapshot = await captured.capture.snapshotBytes();
    if (!snapshot.ok) return mapCaptureFailure(snapshot.reason, false);
    try {
      return { ok: true, ledgerText: new TextDecoder("utf-8", { fatal: true }).decode(snapshot.bytes) };
    } catch {
      return commandFailure("IO_HELPER_UNAVAILABLE");
    }
  });
}

export function invalidLegacyPolicyUse(): LegacyPolicyCommandFailure {
  return commandFailure("INVALID_LEGACY_COMPATIBILITY_POLICY");
}

import { releaseCapturedStructuredFile, parseDirectChildName } from "../io/captured-file.js";
import { openAnchoredReadSession, type AnchoredReadSession } from "../io/output-capabilities.js";
import { decodeStructuredDocumentV02 } from "../schema/decode-envelope.js";
import { ResolvedRunPlanV02, type ResolvedRunPlanV02Value } from "../schema/runtime.js";
import { classifyV02PlannedDirectory } from "./planned-directory-classifier.js";

const CORE_NAMES = [
  "work-item.json",
  "binding-input.json",
  "intake-record.json",
  "catalog-resolution.json",
  "compilation-record.json",
  "compile-pack-manifest.json",
  "generated.loop.yaml",
  "intake-brief.json",
  "resolved-run-plan.json",
] as const;

const MAX_MEMBER_BYTES = 4_194_304;
const MAX_TOTAL_BYTES = 33_554_432;

export type CapturedPlannedRunV02 = Readonly<{
  run_id: string;
  readonly __captured_planned_run_v02: unique symbol;
}>;

export type CapturePlannedRunV02Result =
  | { ok: true; captured: CapturedPlannedRunV02 }
  | {
      ok: false;
      reason:
        | "NOT_V02_PLANNED_RUN"
        | "INVALID_V02_PLAN"
        | "V02_RUN_LAYOUT_CONTAMINATED"
        | "INPUT_TOO_LARGE"
        | "INVALID_INPUT_ROOT"
        | "IO_HELPER_UNAVAILABLE"
        | "IO_IDENTITY_MISMATCH";
      message: string;
    };

export type CapturedPlannedRunV02Value = Readonly<{
  plan: ResolvedRunPlanV02Value;
  member_bytes: ReadonlyMap<(typeof CORE_NAMES)[number], Uint8Array>;
}>;

const capturedRegistry = new WeakMap<CapturedPlannedRunV02, CapturedPlannedRunV02Value>();

function failure(reason: CapturePlannedRunV02Result extends infer _T ? Exclude<CapturePlannedRunV02Result, { ok: true }>["reason"] : never, message: string): CapturePlannedRunV02Result {
  return { ok: false, reason, message };
}

function mapCaptureFailure(reason: string): CapturePlannedRunV02Result {
  if (reason === "INPUT_TOO_LARGE") return failure("INPUT_TOO_LARGE", "A planned-run member exceeds its byte limit.");
  if (reason === "IO_IDENTITY_MISMATCH") return failure("IO_IDENTITY_MISMATCH", "The planned-run directory identity changed.");
  if (reason === "INVALID_INPUT_ROOT" || reason === "INVALID_INPUT_FILE") return failure("INVALID_INPUT_ROOT", "The planned-run input root or member is invalid.");
  return failure("IO_HELPER_UNAVAILABLE", "The planned-run capture helper is unavailable.");
}

async function snapshotMember(
  session: AnchoredReadSession,
  name: (typeof CORE_NAMES)[number],
  remaining: number,
): Promise<{ ok: true; bytes: Uint8Array } | { ok: false; result: CapturePlannedRunV02Result }> {
  const directName = parseDirectChildName(name);
  if (directName === null) return { ok: false, result: failure("IO_HELPER_UNAVAILABLE", "A fixed planned-run member name is invalid.") };
  const captured = await session.captureFile(directName, Math.min(MAX_MEMBER_BYTES, remaining), remaining);
  if (!captured.ok) return { ok: false, result: mapCaptureFailure(captured.reason) };
  let result: { ok: true; bytes: Uint8Array } | { ok: false; result: CapturePlannedRunV02Result };
  try {
    const snapshot = await captured.capture.snapshotBytes();
    result = snapshot.ok
      ? { ok: true, bytes: snapshot.bytes }
      : { ok: false, result: mapCaptureFailure(snapshot.reason) };
  } catch {
    result = { ok: false, result: failure("IO_HELPER_UNAVAILABLE", "The planned-run capture helper failed.") };
  }
  const released = await releaseCapturedStructuredFile(captured.capture);
  return released.ok ? result : { ok: false, result: failure("IO_HELPER_UNAVAILABLE", released.message) };
}

async function captureFromSession(
  session: AnchoredReadSession,
  reportWriterLayoutPrevalidated = false,
): Promise<CapturePlannedRunV02Result> {
    const planName = parseDirectChildName("resolved-run-plan.json");
    if (planName === null) return failure("IO_HELPER_UNAVAILABLE", "The fixed plan member name is invalid.");
    const planCapture = await session.captureFile(planName, MAX_MEMBER_BYTES, MAX_TOTAL_BYTES);
    if (!planCapture.ok) return mapCaptureFailure(planCapture.reason);
    let planBytes: Uint8Array;
    let planResult: CapturePlannedRunV02Result | null = null;
    try {
      const selected = await planCapture.capture.selectFamily("resolved-run-plan");
      if (!selected.ok) planResult = mapCaptureFailure(selected.reason);
      else if (selected.schema_version !== "0.2") {
        planResult = failure("NOT_V02_PLANNED_RUN", "The resolved plan belongs to another schema family.");
      }
      if (planResult === null) {
        const listed = await session.listDirectEntries();
        if (!listed.ok) planResult = mapCaptureFailure(listed.reason);
        else {
          const classification = classifyV02PlannedDirectory(listed.entries);
          if (!classification.ok && !reportWriterLayoutPrevalidated) {
            planResult = failure("V02_RUN_LAYOUT_CONTAMINATED", "The V02 planned-run directory contains an invalid entry set.");
          }
        }
      }
      if (planResult === null) {
        const snapshot = await planCapture.capture.snapshotBytes();
        if (!snapshot.ok) planResult = mapCaptureFailure(snapshot.reason);
        else planBytes = snapshot.bytes;
      }
    } catch {
      planResult = failure("IO_HELPER_UNAVAILABLE", "The planned-run capture helper failed.");
    }
    const released = await releaseCapturedStructuredFile(planCapture.capture);
    if (!released.ok) return failure("IO_HELPER_UNAVAILABLE", released.message);
    if (planResult !== null) return planResult;

    const decoded = decodeStructuredDocumentV02(planBytes!, "json");
    if (!decoded.ok) return failure("INVALID_V02_PLAN", "The resolved V02 plan is not valid strict JSON.");
    const parsed = ResolvedRunPlanV02.safeParse(decoded.value);
    if (!parsed.success) return failure("INVALID_V02_PLAN", "The resolved V02 plan does not satisfy the runtime contract.");

    const members = new Map<(typeof CORE_NAMES)[number], Uint8Array>();
    members.set("resolved-run-plan.json", new Uint8Array(planBytes!));
    let remaining = MAX_TOTAL_BYTES - planBytes!.byteLength;
    for (const name of CORE_NAMES) {
      if (name === "resolved-run-plan.json") continue;
      const snapshot = await snapshotMember(session, name, remaining);
      if (!snapshot.ok) return snapshot.result;
      remaining -= snapshot.bytes.byteLength;
      members.set(name, new Uint8Array(snapshot.bytes));
    }
    const captured = Object.freeze({ run_id: parsed.data.run_id }) as CapturedPlannedRunV02;
    capturedRegistry.set(captured, {
      plan: structuredClone(parsed.data),
      member_bytes: new Map([...members].map(([name, bytes]) => [name, new Uint8Array(bytes)])),
    });
    return { ok: true, captured };
}

function isReportWriterCaptureLayout(entries: readonly { name: string; kind: string }[]): boolean {
  const seen = new Set<string>();
  const core = new Set<string>(CORE_NAMES);
  const reports = new Set(["plan-report.md", "plan-report.html", "plan-report-input.json"]);
  let lockCount = 0;
  let tempCount = 0;
  for (const entry of entries) {
    if (entry.kind !== "regular-file" || seen.has(entry.name)) return false;
    seen.add(entry.name);
    if (core.has(entry.name) || reports.has(entry.name)) continue;
    if (entry.name === "plan-report.lock") { lockCount += 1; continue; }
    if (/^plan-report\.(?:md|html|input\.json)\.[0-9a-f]{32}\.tmp$/u.test(entry.name)) { tempCount += 1; continue; }
    return false;
  }
  return CORE_NAMES.every((name) => seen.has(name)) && lockCount <= 1 && tempCount <= 3;
}

async function captureFromSessionForReportWriter(session: AnchoredReadSession): Promise<CapturePlannedRunV02Result> {
  const listed = await session.listDirectEntries();
  if (!listed.ok) return mapCaptureFailure(listed.reason);
  if (!isReportWriterCaptureLayout(listed.entries)) {
    return failure("V02_RUN_LAYOUT_CONTAMINATED", "The V02 report-writer capture layout is invalid.");
  }
  return captureFromSession(session, true);
}

export async function capturePlannedRunV02(
  rootPath: string,
  mode: "ordinary" | "report-writer" = "ordinary",
): Promise<CapturePlannedRunV02Result> {
  const opened = await openAnchoredReadSession(rootPath);
  if (!opened.ok) return mapCaptureFailure(opened.reason);
  const result = mode === "report-writer"
    ? await captureFromSessionForReportWriter(opened.session)
    : await captureFromSession(opened.session);
  const closed = await opened.session.close();
  return result.ok && !closed.ok ? failure("IO_HELPER_UNAVAILABLE", closed.message) : result;
}

export function consumeCapturedPlannedRunV02(captured: CapturedPlannedRunV02): CapturedPlannedRunV02Value | null {
  const value = capturedRegistry.get(captured);
  if (value === undefined) return null;
  capturedRegistry.delete(captured);
  return {
    plan: structuredClone(value.plan),
    member_bytes: new Map([...value.member_bytes].map(([name, bytes]) => [name, new Uint8Array(bytes)])),
  };
}

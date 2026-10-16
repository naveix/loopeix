import { hashRawBytes } from "../hash.js";
import { parseDirectChildName, releaseCapturedStructuredFile } from "../io/captured-file.js";
import { openAnchoredReadSession, type AnchoredReadSession } from "../io/output-capabilities.js";
import { decodeStructuredDocumentV02 } from "../schema/decode-envelope.js";
import {
  classifyV02PlannedDirectory,
  type CapturedDirectEntry,
} from "../run/planned-directory-classifier.js";
import {
  parsePlanReportInputV02,
  type PlanReportInputV02,
} from "./plan-input.js";

export type PlanReportGenerationBytesV02 = {
  readonly plan_report_input: Uint8Array;
  readonly markdown: Uint8Array;
  readonly html: Uint8Array;
  readonly resolved_plan: Uint8Array;
  readonly compile_manifest: Uint8Array;
  readonly generated_loop: Uint8Array;
};

export type PlanReportGenerationValidationV02 =
  | { ok: true; input: PlanReportInputV02 }
  | {
      ok: false;
      reason: "PLAN_REPORT_GENERATION_INVALID";
      message: "Planned report generation is incomplete or invalid.";
    };

export type PlanReportOpenDecisionV02 =
  | { ok: true; input: PlanReportInputV02 }
  | {
      ok: false;
      reason: "PLAN_REPORT_NOT_BUILT" | "V02_RUN_LAYOUT_CONTAMINATED" | "PLAN_REPORT_GENERATION_INVALID";
      message:
        | "The planned report has not been built."
        | "The planned V02 run directory layout is contaminated."
        | "Planned report generation is incomplete or invalid.";
    };

export type CapturedPlanReportOpenDecisionV02 = PlanReportOpenDecisionV02 | {
  ok: false;
  reason: "NOT_V02_PLANNED_RUN" | "IO_HELPER_UNAVAILABLE" | "IO_IDENTITY_MISMATCH";
  message: string;
};

const OPEN_MEMBER_NAMES = [
  "resolved-run-plan.json",
  "compile-pack-manifest.json",
  "generated.loop.yaml",
  "plan-report-input.json",
  "plan-report.md",
  "plan-report.html",
] as const;
const MAX_OPEN_MEMBER_BYTES = 4_194_304;
const MAX_OPEN_TOTAL_BYTES = 25_165_824;

const INVALID_GENERATION = {
  ok: false,
  reason: "PLAN_REPORT_GENERATION_INVALID",
  message: "Planned report generation is incomplete or invalid.",
} as const;

function decodeUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function occursExactlyOnce(text: string, literal: string): boolean {
  const first = text.indexOf(literal);
  return first >= 0 && text.indexOf(literal, first + literal.length) < 0;
}

export function validatePlanReportGenerationV02(
  bytes: PlanReportGenerationBytesV02,
): PlanReportGenerationValidationV02 {
  try {
    const decodedInput = decodeStructuredDocumentV02(bytes.plan_report_input, "json");
    if (!decodedInput.ok) return INVALID_GENERATION;
    const parsed = parsePlanReportInputV02(decodedInput.value);
    if (!parsed.ok) return INVALID_GENERATION;
    const input = parsed.input;
    if (
      hashRawBytes(bytes.resolved_plan) !== input.resolved_run_plan_hash ||
      hashRawBytes(bytes.compile_manifest) !== input.compile_pack_manifest_hash ||
      hashRawBytes(bytes.generated_loop) !== input.generated_loop_hash ||
      hashRawBytes(bytes.markdown) !== input.markdown_hash ||
      hashRawBytes(bytes.html) !== input.html_hash
    ) return INVALID_GENERATION;

    const markdown = decodeUtf8(bytes.markdown);
    const html = decodeUtf8(bytes.html);
    if (markdown === null || html === null) return INVALID_GENERATION;
    const markdownMarker = `<!-- loopeix-plan-report-v0.1 generation=${input.generation_id} source=${input.resolved_run_plan_hash} -->`;
    if (markdown.split("\n", 1)[0] !== markdownMarker || !occursExactlyOnce(markdown, markdownMarker)) {
      return INVALID_GENERATION;
    }
    const htmlMarkers = [
      '<meta name="loopeix-plan-report-version" content="0.1">',
      `<meta name="loopeix-generation-id" content="${input.generation_id}">`,
      `<meta name="loopeix-source-plan-hash" content="${input.resolved_run_plan_hash}">`,
    ];
    if (htmlMarkers.some((marker) => !occursExactlyOnce(html, marker))) return INVALID_GENERATION;
    if ((html.match(/<meta name="loopeix-(?:plan-report-version|generation-id|source-plan-hash)"/gu) ?? []).length !== 3) {
      return INVALID_GENERATION;
    }
    return { ok: true, input };
  } catch {
    return INVALID_GENERATION;
  }
}

export function decidePlanReportOpenV02(
  entries: readonly CapturedDirectEntry[],
  bytes: PlanReportGenerationBytesV02 | null,
): PlanReportOpenDecisionV02 {
  const classified = classifyV02PlannedDirectory(entries);
  if (!classified.ok) {
    return {
      ok: false,
      reason: "V02_RUN_LAYOUT_CONTAMINATED",
      message: "The planned V02 run directory layout is contaminated.",
    };
  }
  if (classified.layout === "core-only") {
    return {
      ok: false,
      reason: "PLAN_REPORT_NOT_BUILT",
      message: "The planned report has not been built.",
    };
  }
  if (bytes === null) return INVALID_GENERATION;
  return validatePlanReportGenerationV02(bytes);
}

async function captureOpenMember(
  session: AnchoredReadSession,
  name: (typeof OPEN_MEMBER_NAMES)[number],
  remaining: number,
): Promise<{ ok: true; bytes: Uint8Array } | { ok: false; reason: "IO_HELPER_UNAVAILABLE" | "IO_IDENTITY_MISMATCH"; message: string }> {
  const directName = parseDirectChildName(name);
  if (directName === null) return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "A fixed report member name is invalid." };
  const captured = await session.captureFile(directName, Math.min(MAX_OPEN_MEMBER_BYTES, remaining), remaining);
  if (!captured.ok) {
    return {
      ok: false,
      reason: captured.reason === "IO_IDENTITY_MISMATCH" ? "IO_IDENTITY_MISMATCH" : "IO_HELPER_UNAVAILABLE",
      message: captured.message,
    };
  }
  const snapshot = await captured.capture.snapshotBytes();
  const released = await releaseCapturedStructuredFile(captured.capture);
  if (!released.ok) return released;
  return snapshot.ok ? { ok: true, bytes: snapshot.bytes } : { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: snapshot.message };
}

export async function capturePlanReportOpenDecisionV02(
  runDirectory: string,
): Promise<CapturedPlanReportOpenDecisionV02> {
  const opened = await openAnchoredReadSession(runDirectory);
  if (!opened.ok) return {
    ok: false,
    reason: opened.reason === "IO_IDENTITY_MISMATCH" ? "IO_IDENTITY_MISMATCH" : "IO_HELPER_UNAVAILABLE",
    message: opened.message,
  };
  const { session } = opened;
  let result: CapturedPlanReportOpenDecisionV02;
  try {
    const listed = await session.listDirectEntries();
    if (!listed.ok) result = { ok: false, reason: listed.reason === "IO_IDENTITY_MISMATCH" ? listed.reason : "IO_HELPER_UNAVAILABLE", message: listed.message };
    else {
      const planName = parseDirectChildName("resolved-run-plan.json");
      if (planName === null) result = { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "The fixed plan member name is invalid." };
      else {
        const planCapture = await session.captureFile(planName, MAX_OPEN_MEMBER_BYTES, MAX_OPEN_TOTAL_BYTES);
        if (!planCapture.ok) result = { ok: false, reason: planCapture.reason === "IO_IDENTITY_MISMATCH" ? "IO_IDENTITY_MISMATCH" : "IO_HELPER_UNAVAILABLE", message: planCapture.message };
        else {
          const family = await planCapture.capture.selectFamily("resolved-run-plan");
          const snapshot = await planCapture.capture.snapshotBytes();
          const released = await releaseCapturedStructuredFile(planCapture.capture);
          if (!released.ok) result = { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: released.message };
          else if (!snapshot.ok) result = { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: snapshot.message };
          else if (!family.ok) result = { ok: false, reason: "PLAN_REPORT_GENERATION_INVALID", message: "Planned report generation is incomplete or invalid." };
          else if (family.schema_version !== "0.2") result = { ok: false, reason: "NOT_V02_PLANNED_RUN", message: "The resolved plan belongs to another schema family." };
          else {
            const classification = classifyV02PlannedDirectory(listed.entries);
            if (!classification.ok) result = { ok: false, reason: "V02_RUN_LAYOUT_CONTAMINATED", message: "The planned V02 run directory layout is contaminated." };
            else if (classification.layout === "core-only") result = { ok: false, reason: "PLAN_REPORT_NOT_BUILT", message: "The planned report has not been built." };
            else {
              const bytes = new Map<string, Uint8Array>([["resolved-run-plan.json", snapshot.bytes]]);
              let remaining = MAX_OPEN_TOTAL_BYTES - snapshot.bytes.byteLength;
              for (const name of OPEN_MEMBER_NAMES) {
                if (name === "resolved-run-plan.json") continue;
                const member = await captureOpenMember(session, name, remaining);
                if (!member.ok) { result = member; break; }
                bytes.set(name, member.bytes);
                remaining -= member.bytes.byteLength;
              }
              if (bytes.size === OPEN_MEMBER_NAMES.length) {
                result = decidePlanReportOpenV02(listed.entries, {
                  resolved_plan: bytes.get("resolved-run-plan.json")!,
                  compile_manifest: bytes.get("compile-pack-manifest.json")!,
                  generated_loop: bytes.get("generated.loop.yaml")!,
                  plan_report_input: bytes.get("plan-report-input.json")!,
                  markdown: bytes.get("plan-report.md")!,
                  html: bytes.get("plan-report.html")!,
                });
              }
            }
          }
        }
      }
    }
  } catch {
    result = { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "The planned report could not be captured safely." };
  }
  const closed = await session.close();
  return result!.ok && !closed.ok ? { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: closed.message } : result!;
}

import { lstat, open } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { canonicalize, hashRawBytes } from "../hash.js";
import {
  anchorDestinationRootV02,
  captureOutputBytes,
  confirmV02ReportProjection,
  createV02PlanReportWriteAuthority,
  issueV02DestinationCapability,
  openAnchoredWriteSession,
  openV02OutputAdmissionSession,
  parseDirectChildName,
  scanAndAdmitOutputBytes,
  sealV02OutputAdmissionSession,
} from "../io/output-capabilities.js";
import {
  capturePlannedRunV02,
  consumeCapturedPlannedRunV02,
} from "../run/capture-planned-v02.js";
import { presentPlannedRunV02 } from "../run/present-planned-v02.js";
import { derivePlanReportGenerationIdV02 } from "./plan-input.js";
import { renderPlanReportV02 } from "./plan-renderer.js";

const MEMBER_ORDER = ["plan-report.md", "plan-report.html", "plan-report-input.json"] as const;

export type BuildPlanReportV02Result =
  | {
      ok: true;
      reason: null;
      run_id: string;
      generation_id: string;
      members: typeof MEMBER_ORDER;
    }
  | {
      ok: false;
      reason:
        | "NOT_V02_PLANNED_RUN"
        | "INVALID_RESOLVED_RUN_PLAN_DOCUMENT"
        | "V02_RUN_LAYOUT_CONTAMINATED"
        | "INVALID_OUTPUT_CAPTURE"
        | "SENSITIVE_OUTPUT_REJECTED"
        | "OUTPUT_SCAN_FAILED"
        | "OUTPUT_HASH_FAILED"
        | "OUTPUT_CAPTURE_FAILED"
        | "COMPILED_OUTPUT_TOO_LARGE"
        | "PLAN_REPORT_RENDERER_INVALID"
        | "DESTINATION_EXISTS"
        | "REPORT_BUILD_BUSY"
        | "REPORT_BUILD_STALE_LOCK"
        | "IO_HELPER_UNAVAILABLE"
        | "IO_IDENTITY_MISMATCH"
        | "IO_DURABILITY_UNCONFIRMED";
      message: string;
    };

type RendererBundle = Readonly<{
  renderer_bundle_id: string;
  renderer_bundle_hash: string;
}>;

type RendererBundleFile = RendererBundle & Readonly<{
  purpose: "plan-report-renderer-bundle-v02";
  members: readonly Readonly<{ path: string; hash: string }>[];
}>;

function failure(reason: Exclude<BuildPlanReportV02Result, { ok: true }>["reason"], message: string): BuildPlanReportV02Result {
  return { ok: false, reason, message };
}

async function readStableRegularFile(path: string): Promise<Uint8Array | null> {
  try {
    const before = await lstat(path, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink()) return null;
    const handle = await open(path, "r");
    try {
      const openedBefore = await handle.stat({ bigint: true });
      if (!openedBefore.isFile() || openedBefore.dev !== before.dev || openedBefore.ino !== before.ino) return null;
      const bytes = await handle.readFile();
      const openedAfter = await handle.stat({ bigint: true });
      if (openedAfter.dev !== openedBefore.dev || openedAfter.ino !== openedBefore.ino
        || openedAfter.size !== openedBefore.size || openedAfter.mtimeNs !== openedBefore.mtimeNs
        || BigInt(bytes.byteLength) !== openedBefore.size) return null;
      return new Uint8Array(bytes);
    } finally {
      await handle.close();
    }
  } catch {
    return null;
  }
}

async function loadRendererBundle(): Promise<RendererBundle | null> {
  const currentDirectory = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(currentDirectory, "plan-renderer-bundle.json"),
    join(currentDirectory, "..", "..", "dist", "report", "plan-renderer-bundle.json"),
  ];
  for (const path of candidates) {
    try {
      const bundleBytes = await readStableRegularFile(path);
      if (bundleBytes === null) continue;
      const decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bundleBytes)) as RendererBundleFile;
      if (
        Object.keys(decoded).sort().join("|") === "members|purpose|renderer_bundle_hash|renderer_bundle_id" &&
        decoded.purpose === "plan-report-renderer-bundle-v02" &&
        typeof decoded.renderer_bundle_id === "string" && /^renderer_[a-f0-9]{32}$/.test(decoded.renderer_bundle_id) &&
        typeof decoded.renderer_bundle_hash === "string" && /^sha256:[a-f0-9]{64}$/.test(decoded.renderer_bundle_hash) &&
        Array.isArray(decoded.members) && decoded.members.length === 2
      ) {
        const packageRoot = join(dirname(path), "..", "..");
        const expectedPaths = ["dist/report/plan-escaping.js", "dist/report/plan-renderer.js"];
        const actualPaths = decoded.members.map((member) => member.path);
        if (actualPaths.join("|") !== expectedPaths.join("|")) continue;
        let membersValid = true;
        for (const member of decoded.members) {
          const bytes = await readStableRegularFile(join(packageRoot, member.path));
          if (bytes === null || hashRawBytes(bytes) !== member.hash) membersValid = false;
        }
        const inventoryHash = hashRawBytes(new TextEncoder().encode(canonicalize({
          purpose: decoded.purpose,
          members: decoded.members,
        })));
        if (!membersValid || inventoryHash !== decoded.renderer_bundle_hash) continue;
        if (decoded.renderer_bundle_id !== `renderer_${inventoryHash.slice("sha256:".length, "sha256:".length + 32)}`) continue;
        return { renderer_bundle_id: decoded.renderer_bundle_id, renderer_bundle_hash: decoded.renderer_bundle_hash };
      }
    } catch {
      continue;
    }
  }
  return null;
}

function mapCaptureFailure(reason: string, message: string): BuildPlanReportV02Result {
  if (reason === "NOT_V02_PLANNED_RUN") return failure("NOT_V02_PLANNED_RUN", message);
  if (reason === "V02_RUN_LAYOUT_CONTAMINATED") return failure("V02_RUN_LAYOUT_CONTAMINATED", message);
  if (reason === "INVALID_V02_PLAN") return failure("INVALID_RESOLVED_RUN_PLAN_DOCUMENT", message);
  if (reason === "IO_IDENTITY_MISMATCH") return failure("IO_IDENTITY_MISMATCH", message);
  return failure("IO_HELPER_UNAVAILABLE", message);
}

function mapWriterFailure(
  reason:
    | "INVALID_INPUT_ROOT"
    | "INVALID_INPUT_FILE"
    | "INPUT_TOO_LARGE"
    | "DESTINATION_EXISTS"
    | "INVALID_OUTPUT_CAPTURE"
    | "OUTPUT_CAPTURE_FAILED"
    | "IO_HELPER_UNAVAILABLE"
    | "IO_IDENTITY_MISMATCH"
    | "IO_DURABILITY_UNCONFIRMED"
    | "REPORT_BUILD_BUSY"
    | "REPORT_BUILD_STALE_LOCK",
  message: string,
): BuildPlanReportV02Result {
  switch (reason) {
    case "INVALID_INPUT_ROOT":
    case "INVALID_INPUT_FILE":
      return failure("IO_IDENTITY_MISMATCH", message);
    case "INPUT_TOO_LARGE":
      return failure("COMPILED_OUTPUT_TOO_LARGE", message);
    case "DESTINATION_EXISTS":
    case "INVALID_OUTPUT_CAPTURE":
    case "OUTPUT_CAPTURE_FAILED":
    case "IO_HELPER_UNAVAILABLE":
    case "IO_IDENTITY_MISMATCH":
    case "IO_DURABILITY_UNCONFIRMED":
    case "REPORT_BUILD_BUSY":
    case "REPORT_BUILD_STALE_LOCK":
      return failure(reason, message);
  }
}

async function buildPlanReportV02WithBundle(
  runDirectory: string,
  suppliedRendererBundle: RendererBundle | null | undefined,
): Promise<BuildPlanReportV02Result> {
  const captured = await capturePlannedRunV02(runDirectory, "report-writer");
  if (!captured.ok) return mapCaptureFailure(captured.reason, captured.message);
  const value = consumeCapturedPlannedRunV02(captured.captured);
  if (value === null) return failure("INVALID_RESOLVED_RUN_PLAN_DOCUMENT", "The captured V02 planned run could not be consumed safely.");
  const rendererBundle = suppliedRendererBundle === undefined
    ? await loadRendererBundle()
    : suppliedRendererBundle;
  if (rendererBundle === null) return failure("PLAN_REPORT_RENDERER_INVALID", "Installed plan report renderer failed integrity validation.");

  const planBytes = value.member_bytes.get("resolved-run-plan.json");
  const manifestBytes = value.member_bytes.get("compile-pack-manifest.json");
  const generatedBytes = value.member_bytes.get("generated.loop.yaml");
  if (planBytes === undefined || manifestBytes === undefined || generatedBytes === undefined) {
    return failure("INVALID_RESOLVED_RUN_PLAN_DOCUMENT", "The V02 planned-run lineage members are incomplete.");
  }
  const lineage = {
    schema_version: "0.2" as const,
    report_projection_version: "0.1" as const,
    run_id: value.plan.run_id,
    resolved_run_plan_hash: hashRawBytes(planBytes),
    compile_pack_manifest_hash: hashRawBytes(manifestBytes),
    generated_loop_hash: hashRawBytes(generatedBytes),
    ...rendererBundle,
  };
  if (lineage.compile_pack_manifest_hash !== value.plan.compile_pack_manifest_hash) {
    return failure("INVALID_RESOLVED_RUN_PLAN_DOCUMENT", "The copied compile manifest does not match the resolved-plan lineage.");
  }
  const generationId = derivePlanReportGenerationIdV02(lineage);
  const rendered = renderPlanReportV02({
    generation_id: generationId,
    resolved_run_plan_hash: lineage.resolved_run_plan_hash,
    run_id: value.plan.run_id,
    execution_profile: "bounded-v02",
    controls: presentPlannedRunV02(value.plan).controls,
  });
  const markdownBytes = new TextEncoder().encode(rendered.markdown);
  const htmlBytes = new TextEncoder().encode(rendered.html);
  const inputBytes = new TextEncoder().encode(`${canonicalize({
    ...lineage,
    generation_id: generationId,
    markdown_hash: hashRawBytes(markdownBytes),
    html_hash: hashRawBytes(htmlBytes),
    state: "planned",
    reason: "UNSUPPORTED_EXECUTION_PROFILE",
  })}\n`);

  const confirmed = confirmV02ReportProjection({
    kind: "report",
    schema_version: "0.2",
    run_id: lineage.run_id,
    resolved_run_plan_hash: lineage.resolved_run_plan_hash,
    renderer_bundle_id: lineage.renderer_bundle_id,
    renderer_bundle_hash: lineage.renderer_bundle_hash,
    generation_id: generationId,
    output_budget_bytes: 33_554_432,
    compile_pack_manifest_hash: lineage.compile_pack_manifest_hash,
    generated_loop_hash: lineage.generated_loop_hash,
  });
  if (!confirmed.ok) return failure("INVALID_OUTPUT_CAPTURE", confirmed.message);
  const session = openV02OutputAdmissionSession(confirmed.projection, "plan-report");
  if (!session.ok) return failure("INVALID_OUTPUT_CAPTURE", session.message);
  const bytesByName = new Map<string, Uint8Array>([
    ["plan-report.md", markdownBytes],
    ["plan-report.html", htmlBytes],
    ["plan-report-input.json", inputBytes],
  ]);
  for (const name of MEMBER_ORDER) {
    const directName = parseDirectChildName(name);
    if (directName === null) return failure("INVALID_OUTPUT_CAPTURE", "A fixed report member name is invalid.");
    const output = captureOutputBytes(session.session, directName, bytesByName.get(name)!);
    if (!output.ok) {
      const reason = output.reason === "INVALID_OUTPUT_BYTE_VIEW" ? "INVALID_OUTPUT_CAPTURE" : output.reason;
      return failure(reason, output.message);
    }
    const admitted = scanAndAdmitOutputBytes(output.capture);
    if (!admitted.ok) {
      return failure(admitted.reason, "Generated plan report output could not be admitted safely.");
    }
  }
  const sealed = sealV02OutputAdmissionSession(session.session);
  if (!sealed.ok) return failure("INVALID_OUTPUT_CAPTURE", sealed.message);
  const anchored = await anchorDestinationRootV02(runDirectory, "run-directory");
  if (!anchored.ok) return failure(anchored.reason === "INVALID_INPUT_ROOT" ? "IO_IDENTITY_MISMATCH" : anchored.reason, anchored.message);
  const authority = createV02PlanReportWriteAuthority(confirmed.projection, anchored.root, sealed.output_set);
  if (!authority.ok) return failure("INVALID_OUTPUT_CAPTURE", authority.message);
  const capability = await issueV02DestinationCapability(authority.authority);
  if (!capability.ok) return failure(capability.reason === "INVALID_INPUT_ROOT" ? "IO_IDENTITY_MISMATCH" : capability.reason, capability.message);
  const opened = await openAnchoredWriteSession(runDirectory, capability.capability);
  if (!opened.ok) return failure(opened.reason === "INVALID_INPUT_ROOT" ? "IO_IDENTITY_MISMATCH" : opened.reason, opened.message);
  try {
    const written = await opened.session.replacePlanReportProjectionSet({ generation_id: generationId });
    if (!written.ok) return mapWriterFailure(written.reason, written.message);
  } finally {
    await opened.session.close();
  }
  return { ok: true, reason: null, run_id: value.plan.run_id, generation_id: generationId, members: MEMBER_ORDER };
}

export async function buildPlanReportV02(runDirectory: string): Promise<BuildPlanReportV02Result> {
  return buildPlanReportV02WithBundle(runDirectory, undefined);
}

export async function buildPlanReportV02ForTest(
  runDirectory: string,
  rendererBundle: RendererBundle | null,
): Promise<BuildPlanReportV02Result> {
  return buildPlanReportV02WithBundle(runDirectory, rendererBundle);
}

import { realpath } from "node:fs/promises";
import { join, resolve } from "node:path";

import { RunManifestV04, inspectRunManifestV04, type ValidatedRunManifestV04 } from "./runtime-manifest-v04.js";
import { inspectRuntimePlanV03, type ValidatedRuntimePlanV03 } from "./project-plan-v03.js";
import { inspectRuntimeLedgerV04, type ValidatedRuntimeLedgerV04 } from "./runtime-ledger-v04.js";
import { inspectRuntimeSummaryV04, type InspectedSummaryArtifactV01 } from "./runtime-summary-v04.js";
import {
  captureRunFileForRuntimeInspectionV02,
  issueAnchoredRunDirectoryReadCapabilityV02,
  type AnchoredRunDirectoryReadCapabilityV02,
  type RuntimeRunFileCaptureErrorV02,
} from "../io/runtime-file-capture-v02.js";

const UTF8 = new TextDecoder("utf-8", { fatal: true });
const MAX_LEDGER_BYTES = 67_108_864;
const MAX_PLAN_BYTES = 4_194_304;
const MAX_MANIFEST_BYTES = 16_777_216;

type OwnerStatusV04 =
  | Readonly<{ status: "absent"; evidence_refs: [] }>
  | Readonly<{
      status: "ambiguous";
      ambiguous_reason: "stale-owner-proof-missing";
      owner_lease_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
      evidence_refs: readonly Readonly<{ ledger_sequence: number; event_hash: string }>[];
    }>;

export type InspectedRuntimeDirectoryV04 = Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  owner_status: OwnerStatusV04;
  summary: InspectedSummaryArtifactV01 | null;
}>;

export type InspectRuntimeDirectoryV04Result =
  | Readonly<{ ok: true; inspected: InspectedRuntimeDirectoryV04 }>
  | Readonly<{ ok: false; reason: "RUNTIME_V04_NOT_PRESENT" | "RUNTIME_V04_INVALID"; message: string }>;

type ManifestInventoryRow = Readonly<{
  path: string;
  family: "primary" | "record" | "projection";
  required: boolean;
  exists: boolean;
  mode: 384 | null;
  size_bytes: number | null;
}>;

function failure(
  reason: "RUNTIME_V04_NOT_PRESENT" | "RUNTIME_V04_INVALID",
  message: string,
): InspectRuntimeDirectoryV04Result {
  return Object.freeze({ ok: false, reason, message });
}

function mapCaptureFailure(
  relativePath: string,
  error: RuntimeRunFileCaptureErrorV02,
): Readonly<{ ok: false; reason: "RUNTIME_V04_NOT_PRESENT" | "RUNTIME_V04_INVALID"; message: string }> {
  switch (error) {
    case "RUNTIME_FILE_NOT_FOUND":
      return Object.freeze({ ok: false, reason: "RUNTIME_V04_INVALID", message: `The V04 runtime file is missing: ${relativePath}` });
    case "RUNTIME_FILE_PATH_INVALID":
      return Object.freeze({ ok: false, reason: "RUNTIME_V04_INVALID", message: `The V04 runtime file path is invalid: ${relativePath}` });
    case "RUNTIME_FILE_NOT_REGULAR":
      return Object.freeze({ ok: false, reason: "RUNTIME_V04_INVALID", message: `The V04 runtime file is not a regular file: ${relativePath}` });
    case "RUNTIME_FILE_MODE_INVALID":
      return Object.freeze({ ok: false, reason: "RUNTIME_V04_INVALID", message: `The V04 runtime file must be 0600 or legacy 0644 for inspection: ${relativePath}` });
    case "RUNTIME_FILE_IDENTITY_CHANGED":
      return Object.freeze({ ok: false, reason: "RUNTIME_V04_INVALID", message: `The V04 runtime file changed while being inspected: ${relativePath}` });
    case "RUNTIME_INPUT_RESOURCE_LIMIT":
      return Object.freeze({ ok: false, reason: "RUNTIME_V04_INVALID", message: `The V04 runtime file exceeds the bounded inspection limit: ${relativePath}` });
    case "RUNTIME_FILE_CAPTURE_FAILED":
      return Object.freeze({ ok: false, reason: "RUNTIME_V04_INVALID", message: `The V04 runtime file could not be captured safely: ${relativePath}` });
  }
}

async function readRelativeBytes(
  anchoredRoot: AnchoredRunDirectoryReadCapabilityV02,
  runDirectory: string,
  relativePath: string,
  maxBytes: number,
  missingReason: "RUNTIME_V04_NOT_PRESENT" | "RUNTIME_V04_INVALID",
): Promise<
  | Readonly<{ ok: true; bytes: Uint8Array; path: string; mode: 384 | 420 }>
  | Readonly<{ ok: false; reason: "RUNTIME_V04_NOT_PRESENT" | "RUNTIME_V04_INVALID"; message: string }>
> {
  const captured = await captureRunFileForRuntimeInspectionV02({
    anchored_run_directory: anchoredRoot,
    relative_path: relativePath,
    max_bytes: maxBytes,
  });
  if (!captured.ok) {
    if (captured.error === "RUNTIME_FILE_NOT_FOUND") {
      return Object.freeze({ ok: false, reason: missingReason, message: missingReason === "RUNTIME_V04_NOT_PRESENT"
        ? `The V04 runtime directory does not contain ${relativePath}.`
        : `The V04 runtime directory is missing ${relativePath}.` });
    }
    return mapCaptureFailure(relativePath, captured.error);
  }
  return Object.freeze({
    ok: true,
    bytes: new Uint8Array(captured.value.bytes),
    path: join(runDirectory, relativePath),
    mode: captured.value.metadata.mode,
  });
}

function decodeJson(bytes: Uint8Array): unknown | null {
  try {
    return JSON.parse(UTF8.decode(bytes)) as unknown;
  } catch {
    return null;
  }
}

function inventoryRows(value: unknown): readonly ManifestInventoryRow[] | null {
  const parsed = RunManifestV04.safeParse(value);
  if (!parsed.success) return null;
  return parsed.data.file_inventory.map((row) => ({
    path: row.path,
    family: row.family,
    required: row.required,
    exists: row.exists,
    mode: row.mode,
    size_bytes: row.size_bytes,
  }));
}

function maximumBytes(row: ManifestInventoryRow): number | null {
  if (!row.exists) return 1;
  if (typeof row.size_bytes !== "number" || !Number.isSafeInteger(row.size_bytes) || row.size_bytes < 0) {
    return null;
  }
  return Math.max(1, row.size_bytes);
}

function deriveOwnerStatus(ledger: ValidatedRuntimeLedgerV04): OwnerStatusV04 {
  const activeOwner = ledger.state.active_run_owner;
  if (activeOwner === null) return Object.freeze({ status: "absent", evidence_refs: Object.freeze([]) as [] });
  return Object.freeze({
    status: "ambiguous",
    ambiguous_reason: "stale-owner-proof-missing",
    owner_lease_event_ref: activeOwner.lease_event_ref,
    evidence_refs: Object.freeze([activeOwner.lease_event_ref]),
  });
}

export async function inspectRuntimeDirectoryV04(
  runDirectory: unknown,
): Promise<InspectRuntimeDirectoryV04Result> {
  if (typeof runDirectory !== "string" || runDirectory.length === 0) {
    return failure("RUNTIME_V04_INVALID", "The runtime directory path is invalid.");
  }
  const absoluteDirectory = resolve(runDirectory);
  let canonicalDirectory: string;
  try {
    canonicalDirectory = await realpath(absoluteDirectory);
  } catch {
    return failure("RUNTIME_V04_INVALID", `The runtime directory could not be resolved safely: ${absoluteDirectory}`);
  }
  const anchored = await issueAnchoredRunDirectoryReadCapabilityV02(canonicalDirectory);
  if (!anchored.ok) {
    return failure("RUNTIME_V04_INVALID", `The runtime directory could not be anchored safely: ${absoluteDirectory}`);
  }

  const manifestRead = await readRelativeBytes(
    anchored.value,
    canonicalDirectory,
    "run-manifest.json",
    MAX_MANIFEST_BYTES,
    "RUNTIME_V04_NOT_PRESENT",
  );
  if (!manifestRead.ok) return manifestRead;
  if (manifestRead.mode !== 384) {
    return failure("RUNTIME_V04_INVALID", "The V04 run-manifest.json file must use exact mode 0600.");
  }

  const rawManifest = decodeJson(manifestRead.bytes);
  const rows = inventoryRows(rawManifest);
  if (rawManifest === null || rows === null) {
    return failure("RUNTIME_V04_INVALID", "run-manifest.json is not valid strict V04 manifest JSON.");
  }

  const planRead = await readRelativeBytes(
    anchored.value,
    canonicalDirectory,
    "resolved-run-plan.json",
    MAX_PLAN_BYTES,
    "RUNTIME_V04_INVALID",
  );
  if (!planRead.ok) return planRead;

  const ledgerRead = await readRelativeBytes(
    anchored.value,
    canonicalDirectory,
    "ledger.jsonl",
    MAX_LEDGER_BYTES,
    "RUNTIME_V04_INVALID",
  );
  if (!ledgerRead.ok) return ledgerRead;

  const validatedPlan = inspectRuntimePlanV03(planRead.bytes);
  if (!validatedPlan.ok) {
    return failure("RUNTIME_V04_INVALID", `resolved-run-plan.json failed V03 inspection: ${validatedPlan.reason}`);
  }
  const validatedLedger = inspectRuntimeLedgerV04(ledgerRead.bytes);
  if (!validatedLedger.ok) {
    return failure("RUNTIME_V04_INVALID", `ledger.jsonl failed V04 inspection: ${validatedLedger.reason}`);
  }

  const capturedFiles: Array<{
    path: string;
    family: "primary" | "record" | "projection";
    required: boolean;
    mode: 384 | null;
    bytes: Uint8Array | null;
  }> = [];
  for (const row of rows) {
    if (!row.exists) {
      capturedFiles.push({
        path: row.path,
        family: row.family,
        required: row.required,
        mode: null,
        bytes: null,
      });
      continue;
    }
    const maxBytes = maximumBytes(row);
    if (maxBytes === null) {
      return failure("RUNTIME_V04_INVALID", `run-manifest.json contains an invalid size for ${row.path}.`);
    }
    const bytes = row.path === "resolved-run-plan.json"
      ? planRead.bytes
      : row.path === "ledger.jsonl"
        ? ledgerRead.bytes
        : (() => null)();
    if (bytes !== null) {
      const actualMode = row.path === "resolved-run-plan.json" ? planRead.mode : ledgerRead.mode;
      if (actualMode !== 384) {
        return failure("RUNTIME_V04_INVALID", `The V04 runtime file mode does not match the required 0600 contract: ${row.path}.`);
      }
      capturedFiles.push({
        path: row.path,
        family: row.family,
        required: row.required,
        mode: actualMode,
        bytes,
      });
      continue;
    }
    const memberRead = await readRelativeBytes(
      anchored.value,
      canonicalDirectory,
      row.path,
      maxBytes,
      "RUNTIME_V04_INVALID",
    );
    if (!memberRead.ok) return memberRead;
    if (memberRead.mode !== 384) {
      return failure("RUNTIME_V04_INVALID", `The V04 runtime file mode does not match the required 0600 contract: ${row.path}.`);
    }
    capturedFiles.push({
      path: row.path,
      family: row.family,
      required: row.required,
      mode: memberRead.mode,
      bytes: memberRead.bytes,
    });
  }

  const validatedManifest = inspectRunManifestV04({
    manifest_bytes: manifestRead.bytes,
    ledger_bytes: ledgerRead.bytes,
    captured_files: capturedFiles,
  });
  if (!validatedManifest.ok) {
    return failure("RUNTIME_V04_INVALID", `run-manifest.json failed V04 inspection: ${validatedManifest.reason}`);
  }

  const latestCompaction = [...validatedManifest.ledger.events]
    .reverse()
    .find((event) => event.event_type === "run.compaction-recorded");
  if (latestCompaction === undefined) {
    return Object.freeze({
      ok: true,
      inspected: {
        validated_plan: validatedPlan.validated_plan,
        ledger: validatedManifest.ledger,
        manifest: validatedManifest.validated_manifest,
        owner_status: deriveOwnerStatus(validatedManifest.ledger),
        summary: null,
      },
    });
  }

  const summary = inspectRuntimeSummaryV04({
    ledger: validatedManifest.ledger,
    manifest: validatedManifest.validated_manifest,
    compaction_event_ref: {
      ledger_sequence: latestCompaction.sequence,
      event_hash: latestCompaction.event_hash,
    },
  });
  if (!summary.ok) {
    return failure("RUNTIME_V04_INVALID", `The V04 summary binding is invalid: ${summary.reason}`);
  }
  return Object.freeze({
    ok: true,
    inspected: {
      validated_plan: validatedPlan.validated_plan,
      ledger: validatedManifest.ledger,
      manifest: validatedManifest.validated_manifest,
      owner_status: deriveOwnerStatus(validatedManifest.ledger),
      summary: summary.inspected_summary,
    },
  });
}

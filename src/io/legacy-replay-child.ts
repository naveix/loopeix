import { constants } from "node:fs";
import { open, stat } from "node:fs/promises";
import { basename, extname } from "node:path";
import { pathToFileURL } from "node:url";
import type {
  LegacyV01DocumentKind,
  LegacyV01ParseResult,
  StructuredFamilySelectionKind,
} from "./captured-file.js";

export type LegacyReplayChildRequest = {
  direct_child_name: string;
  expected_directory_device: string;
  expected_directory_inode: string;
  max_bytes: number;
};

export type LegacyReplayChildResponse =
  | { ok: true; bytes_base64: string; byte_length: number }
  | {
      ok: false;
      reason: "IO_IDENTITY_MISMATCH" | "INVALID_INPUT_FILE" | "INPUT_TOO_LARGE" | "IO_HELPER_FAILURE";
      message: string;
    };

export type LegacyReplaySessionRequest =
  | { operation: "open"; request: LegacyReplayChildRequest }
  | { operation: "select-family"; kind: StructuredFamilySelectionKind }
  | { operation: "select-ledger-v01-lineage"; expected_run_id: string }
  | { operation: "parse-v01"; kind: LegacyV01DocumentKind }
  | { operation: "snapshot" }
  | { operation: "close" };

export type LegacyReplaySessionResponse =
  | { ok: true; operation: "open"; byte_length: number }
  | { ok: true; operation: "select-family"; schema_version: "0.1" | "0.2" }
  | { ok: true; operation: "select-ledger-v01-lineage"; schema_version: "0.1"; run_id: string }
  | ({ operation: "parse-v01" } & LegacyV01ParseResult)
  | { ok: true; operation: "snapshot"; bytes_base64: string; byte_length: number }
  | { ok: true; operation: "close" }
  | {
      ok: false;
      operation: "open" | "select-family" | "select-ledger-v01-lineage" | "parse-v01" | "snapshot" | "close";
      reason:
        | "IO_IDENTITY_MISMATCH"
        | "INVALID_INPUT_FILE"
        | "INPUT_TOO_LARGE"
        | "INVALID_DOCUMENT_ENVELOPE"
        | "MISSING_SCHEMA_VERSION"
        | "MALFORMED_SCHEMA_VERSION"
        | "UNSUPPORTED_SCHEMA_VERSION"
        | "INVALID_V01_DOCUMENT"
        | "IO_HELPER_FAILURE";
      message: string;
    };

type CapturedBytes = { bytes: Uint8Array; format: "json" | "yaml"; byteLength: number };

const MAX_V02_INPUT_BYTES = 4_194_304;

function failure(
  reason: Extract<LegacyReplayChildResponse, { ok: false }>['reason'],
  message: string,
): Extract<LegacyReplayChildResponse, { ok: false }> {
  return { ok: false, reason, message };
}

function isDirectChildName(value: string): boolean {
  return (
    value.length > 0 && value !== "." && value !== ".." && !value.includes("/") &&
    !value.includes("\\") && !value.includes("\0") && value.normalize("NFC") === value &&
    basename(value) === value
  );
}

function isRequest(value: unknown): value is LegacyReplayChildRequest {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const candidate = value as Partial<LegacyReplayChildRequest>;
  return (
    typeof candidate.direct_child_name === "string" &&
    typeof candidate.expected_directory_device === "string" &&
    typeof candidate.expected_directory_inode === "string" &&
    typeof candidate.max_bytes === "number" && Number.isSafeInteger(candidate.max_bytes) && candidate.max_bytes >= 0
  );
}

async function captureBytes(request: LegacyReplayChildRequest): Promise<CapturedBytes | Extract<LegacyReplayChildResponse, { ok: false }>> {
  if (!isDirectChildName(request.direct_child_name)) {
    return failure("INVALID_INPUT_FILE", "The helper accepts only a direct child file name.");
  }
  try {
    const directory = await stat(".", { bigint: true });
    if (directory.dev.toString() !== request.expected_directory_device || directory.ino.toString() !== request.expected_directory_inode) {
      return failure("IO_IDENTITY_MISMATCH", "The helper working-directory identity changed.");
    }
    const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
    const handle = await open(request.direct_child_name, constants.O_RDONLY | noFollow);
    try {
      const file = await handle.stat({ bigint: true });
      if (!file.isFile()) return failure("INVALID_INPUT_FILE", "The input must be a regular file.");
      if (file.size > BigInt(request.max_bytes)) return failure("INPUT_TOO_LARGE", `The input exceeds ${request.max_bytes} bytes.`);
      const chunks: Buffer[] = [];
      let byteLength = 0;
      for (;;) {
        const capacity = Math.min(65_536, request.max_bytes + 1 - byteLength);
        if (capacity <= 0) return failure("INPUT_TOO_LARGE", `The input exceeds ${request.max_bytes} bytes.`);
        const chunk = Buffer.allocUnsafe(capacity);
        const { bytesRead } = await handle.read(chunk, 0, capacity, null);
        if (bytesRead === 0) break;
        byteLength += bytesRead;
        if (byteLength > request.max_bytes) return failure("INPUT_TOO_LARGE", `The input exceeds ${request.max_bytes} bytes.`);
        chunks.push(chunk.subarray(0, bytesRead));
      }
      return {
        bytes: new Uint8Array(Buffer.concat(chunks, byteLength)),
        format: extname(request.direct_child_name).toLowerCase() === ".json" ? "json" : "yaml",
        byteLength,
      };
    } finally {
      await handle.close();
    }
  } catch (error: unknown) {
    const code = typeof error === "object" && error !== null && "code" in error ? String((error as { code?: unknown }).code) : "";
    if (code === "ELOOP" || code === "ENOENT" || code === "ENOTDIR") {
      return failure("INVALID_INPUT_FILE", "The input must be an existing direct regular file.");
    }
    return failure("IO_HELPER_FAILURE", "The compatibility helper could not capture the input.");
  }
}

export async function captureLegacyReplayChild(request: LegacyReplayChildRequest): Promise<LegacyReplayChildResponse> {
  const captured = await captureBytes(request);
  return "bytes" in captured
    ? { ok: true, bytes_base64: Buffer.from(captured.bytes).toString("base64"), byte_length: captured.byteLength }
    : captured;
}

async function decodeLegacyDocument(input: Uint8Array, format: "json" | "yaml"): Promise<{ ok: true; value: unknown } | { ok: false; message: string }> {
  let decoded: string;
  try { decoded = new TextDecoder("utf-8", { fatal: true }).decode(input); }
  catch { return { ok: false, message: "Input is not valid UTF-8." }; }
  const text = decoded.startsWith("\ufeff") ? decoded.slice(1) : decoded;
  try {
    const { parseAllDocuments, parseDocument } = await import("yaml");
    if (format === "json") {
      const duplicateCheck = parseDocument(text, { uniqueKeys: true });
      if (duplicateCheck.errors.length > 0) return { ok: false, message: "JSON framing or key uniqueness is invalid." };
      return { ok: true, value: JSON.parse(text) as unknown };
    }
    if (/^[ \t]*%/m.test(text) || /(^|[\s[{,])(?:&|\*)[A-Za-z0-9_-]+/.test(text) || /(^|\n)[ \t]*<<[ \t]*:/.test(text) || /(^|[\s[{,])![^\s]+/.test(text)) {
      return { ok: false, message: "YAML aliases, anchors, merge keys, tags, and directives are not allowed." };
    }
    const documents = parseAllDocuments(text, { uniqueKeys: true });
    const document = documents[0];
    if (documents.length !== 1 || document === undefined || document.errors.length > 0) {
      return { ok: false, message: "YAML must contain exactly one valid document with unique keys." };
    }
    return { ok: true, value: document.toJS({ maxAliasCount: 0 }) as unknown };
  } catch { return { ok: false, message: "Document syntax is invalid." }; }
}

type SelectedSchemaVersion =
  | { ok: true; schema_version: "0.1" | "0.2" }
  | { ok: false; reason: "MISSING_SCHEMA_VERSION" | "MALFORMED_SCHEMA_VERSION" | "UNSUPPORTED_SCHEMA_VERSION"; message: string };

function selectSchemaVersion(value: unknown): SelectedSchemaVersion {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return { ok: false, reason: "MISSING_SCHEMA_VERSION", message: "schema_version is required." };
  const descriptor = Object.getOwnPropertyDescriptor(value, "schema_version");
  if (descriptor === undefined) return { ok: false, reason: "MISSING_SCHEMA_VERSION", message: "schema_version is required." };
  if (!("value" in descriptor) || typeof descriptor.value !== "string" || !/^\d+\.\d+$/.test(descriptor.value)) {
    return { ok: false, reason: "MALFORMED_SCHEMA_VERSION", message: "schema_version must be an unmodified major.minor string." };
  }
  if (descriptor.value !== "0.1" && descriptor.value !== "0.2") return { ok: false, reason: "UNSUPPORTED_SCHEMA_VERSION", message: `Unsupported schema_version '${descriptor.value}'.` };
  return { ok: true, schema_version: descriptor.value };
}

function selectLargeSchemaVersion(bytes: Uint8Array, format: "json" | "yaml"): SelectedSchemaVersion | { ok: false; reason: "INVALID_DOCUMENT_ENVELOPE"; message: string } {
  let prefix: string;
  try { prefix = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, Math.min(bytes.byteLength, 65_536)), { stream: bytes.byteLength > 65_536 }); }
  catch { return { ok: false, reason: "INVALID_DOCUMENT_ENVELOPE", message: "Input is not valid UTF-8." }; }
  const withoutBom = prefix.startsWith("\ufeff") ? prefix.slice(1) : prefix;
  const match = format === "json"
    ? /^\s*\{\s*"schema_version"\s*:\s*"([^"]*)"/.exec(withoutBom)
    : /^(?:---[ \t]*(?:\r?\n|$))?(?:(?:[ \t]*#.*|[ \t]*)\r?\n)*schema_version[ \t]*:[ \t]*(?:"([^"]*)"|'([^']*)'|([^\s#]+))/.exec(withoutBom);
  const raw = match?.[1] ?? match?.[2] ?? match?.[3];
  return raw === undefined
    ? { ok: false, reason: "MISSING_SCHEMA_VERSION", message: "schema_version is required near the document start." }
    : selectSchemaVersion({ schema_version: raw });
}

function invalidV01(message: string): LegacyV01ParseResult {
  return { ok: false, reason: "INVALID_V01_DOCUMENT", message };
}

async function parseV01(captured: CapturedBytes, kind: LegacyV01DocumentKind): Promise<LegacyV01ParseResult> {
  const { hashRawBytes } = await import("../hash.js");
  const rawHash = hashRawBytes(captured.bytes);
  if (kind === "ledger-jsonl") {
    const { parseLedgerText, validateLedger, verifyEventHashes } = await import("../ledger.js");
    const { LedgerEvent } = await import("../schema/runtime.js");
    let text: string;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes); }
    catch { return { ok: false, reason: "INVALID_DOCUMENT_ENVELOPE", message: "Input is not valid UTF-8." }; }
    if (!text.endsWith("\n")) return invalidV01("A V01 ledger must be newline-terminated.");
    const parsed = parseLedgerText(text);
    if (parsed.partialFinalLineDropped || parsed.corruptLines.length > 0 || parsed.events.length === 0) return invalidV01("The V01 ledger contains an incomplete or corrupt event line.");
    const chainIssues = validateLedger(parsed.events);
    const events = parsed.events.flatMap((event) => { const result = LedgerEvent.safeParse(event); return result.success ? [result.data] : []; });
    const hashIssues = chainIssues.length === 0 ? verifyEventHashes(events) : [];
    if (chainIssues.length > 0 || hashIssues.length > 0 || events.some((event) => event.schema_version !== "0.1")) return invalidV01("The V01 ledger shape or hash chain is invalid.");
    return { ok: true, schema_version: "0.1", kind, byte_length: captured.byteLength, raw_hash: rawHash, value: events };
  }

  const decoded = await decodeLegacyDocument(captured.bytes, captured.format);
  if (!decoded.ok) return { ok: false, reason: "INVALID_DOCUMENT_ENVELOPE", message: decoded.message };
  let value: unknown;
  if (kind === "authoring" || kind === "generated-loop") {
    const { parseLoopeixDocument } = await import("../schema/version-dispatch.js");
    const parsed = parseLoopeixDocument(decoded.value);
    if (!parsed.ok || parsed.schema_version !== "0.1") return invalidV01(`The captured input is not a valid V01 ${kind} document.`);
    value = parsed.value;
  } else if (kind === "report-input") {
    const { z } = await import("zod");
    const { IntegrityStatus, RunState } = await import("../schema/runtime.js");
    const { HumanId, IsoTimestamp, LoopVersion, MachineId } = await import("../schema/scalars.js");
    const ReportInputShape = z.object({
      run_id: MachineId, loop_family: HumanId, loopeix_version: LoopVersion,
      run_state: RunState, integrity_status: IntegrityStatus,
      evidence: z.object({ verified: z.array(z.string()), unverified: z.array(z.string()), claims: z.array(z.object({ claim_id: z.string(), strength: z.string(), resolved_status: z.string() }).strict()) }).strict(),
      capture_gaps: z.array(z.object({ engine: z.string(), capability: z.string(), level: z.string(), note: z.string() }).strict()),
      waivers: z.array(z.object({ gate_id: z.string(), approver: z.string() }).strict()),
      findings: z.array(z.object({ finding_id: z.string(), title: z.string(), classification: z.string(), severity: z.string() }).strict()),
      redaction: z.object({ policy_version: z.string(), quarantined: z.number().int().nonnegative(), raw_excluded: z.boolean(), limitations: z.array(z.string()) }).strict(),
      timeline: z.array(z.object({ sequence: z.number().int().positive(), event_type: z.string().min(1), timestamp: IsoTimestamp }).strict()),
    }).strict().superRefine((report, context) => report.timeline.forEach((event, index) => {
      if (event.sequence !== index + 1) context.addIssue({ code: "custom", path: ["timeline", index, "sequence"], message: `expected lineage sequence ${index + 1}` });
    }));
    const parsed = ReportInputShape.safeParse(decoded.value);
    if (!parsed.success) return invalidV01("The captured input is not a valid V01 report input with ledger lineage.");
    value = parsed.data;
  } else if (kind === "receipt") {
    const { ReceiptShape, checkReceiptInvariants } = await import("../schema/receipt.js");
    const parsed = ReceiptShape.safeParse(decoded.value);
    if (!parsed.success || checkReceiptInvariants(parsed.data).length > 0) return invalidV01("The captured input is not a valid V01 receipt.");
    value = parsed.data;
  } else {
    const { ResolvedRunPlan } = await import("../schema/runtime.js");
    const { ApprovedIntakeBrief, CatalogResolution, CompilationRecord, IntakeRecord, WorkItemRecord } = await import("../compiler/records.js");
    const versionedSchemas = {
      "resolved-run-plan": ResolvedRunPlan, "work-item": WorkItemRecord, "intake-record": IntakeRecord,
      "catalog-resolution": CatalogResolution, "compilation-record": CompilationRecord,
      "approved-intake-brief": ApprovedIntakeBrief,
    } as const;
    const parsed = versionedSchemas[kind].safeParse(decoded.value);
    if (!parsed.success || parsed.data.schema_version !== "0.1") return invalidV01(`The captured input is not a valid V01 ${kind} document.`);
    value = parsed.data;
  }
  return { ok: true, schema_version: "0.1", kind, byte_length: captured.byteLength, raw_hash: rawHash, value };
}

async function selectLedgerV01Lineage(
  captured: CapturedBytes,
  expectedRunId: string,
): Promise<
  | { ok: true; operation: "select-ledger-v01-lineage"; schema_version: "0.1"; run_id: string }
  | { ok: false; operation: "select-ledger-v01-lineage"; reason: "INVALID_V01_DOCUMENT"; message: string }
> {
  if (expectedRunId.length === 0) {
    return { ok: false, operation: "select-ledger-v01-lineage", reason: "INVALID_V01_DOCUMENT", message: "The V01 ledger lineage is not coherent with the receipt." };
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes);
  } catch {
    return { ok: false, operation: "select-ledger-v01-lineage", reason: "INVALID_V01_DOCUMENT", message: "The V01 ledger has no valid complete first event." };
  }
  let firstLine: string | undefined;
  let start = 0;
  for (;;) {
    const newline = text.indexOf("\n", start);
    if (newline < 0) break;
    const line = text.slice(start, newline).replace(/\r$/u, "");
    if (line.trim().length > 0) {
      firstLine = line;
      break;
    }
    start = newline + 1;
  }
  if (firstLine === undefined) {
    return { ok: false, operation: "select-ledger-v01-lineage", reason: "INVALID_V01_DOCUMENT", message: "The V01 ledger has no valid complete first event." };
  }
  try {
    const { decodeStructuredDocumentV02 } = await import("../schema/decode-envelope.js");
    const decoded = decodeStructuredDocumentV02(new TextEncoder().encode(firstLine), "json");
    if (!decoded.ok) throw new Error("invalid event envelope");
    const value = decoded.value;
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("not an object");
    const event = value as Record<string, unknown>;
    if (event.schema_version !== "0.1" || event.run_id !== expectedRunId) {
      return { ok: false, operation: "select-ledger-v01-lineage", reason: "INVALID_V01_DOCUMENT", message: "The V01 ledger lineage is not coherent with the receipt." };
    }
    return { ok: true, operation: "select-ledger-v01-lineage", schema_version: "0.1", run_id: expectedRunId };
  } catch {
    return { ok: false, operation: "select-ledger-v01-lineage", reason: "INVALID_V01_DOCUMENT", message: "The V01 ledger has no valid complete first event." };
  }
}

async function runOneShot(): Promise<void> {
  let body = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) body += chunk;
  let request: unknown;
  try { request = JSON.parse(body) as unknown; }
  catch { process.stdout.write(`${JSON.stringify(failure("IO_HELPER_FAILURE", "The helper request was not valid JSON."))}\n`); return; }
  const response = isRequest(request) ? await captureLegacyReplayChild(request) : failure("IO_HELPER_FAILURE", "The helper request was malformed.");
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

async function runSession(): Promise<void> {
  let captured: CapturedBytes | null = null;
  let buffer = "";
  let idleTimer = setTimeout(() => process.exit(0), 30_000);
  idleTimer.unref();
  const resetIdleTimer = (): void => {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => process.exit(0), 30_000);
    idleTimer.unref();
  };
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) {
    buffer += chunk;
    for (;;) {
      const newline = buffer.indexOf("\n");
      if (newline < 0) break;
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      let input: unknown;
      try { input = JSON.parse(line) as unknown; }
      catch { process.stdout.write(`${JSON.stringify({ ok: false, operation: "open", reason: "IO_HELPER_FAILURE", message: "The helper request was not valid JSON." })}\n`); continue; }
      const request = input as Partial<LegacyReplaySessionRequest>;
      resetIdleTimer();
      let response: LegacyReplaySessionResponse;
      if (request.operation === "open" && isRequest(request.request) && captured === null) {
        const result = await captureBytes(request.request);
        if ("bytes" in result) { captured = result; response = { ok: true, operation: "open", byte_length: result.byteLength }; }
        else response = { ...result, operation: "open" };
      } else if (request.operation === "select-family" && captured !== null && (request.kind === "authoring" || request.kind === "resolved-run-plan")) {
        const selected = captured.byteLength > MAX_V02_INPUT_BYTES
          ? selectLargeSchemaVersion(captured.bytes, captured.format)
          : await (async () => { const { decodeStructuredDocumentV02 } = await import("../schema/decode-envelope.js"); const decoded = decodeStructuredDocumentV02(captured.bytes, captured.format); return decoded.ok ? selectSchemaVersion(decoded.value) : decoded; })();
        response = selected.ok
          ? (selected.schema_version === "0.2" && captured.byteLength > MAX_V02_INPUT_BYTES
              ? { ok: false, operation: "select-family", reason: "INPUT_TOO_LARGE", message: `Input exceeds ${MAX_V02_INPUT_BYTES} bytes.` }
              : { ok: true, operation: "select-family", schema_version: selected.schema_version })
          : { ...selected, operation: "select-family" };
      } else if (request.operation === "select-ledger-v01-lineage" && captured !== null && typeof request.expected_run_id === "string") {
        response = await selectLedgerV01Lineage(captured, request.expected_run_id);
      } else if (request.operation === "parse-v01" && captured !== null && typeof request.kind === "string") {
        response = { ...await parseV01(captured, request.kind as LegacyV01DocumentKind), operation: "parse-v01" };
      } else if (request.operation === "snapshot" && captured !== null) {
        response = { ok: true, operation: "snapshot", bytes_base64: Buffer.from(captured.bytes).toString("base64"), byte_length: captured.byteLength };
      } else if (request.operation === "close") {
        captured = null;
        response = { ok: true, operation: "close" };
      } else {
        response = { ok: false, operation: request.operation ?? "open", reason: "IO_HELPER_FAILURE", message: "The helper session request was malformed or out of order." } as LegacyReplaySessionResponse;
      }
      process.stdout.write(`${JSON.stringify(response)}\n`);
      if (request.operation === "close") return;
    }
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  const runner = process.argv.includes("--one-shot") ? runOneShot : runSession;
  void runner().catch(() => process.stdout.write(`${JSON.stringify(failure("IO_HELPER_FAILURE", "The compatibility helper failed."))}\n`));
}

import { parseDocument } from "yaml";

import { parseAndValidateRuntimeLedgerV02 } from "./runtime-ledger-v02.js";
import { inspectRuntimeLedgerV03 } from "./runtime-ledger-v03.js";

const MAX_LEDGER_BYTES = 67_108_864;
const MAX_EVENT_BYTES = 4_194_304;
const MAX_EVENTS = 100_000;

export type RuntimeLedgerDocumentInspection =
  | Readonly<{ ok: true; version: "0.2"; events: readonly unknown[]; sealed: boolean }>
  | (Extract<ReturnType<typeof inspectRuntimeLedgerV03>, { ok: true }> & Readonly<{ version: "0.3" }>)
  | Readonly<{ ok: false; reason: "LEDGER_VERSION_MISSING" | "LEDGER_VERSION_MIXED" | "LEDGER_VERSION_UNSUPPORTED" }>
  | Extract<ReturnType<typeof parseAndValidateRuntimeLedgerV02>, { ok: false }>
  | Extract<ReturnType<typeof inspectRuntimeLedgerV03>, { ok: false }>;

export function inspectRuntimeLedgerDocument(input: Uint8Array): RuntimeLedgerDocumentInspection {
  let bytes: Uint8Array;
  let text: string;
  try {
    if (!(input instanceof Uint8Array) || Object.getPrototypeOf(input) !== Uint8Array.prototype) throw new Error("invalid-byte-view");
    if (input.byteLength === 0 || input.byteLength > MAX_LEDGER_BYTES || input.buffer instanceof SharedArrayBuffer) throw new Error("invalid-byte-view");
    bytes = new Uint8Array(input);
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { ok: false, reason: "LEDGER_SYNTAX_INVALID", issues: [{ path: "(root)", message: "Runtime ledger bytes must be an owned valid UTF-8 view." }] };
  }
  if (Buffer.byteLength(text, "utf8") === 0 || Buffer.byteLength(text, "utf8") > MAX_LEDGER_BYTES || !text.endsWith("\n")) {
    return { ok: false, reason: "LEDGER_SYNTAX_INVALID", issues: [{ path: "(root)", message: "Runtime ledger must be bounded, non-empty, and newline-terminated." }] };
  }
  const lines = text.slice(0, -1).split("\n");
  if (lines.length === 0 || lines.length > MAX_EVENTS
    || lines.some((line) => line.length === 0 || Buffer.byteLength(line, "utf8") > MAX_EVENT_BYTES)) {
    return { ok: false, reason: "LEDGER_SYNTAX_INVALID", issues: [{ path: "(root)", message: "Every JSONL line must contain exactly one event." }] };
  }
  const versions = new Set<string>();
  for (const line of lines) {
    let value: unknown;
    try {
      const duplicateCheck = parseDocument(line, { uniqueKeys: true });
      if (duplicateCheck.errors.length > 0) throw new Error("invalid");
      value = JSON.parse(line) as unknown;
    } catch {
      return { ok: false, reason: "LEDGER_SYNTAX_INVALID", issues: [{ path: "(root)", message: "Runtime ledger JSONL framing is invalid." }] };
    }
    const schemaVersion = typeof value === "object" && value !== null
      ? (value as Record<string, unknown>).schema_version
      : undefined;
    if (typeof schemaVersion !== "string") {
      return { ok: false, reason: "LEDGER_VERSION_MISSING" };
    }
    versions.add(schemaVersion);
  }
  if (versions.size !== 1) return { ok: false, reason: "LEDGER_VERSION_MIXED" };
  const version = [...versions][0]!;
  if (version === "0.2") {
    const result = parseAndValidateRuntimeLedgerV02(text);
    return result.ok ? { ok: true, version, events: result.events, sealed: result.sealed } : result;
  }
  if (version === "0.3") {
    const result = inspectRuntimeLedgerV03(bytes);
    return result.ok ? { ...result, version } : result;
  }
  return { ok: false, reason: "LEDGER_VERSION_UNSUPPORTED" };
}

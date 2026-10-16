import { z } from "zod";
import { LoopeixV01Shape, checkLoopeixV01Invariants, type LoopeixV01 } from "./loopeix-v01.js";
import { LoopeixV02Shape, checkLoopeixV02Invariants, type LoopeixV02 } from "./loopeix-v02.js";

export const LoopeixDocument = z.union([LoopeixV01Shape, LoopeixV02Shape]);

export type DocumentIssue = { path: string; message: string };

export type LoopeixDocumentParseResult =
  | { ok: true; schema_version: "0.1"; value: LoopeixV01 }
  | { ok: true; schema_version: "0.2"; value: LoopeixV02 }
  | {
      ok: false;
      schema_version: "0.1" | "0.2";
      reason: "INVALID_AUTHORING_DOCUMENT";
      issues: DocumentIssue[];
    }
  | {
      ok: false;
      schema_version: null;
      reason:
        | "MISSING_SCHEMA_VERSION"
        | "MALFORMED_SCHEMA_VERSION"
        | "UNSUPPORTED_SCHEMA_VERSION";
      message: string;
    };

type VersionDispatchResult =
  | { ok: true; schema_version: "0.1" | "0.2" }
  | Extract<LoopeixDocumentParseResult, { ok: false; schema_version: null }>;

function readSchemaVersion(input: unknown): VersionDispatchResult {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return {
      ok: false,
      schema_version: null,
      reason: "MISSING_SCHEMA_VERSION",
      message: "schema_version is required.",
    };
  }

  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(input, "schema_version");
  } catch {
    descriptor = undefined;
  }
  if (descriptor === undefined) {
    return {
      ok: false,
      schema_version: null,
      reason: "MISSING_SCHEMA_VERSION",
      message: "schema_version is required.",
    };
  }

  if (!("value" in descriptor)) {
    return {
      ok: false,
      schema_version: null,
      reason: "MALFORMED_SCHEMA_VERSION",
      message: "schema_version must be an unmodified major.minor string.",
    };
  }
  const raw: unknown = descriptor.value;
  if (typeof raw !== "string" || !/^\d+\.\d+$/.test(raw)) {
    return {
      ok: false,
      schema_version: null,
      reason: "MALFORMED_SCHEMA_VERSION",
      message: "schema_version must be an unmodified major.minor string.",
    };
  }

  if (raw !== "0.1" && raw !== "0.2") {
    return {
      ok: false,
      schema_version: null,
      reason: "UNSUPPORTED_SCHEMA_VERSION",
      message: "schema_version is not supported; supported versions are '0.1' and '0.2'.",
    };
  }
  return { ok: true, schema_version: raw };
}

function zodIssues(error: { issues: readonly { path: readonly PropertyKey[]; message: string }[] }): DocumentIssue[] {
  return error.issues.map((issue) => ({
    path: issue.path.map((part) => String(part)).join(".") || "(root)",
    message: issue.message,
  }));
}

export function dispatchLoopeixValue(input: unknown): LoopeixDocumentParseResult {
  const dispatched = readSchemaVersion(input);
  if (!dispatched.ok) return dispatched;

  if (dispatched.schema_version === "0.1") {
    const parsed = LoopeixV01Shape.safeParse(input);
    if (!parsed.success) {
      return {
        ok: false,
        schema_version: "0.1",
        reason: "INVALID_AUTHORING_DOCUMENT",
        issues: zodIssues(parsed.error),
      };
    }
    const issues = checkLoopeixV01Invariants(parsed.data);
    return issues.length === 0
      ? { ok: true, schema_version: "0.1", value: parsed.data }
      : { ok: false, schema_version: "0.1", reason: "INVALID_AUTHORING_DOCUMENT", issues };
  }

  const parsed = LoopeixV02Shape.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      schema_version: "0.2",
      reason: "INVALID_AUTHORING_DOCUMENT",
      issues: zodIssues(parsed.error),
    };
  }
  const issues = checkLoopeixV02Invariants(parsed.data);
  return issues.length === 0
    ? { ok: true, schema_version: "0.2", value: parsed.data }
    : { ok: false, schema_version: "0.2", reason: "INVALID_AUTHORING_DOCUMENT", issues };
}

export function parseLoopeixDocument(input: unknown): LoopeixDocumentParseResult {
  return dispatchLoopeixValue(input);
}

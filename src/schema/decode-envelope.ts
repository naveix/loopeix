import { parseAllDocuments, parseDocument } from "yaml";

export type StructuredDecodeResult =
  | { ok: true; value: unknown }
  | {
      ok: false;
      reason: "INPUT_TOO_LARGE" | "INVALID_DOCUMENT_ENVELOPE";
      message: string;
    };

const MAX_INPUT_BYTES = 4_194_304;
const MAX_DEPTH = 64;
const MAX_NODES = 100_000;

function invalid(message: string): StructuredDecodeResult {
  return { ok: false, reason: "INVALID_DOCUMENT_ENVELOPE", message };
}

function validateTree(root: unknown): boolean {
  let nodes = 0;
  const stack: Array<{ value: unknown; depth: number }> = [{ value: root, depth: 1 }];
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) break;
    nodes += 1;
    if (nodes > MAX_NODES || current.depth > MAX_DEPTH) return false;
    if (Array.isArray(current.value)) {
      for (let index = current.value.length - 1; index >= 0; index -= 1) {
        stack.push({ value: current.value[index], depth: current.depth + 1 });
      }
    } else if (typeof current.value === "object" && current.value !== null) {
      const values = Object.values(current.value as Record<string, unknown>);
      for (let index = values.length - 1; index >= 0; index -= 1) {
        stack.push({ value: values[index], depth: current.depth + 1 });
      }
    }
  }
  return true;
}

function decodeUtf8(input: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(input);
  } catch {
    return null;
  }
}

export function decodeStructuredDocumentV02(
  input: Uint8Array,
  format: "json" | "yaml",
): StructuredDecodeResult {
  if (input.byteLength > MAX_INPUT_BYTES) {
    return { ok: false, reason: "INPUT_TOO_LARGE", message: `Input exceeds ${MAX_INPUT_BYTES} bytes.` };
  }

  const decoded = decodeUtf8(input);
  if (decoded === null) return invalid("Input is not valid UTF-8.");
  const text = decoded.startsWith("\ufeff") ? decoded.slice(1) : decoded;

  try {
    let value: unknown;
    if (format === "json") {
      const duplicateCheck = parseDocument(text, { uniqueKeys: true });
      if (duplicateCheck.errors.length > 0) return invalid("JSON contains duplicate keys or invalid framing.");
      value = JSON.parse(text) as unknown;
    } else {
      if (/^[ \t]*%/m.test(text) || /(^|[\s[{,])(?:&|\*)[A-Za-z0-9_-]+/.test(text) || /(^|\n)[ \t]*<<[ \t]*:/.test(text) || /(^|[\s[{,])![^\s]+/.test(text)) {
        return invalid("YAML aliases, anchors, merge keys, tags, and directives are not allowed.");
      }
      const documents = parseAllDocuments(text, { uniqueKeys: true });
      if (documents.length !== 1 || documents[0] === undefined || documents.some((document) => document.errors.length > 0)) {
        return invalid("YAML must contain exactly one valid document with unique keys.");
      }
      value = documents[0].toJS({ maxAliasCount: 0 }) as unknown;
    }

    if (!validateTree(value)) return invalid("Document exceeds the depth or node limit.");
    return { ok: true, value };
  } catch {
    return invalid("Document syntax is invalid.");
  }
}

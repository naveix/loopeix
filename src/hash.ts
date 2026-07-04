import { createHash } from "node:crypto";
import jcsCanonicalize from "canonicalize";

/**
 * Deterministic canonical JSON per RFC 8785 (JSON Canonicalization Scheme, JCS).
 * Keys are sorted by Unicode code point, array order is preserved, and numbers use
 * the ES6 serialisation rule. This is the byte form hashed for ledger events so
 * the same logical value always produces the same hash regardless of key insertion order.
 */
export function canonicalize(value: unknown): string {
  const s = jcsCanonicalize(value);
  if (s === undefined) throw new Error("cannot canonicalize non-serializable value");
  return s;
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** Hash of the canonical bytes of a value, as `sha256:<hex>`. */
export function hashCanonical(value: unknown): string {
  return `sha256:${sha256Hex(canonicalize(value))}`;
}

/** Hash of raw string bytes (e.g. an artifact's persisted contents), as `sha256:<hex>`. */
export function hashBytes(input: string): string {
  return `sha256:${sha256Hex(input)}`;
}

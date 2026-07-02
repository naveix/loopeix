import { createHash } from "node:crypto";

/**
 * Deterministic canonical JSON: object keys sorted recursively, array order kept.
 * This is the byte form hashed for ledger events and manifests, so the same logical
 * value always produces the same hash regardless of key order.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortValue);
  if (v !== null && typeof v === "object") {
    const src = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(src).sort()) out[k] = sortValue(src[k]);
    return out;
  }
  return v;
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

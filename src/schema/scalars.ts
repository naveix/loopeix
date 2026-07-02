import { z } from "zod";

/**
 * Shared scalar contracts (schema-contract.md §Shared Scalars).
 * These are the structural, JSON-Schema-representable building blocks.
 */

/** Human-authored id: lowercase kebab-case, e.g. `expert-sprint`. */
export const HumanId = z
  .string()
  .regex(/^[a-z0-9]+(-[a-z0-9]+)*$/, "must be lowercase kebab-case (e.g. expert-sprint)");

/** Runtime machine id: prefix + lowercase token, e.g. `run_...`, `ev_...`, `gate_...`. */
export const MachineId = z
  .string()
  .regex(/^[a-z]+_[a-z0-9]+(_[a-z0-9]+)*$/, "must be prefix_token (e.g. run_abc, ev_0001)");

/** Schema version string, e.g. `0.1`. */
export const SchemaVersion = z.string().regex(/^\d+\.\d+$/, 'must look like "0.1"');

/** Immutable loop version: `v` + three digits, e.g. `v001`. */
export const LoopVersion = z.string().regex(/^v\d{3}$/, "must be v + three digits (e.g. v001)");

/** ISO 8601 UTC timestamp. */
export const IsoTimestamp = z.iso.datetime({ offset: false });

/** Content hash, `sha256:<64 lowercase hex>`. */
export const Hash = z.string().regex(/^sha256:[0-9a-f]{64}$/, "must be sha256:<64 hex>");

/** Relative path that must stay inside the approved run directory. */
export const RelativeRunPath = z.string().refine(
  (p) => {
    if (p.startsWith("/") || p.startsWith("\\")) return false; // absolute (posix / unc)
    if (/^[A-Za-z]:/.test(p)) return false; // windows drive letter
    return !p.split(/[\\/]/).includes(".."); // no parent-dir escape
  },
  { message: "must be a relative path within the run directory (no leading /, \\, drive letter, or ..)" },
);

/** Full risk-tier space, including T5. Used by RUNTIME records that must be able to
 *  record a T5 attempt that was blocked (e.g. a t5-blocked-fail ledger). */
export const RiskTier = z.enum([
  "T0",
  "T1",
  "T2",
  "T3a",
  "T3b",
  "T3c",
  "T3d",
  "T4",
  "T5",
]);

/** Authoring-time risk tier. V1 rejects T5 outright, so it is NOT selectable in a spec.
 *  Using this for `max_tier_without_approval` and `ToolGrant.risk_tier` closes the T5
 *  bypass that a single `t5_allowed: false` literal leaves open. */
export const RiskTierV1 = z.enum([
  "T0",
  "T1",
  "T2",
  "T3a",
  "T3b",
  "T3c",
  "T3d",
  "T4",
]);

export type RiskTierValue = z.infer<typeof RiskTier>;

import { parse as parseYaml } from "yaml";
import { BriefShape, type Brief } from "./schema/brief.js";
import { computeBriefHash } from "./schema/receipt.js";

/**
 * Brief loading + sealing helpers (claim-families-v1.md §Structured clauses, flagship M2).
 *
 * `loadBrief` is the trusted producer side: an unreadable, malformed, or structurally invalid
 * brief throws an explicit error naming the first issues — a run must never start against a
 * promise that could not be parsed exactly as written. The sealed payload pairs the validated
 * brief with its `brief_hash` (RFC 8785 canonical hash over the five content fields — the SAME
 * hash `buildReceipt` embeds and `checkReceiptInvariants` recomputes), so the ledger's
 * `brief.sealed` event and the final receipt bind to one identical promise.
 */

/** Parse + validate a brief YAML text. Throws with precise issues; never returns a partial brief. */
export function loadBrief(yamlText: string): Brief {
  let raw: unknown;
  try {
    raw = parseYaml(yamlText);
  } catch (err) {
    throw new Error(`brief is not valid YAML: ${(err as Error).message}`);
  }
  const parsed = BriefShape.safeParse(raw);
  if (!parsed.success) {
    const shown = parsed.error.issues
      .slice(0, 3)
      .map((i) => `${i.path.map((p) => String(p)).join(".") || "(root)"}: ${i.message}`)
      .join("; ");
    throw new Error(`invalid brief (${parsed.error.issues.length} issue(s)): ${shown}`);
  }
  const d = parsed.data;
  // NFC-normalize all glob strings exactly once at load time so that NFD-authored briefs
  // (e.g., globs pasted from a macOS NFD filesystem) do not produce false convictions when
  // compared against NFC-normalized paths. globMatchesNormalized also NFC-normalizes the
  // pattern at match time as a belt — this covers hand-built Brief objects.
  return {
    ...d,
    scope: d.scope.map((p) => p.normalize("NFC")),
    forbidden: d.forbidden.map((c) =>
      c.kind === "delete_paths" || c.kind === "write_paths"
        ? { ...c, globs: c.globs.map((g) => g.normalize("NFC")) }
        : c,
    ),
  };
}

/** The `brief.sealed` ledger-event payload: the brief plus the hash the receipt will re-bind. */
export function sealedBriefPayload(brief: Brief): { brief: Brief; brief_hash: string } {
  return { brief: structuredClone(brief), brief_hash: computeBriefHash(brief) };
}

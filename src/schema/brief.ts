import { z } from "zod";
import { HumanId } from "./scalars.js";

/**
 * Sealed-brief schema, brief_version 0.1 (claim-families-v1.md §Structured clauses).
 *
 * Free text cannot be adjudicated without NLP guessing, so brief clauses are STRUCTURED
 * objects — each with a human `label` (the display string) and a machine `kind` that names
 * the claim family adjudicating it:
 *  - acceptance: `tests-pass` (family F1) or `freeform` (recorded verbatim; always UNEVALUATED);
 *  - forbidden: `delete_paths` / `write_paths` (family F2; `globs` REQUIRED) or `freeform`;
 *  - scope: plain glob array (family F3); empty scope ⇒ no scope clause is ever emitted.
 *
 * The globs rule is STRUCTURAL, not a refinement: the discriminated union's path branch
 * requires `globs` (min 1) and its strict freeform branch has no `globs` key at all — so the
 * rule survives into any generated JSON Schema, same technique as the receipt's doctrine
 * encoding (src/schema/receipt.ts). All clause objects are strict: an unknown key in an
 * authored brief is an author error, never silently stripped into a different promise.
 */

export const AcceptanceKind = z.enum(["tests-pass", "freeform"]);
export const ForbiddenKind = z.enum(["delete_paths", "write_paths", "freeform"]);

/** One acceptance criterion. `label` is what humans read; `kind` is what machines adjudicate. */
export const AcceptanceClause = z.strictObject({
  id: HumanId,
  label: z.string().min(1),
  kind: AcceptanceKind,
});
export type AcceptanceClauseRecord = z.infer<typeof AcceptanceClause>;

/** One forbidden clause. Path kinds REQUIRE globs; freeform structurally cannot carry them. */
export const ForbiddenClause = z.discriminatedUnion("kind", [
  z.strictObject({
    id: HumanId,
    label: z.string().min(1),
    kind: z.enum(["delete_paths", "write_paths"]),
    globs: z.array(z.string().min(1)).min(1),
  }),
  z.strictObject({
    id: HumanId,
    label: z.string().min(1),
    kind: z.literal("freeform"),
  }),
]);
export type ForbiddenClauseRecord = z.infer<typeof ForbiddenClause>;

/**
 * The authored brief (what `--seal <path>` loads). `forbidden` and `scope` default to empty;
 * clause ids must be unique across acceptance[] and forbidden[] (they become receipt
 * claim/clause ids). The uniqueness rule is a refinement, which is fine here: BriefShape is
 * never emitted as a public JSON Schema — the receipt embeds the structural clause shapes only.
 */
export const BriefShape = z
  .strictObject({
    brief_version: z.literal("0.1"),
    task: z.string().min(1),
    acceptance: z.array(AcceptanceClause).min(1),
    forbidden: z.array(ForbiddenClause).default([]),
    scope: z.array(z.string().min(1)).default([]),
  })
  .superRefine((brief, ctx) => {
    const seen = new Set<string>();
    const all = [...brief.acceptance.map((c) => c.id), ...brief.forbidden.map((c) => c.id)];
    for (const id of all) {
      // `scope` is a reserved id: it names the built-in F3 scope clause in receipt clause ids
      // (clause_scope) and must not collide with a user-defined acceptance/forbidden clause.
      if (id === "scope") {
        ctx.addIssue({ code: "custom", message: `clause id 'scope' is reserved — use a different id` });
      }
      if (seen.has(id)) {
        ctx.addIssue({ code: "custom", message: `duplicate clause id '${id}' across acceptance/forbidden` });
      }
      seen.add(id);
    }
  });
export type Brief = z.infer<typeof BriefShape>;

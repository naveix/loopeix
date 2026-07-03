import { checkLoopeixInvariants, LoopeixShape, type Issue } from "./schema/loopeix.js";

export interface ValidationResult {
  ok: boolean;
  /** Structural (schema) issues, then relational (invariant) issues. */
  errors: Issue[];
}

/**
 * Validate an already-parsed Loopeix value (e.g. from YAML.parse).
 * Layer 1: Zod structural parse. Layer 2: cross-field invariants (only if Layer 1 passes).
 */
export function validateLoopeix(data: unknown): ValidationResult {
  const parsed = LoopeixShape.safeParse(data);
  if (!parsed.success) {
    const errors: Issue[] = parsed.error.issues.map((issue) => ({
      path: issue.path.map((p) => String(p)).join(".") || "(root)",
      message: issue.message,
    }));
    return { ok: false, errors };
  }
  const invariantIssues = checkLoopeixInvariants(parsed.data);
  return { ok: invariantIssues.length === 0, errors: invariantIssues };
}

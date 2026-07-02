import { checkLoopSpecInvariants, LoopSpecShape, type Issue } from "./schema/loopspec.js";

export interface ValidationResult {
  ok: boolean;
  /** Structural (schema) issues, then relational (invariant) issues. */
  errors: Issue[];
}

/**
 * Validate an already-parsed LoopSpec value (e.g. from YAML.parse).
 * Layer 1: Zod structural parse. Layer 2: cross-field invariants (only if Layer 1 passes).
 */
export function validateLoopSpec(data: unknown): ValidationResult {
  const parsed = LoopSpecShape.safeParse(data);
  if (!parsed.success) {
    const errors: Issue[] = parsed.error.issues.map((issue) => ({
      path: issue.path.map((p) => String(p)).join(".") || "(root)",
      message: issue.message,
    }));
    return { ok: false, errors };
  }
  const invariantIssues = checkLoopSpecInvariants(parsed.data);
  return { ok: invariantIssues.length === 0, errors: invariantIssues };
}

import { checkLoopeixInvariants, LoopeixShape, type Issue } from "./schema/loopeix.js";
import { checkLoopeixV01Invariants, LoopeixV01Shape } from "./schema/loopeix-v01.js";
import { checkLoopeixV02Invariants, LoopeixV02Shape } from "./schema/loopeix-v02.js";

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

function structuralErrors(issues: readonly { path: readonly PropertyKey[]; message: string }[]): Issue[] {
  return issues.map((issue) => ({
    path: issue.path.map((part) => String(part)).join(".") || "(root)",
    message: issue.message,
  }));
}

export function validateLoopeixV01(data: unknown): ValidationResult {
  const parsed = LoopeixV01Shape.safeParse(data);
  if (!parsed.success) return { ok: false, errors: structuralErrors(parsed.error.issues) };
  const errors = checkLoopeixV01Invariants(parsed.data);
  return { ok: errors.length === 0, errors };
}

export function validateLoopeixV02(data: unknown): ValidationResult {
  const parsed = LoopeixV02Shape.safeParse(data);
  if (!parsed.success) return { ok: false, errors: structuralErrors(parsed.error.issues) };
  const errors = checkLoopeixV02Invariants(parsed.data);
  return { ok: errors.length === 0, errors };
}

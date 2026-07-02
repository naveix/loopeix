import { UNWAIVABLE_GATES } from "./schema/evidence.js";

/**
 * Gate engine (architecture-plan.md §Gate Engine, schema-evidence-gates.md).
 *
 * FAIL-CLOSED by design — this is the T5 / unwaivable enforcement point:
 *  - `no-t5` is normalized-injected (a spec cannot weaken it to non-blocking or waivable) and
 *    FAILs on ANY T5 signal, matched leniently (any non-`false` flag, trimmed/upper-cased tiers).
 *  - Unwaivable gates, and gates a spec marks `waiver_allowed:false`, can never be WAIVED.
 *  - A blocking gate with nothing to verify HOLDs (never a silent PASS).
 *  - Evidence-based gates HOLD if any `inputs_required` is absent.
 *
 * V1 scope note: `no-t5` is the one control injected universally (T5 is always forbidden). The
 * other unwaivable controls (report-truthfulness, secrets-privacy, evidence-integrity) are
 * enforced WHEN a spec declares them — they cannot be waived and cannot false-PASS — but are not
 * force-injected, because their required evidence is loop-type-dependent.
 */

export type GateStatusValue = "PASS" | "HOLD" | "FAIL" | "WAIVED";

/** Gates always evaluated in V1, injected (normalized) if a spec omits or weakens them (S10-B). */
export const REQUIRED_V1_GATES: readonly string[] = ["no-t5"];

export interface GateSpecInput {
  id: string;
  blocking: boolean;
  inputs_required: readonly string[];
  waiver_allowed: boolean;
}

export interface RunGateContext {
  gates: readonly GateSpecInput[];
  risk_controls: { max_tier_without_approval: string; t5_allowed: boolean };
  tool_grant_tiers?: readonly string[];
  available_inputs?: readonly string[];
  waivers?: readonly string[];
  unattended_loop_present?: boolean;
}

export interface GateDecision {
  gate_id: string;
  blocking: boolean;
  status: GateStatusValue;
  reason: string;
  missing_inputs: string[];
  findings: string[];
}

export interface GateReport {
  decisions: GateDecision[];
  summary: { pass: number; hold: number; fail: number; waived: number };
  blocking_hold_or_fail: boolean;
}

const normId = (id: string): string => id.trim().toLowerCase();
const isT5Tier = (t: unknown): boolean => typeof t === "string" && t.trim().toUpperCase() === "T5";

function hasT5(ctx: RunGateContext): boolean {
  const rc = ctx.risk_controls;
  if (rc === null || typeof rc !== "object") return true; // fail-closed on malformed context
  return (
    rc.t5_allowed !== false || // fail-closed: anything not strictly `false` counts as T5
    isT5Tier(rc.max_tier_without_approval) ||
    (Array.isArray(ctx.tool_grant_tiers) ? ctx.tool_grant_tiers : []).some(isT5Tier) ||
    ctx.unattended_loop_present === true
  );
}

export function evaluateGates(ctx: RunGateContext): GateReport {
  const available = new Set(ctx.available_inputs ?? []);
  const waived = new Set((ctx.waivers ?? []).map(normId));
  const t5 = hasT5(ctx);

  // NORMALIZED injection: drop any spec-declared required gate and append the hardcoded safe one,
  // so a spec cannot shadow `no-t5` with a non-blocking / waivable version (B1).
  const required = new Set(REQUIRED_V1_GATES.map(normId));
  const gates: GateSpecInput[] = (Array.isArray(ctx.gates) ? ctx.gates : []).filter((g) => !required.has(normId(g.id)));
  for (const req of REQUIRED_V1_GATES) {
    gates.push({ id: req, blocking: true, inputs_required: [], waiver_allowed: false });
  }

  const decisions: GateDecision[] = gates.map((g) => {
    const gid = normId(g.id);
    const findings: string[] = [];
    let missing: string[] = [];
    let status: GateStatusValue;
    let reason: string;

    if (gid === "no-t5") {
      status = t5 ? "FAIL" : "PASS";
      reason = t5
        ? "T5 (scheduled/recurring/unattended) behavior is present; V1 blocks T5."
        : "No T5 behavior requested or executed.";
    } else {
      const inputs = Array.isArray(g.inputs_required) ? g.inputs_required : [];
      missing = inputs.filter((i) => !available.has(i));
      if (missing.length > 0) {
        status = "HOLD";
        reason = `Missing required evidence: ${missing.join(", ")}.`;
      } else if (g.blocking && inputs.length === 0) {
        // A blocking gate that declares nothing to verify cannot be proven → HOLD, never PASS (M2).
        status = "HOLD";
        reason = "Blocking gate declares no inputs to verify; cannot be proven — held.";
      } else {
        status = "PASS";
        reason = "All required inputs are present.";
      }
    }

    // Waiver handling — refuse for unwaivable gates OR gates the spec marks non-waivable (M1).
    if (waived.has(gid)) {
      if (UNWAIVABLE_GATES.has(gid)) {
        findings.push(`Waiver ignored: '${g.id}' is unwaivable in V1.`);
      } else if (g.waiver_allowed === false) {
        findings.push(`Waiver ignored: gate '${g.id}' is declared non-waivable (waiver_allowed:false).`);
      } else if (status === "FAIL" || status === "HOLD") {
        status = "WAIVED";
        reason = `${reason} Waived by an approved waiver.`;
      }
    }

    return { gate_id: g.id, blocking: g.blocking, status, reason, missing_inputs: missing, findings };
  });

  const summary = { pass: 0, hold: 0, fail: 0, waived: 0 };
  for (const d of decisions) {
    if (d.status === "PASS") summary.pass += 1;
    else if (d.status === "HOLD") summary.hold += 1;
    else if (d.status === "FAIL") summary.fail += 1;
    else summary.waived += 1;
  }

  const blocking_hold_or_fail = decisions.some((d) => d.blocking && (d.status === "HOLD" || d.status === "FAIL"));
  return { decisions, summary, blocking_hold_or_fail };
}

export const S35_FREE_CONTROL_STRING_MAX_BYTES = 16_384;
export const S35_RELATED_IDS_MAX_CARDINALITY = 256;

export const S35_CONTROL_PLANE_FAMILY_CEILINGS = Object.freeze({
  ledger_standard: 131_072,
  ledger_authority: 524_288,
  record_standard: 262_144,
  record_authority: 1_048_576,
  manifest: 4_194_304,
  report: 4_194_304,
});

export type ControlPlaneBudgetOracleInputS35 = Readonly<{
  goal: Readonly<{ success_criteria: readonly Readonly<{ id: string }>[] }>;
  tasks: readonly Readonly<{ id: string }>[];
  gates: readonly Readonly<{ id: string }>[];
  evaluations: readonly Readonly<{ id: string }>[];
  artifacts: readonly Readonly<{ id: string }>[];
  progress: Readonly<{ observations: readonly Readonly<{ id: string }>[] }>;
  compensations: readonly Readonly<{ id: string }>[];
  side_effects: readonly Readonly<{ task_id: string; effects: readonly Readonly<{ effect_id: string }>[] }>[];
  retry_policy: Readonly<{ rules: readonly Readonly<{ task_ref: string; max_task_executions: number }>[] }>;
  runtime_record_limits: Readonly<{
    max_authority_records: number;
    max_agency_recommendation_records: number;
    max_authority_revocation_records: number;
    max_evidence_records: number;
    max_task_result_records: number;
    max_manual_observation_records: number;
    max_export_decision_records: number;
    max_claim_records: number;
    max_finding_records: number;
    max_waiver_records: number;
    max_preseal_custody_events: number;
  }>;
  limit_policy: Readonly<{
    max_loop_attempts: number;
    max_tool_calls: number;
    control_plane_output_reserve_bytes: number;
  }>;
}>;

export type ControlPlaneBudgetFamilyOracleS35 = Readonly<{
  family: string;
  cardinality: number;
  max_bytes: number;
}>;

export type ControlPlaneBudgetOracleResultS35 =
  | Readonly<{
      ok: true;
      value: Readonly<{
        required_control_plane_output_bytes: number;
        k_non_clock_primary_event_max: number;
        clock_event_max: number;
        terminal_event_reservation_max: number;
        event_families: readonly ControlPlaneBudgetFamilyOracleS35[];
        file_families: readonly ControlPlaneBudgetFamilyOracleS35[];
      }>;
    }>
  | Readonly<{ ok: false; reason: "CONTROL_PLANE_BUDGET_OVERFLOW" | "CONTROL_PLANE_BUDGET_EXCEEDS_RESERVE" }>;

function checked(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new RangeError("unsafe budget arithmetic");
  return value;
}

function add(...values: readonly number[]): number {
  return values.reduce((sum, value) => checked(sum + checked(value)), 0);
}

function multiply(left: number, right: number): number {
  return checked(checked(left) * checked(right));
}

function row(family: string, cardinality: number, maxBytes: number): ControlPlaneBudgetFamilyOracleS35 {
  return Object.freeze({ family, cardinality: checked(cardinality), max_bytes: checked(maxBytes) });
}

export function expectedRuntimeRecordLimitsOracleS35(
  A: number, G: number, E: number, R: number, S: number, C: number,
): ControlPlaneBudgetOracleInputS35["runtime_record_limits"] {
  const evidence = add(multiply(8, A), multiply(12, G), multiply(4, E), multiply(2, R), 32);
  return Object.freeze({
    max_authority_records: add(multiply(9, A), multiply(10, G)),
    max_agency_recommendation_records: multiply(8, add(multiply(2, A), C)),
    max_authority_revocation_records: add(A, multiply(2, G)),
    max_evidence_records: evidence,
    max_task_result_records: A,
    max_manual_observation_records: evidence,
    max_export_decision_records: add(R, evidence),
    max_claim_records: add(S, G, E),
    max_finding_records: add(multiply(4, A), multiply(2, G), multiply(2, E), multiply(2, R), 32),
    max_waiver_records: G,
    max_preseal_custody_events: multiply(2, add(R, evidence)),
  });
}

export function deriveControlPlaneBudgetOracleS35(input: ControlPlaneBudgetOracleInputS35): ControlPlaneBudgetOracleResultS35 {
  try {
    const retryByTask = new Map<string, number>();
    for (const rule of input.retry_policy.rules) {
      checked(rule.max_task_executions);
      retryByTask.set(rule.task_ref, Math.max(retryByTask.get(rule.task_ref) ?? 0, rule.max_task_executions));
    }
    const A = input.tasks.reduce((sum, task) => add(sum, retryByTask.get(task.id) ?? 0), 0);
    const G = input.gates.length;
    const E = input.evaluations.length;
    const R = input.artifacts.length;
    const S = input.goal.success_criteria.length;
    const C = input.compensations.length;
    const P = input.progress.observations.length;
    const T = input.limit_policy.max_loop_attempts;
    const D = add(multiply(2, A), C);
    const expectedLimits = expectedRuntimeRecordLimitsOracleS35(A, G, E, R, S, C);
    if (Object.keys(expectedLimits).some((key) =>
      input.runtime_record_limits[key as keyof typeof expectedLimits] !== expectedLimits[key as keyof typeof expectedLimits])) {
      throw new RangeError("record limit mismatch");
    }

    let F = 0;
    for (const task of input.tasks) {
      const effectRows = input.side_effects.filter(({ task_id }) => task_id === task.id);
      if (effectRows.length !== 1 || effectRows[0]!.effects.length < 1) throw new RangeError("side-effect mismatch");
      F = add(F, multiply(effectRows[0]!.effects.length, retryByTask.get(task.id) ?? 0));
    }

    const L = S35_CONTROL_PLANE_FAMILY_CEILINGS;
    const nonClockRows = [
      row("initialize", 1, L.ledger_standard),
      row("fence-advances-plus-abort", add(A, 3), L.ledger_standard),
      row("gate-required-results", multiply(2, G), L.ledger_standard),
      row("evaluation-required-results", multiply(2, E), L.ledger_standard),
      row("authority-events", add(multiply(26, A), multiply(13, G), multiply(8, C)), L.ledger_authority),
      row("policy-decisions", D, L.ledger_authority),
      row("evidence-recorded", expectedLimits.max_evidence_records, L.ledger_standard),
      row("manual-observations", expectedLimits.max_manual_observation_records, L.ledger_standard),
      row("export-decisions", expectedLimits.max_export_decision_records, L.ledger_standard),
      row("claims-findings", add(expectedLimits.max_claim_records, expectedLimits.max_finding_records), L.ledger_standard),
      row("action-lifecycle", multiply(7, A), L.ledger_standard),
      row("tool-admission", input.limit_policy.max_tool_calls, L.ledger_standard),
      row("artifact-write-record", multiply(2, R), L.ledger_standard),
      row("prospective-limit-blocks", add(C, 1), L.ledger_standard),
      row("effect-outcomes", F, L.ledger_standard),
      row("preseal-redaction-custody", expectedLimits.max_preseal_custody_events, L.ledger_standard),
      row("task-progress-facts", A, L.ledger_standard),
      row("progress-attempt-boundaries", multiply(T, add(P, 1)), L.ledger_standard),
      row("terminal-freeze", 7, L.ledger_standard),
      row("compensation-requests", C === 0 ? 0 : add(C, 3), L.ledger_standard),
      row("compensation-phase-escalation", C === 0 ? 0 : 4, L.ledger_standard),
      row("compensation-settlements", C, L.ledger_standard),
      row("terminal-seal", 1, L.ledger_standard),
    ] as const;
    const K = nonClockRows.reduce((sum, family) => add(sum, family.cardinality), 0);
    const clocks = add(multiply(2, A), G, K);
    const eventFamilies = Object.freeze([
      nonClockRows[0],
      row("clocks", clocks, L.ledger_standard),
      ...nonClockRows.slice(1),
    ]);
    const fileFamilies = Object.freeze([
      row("authority-records", expectedLimits.max_authority_records, L.record_authority),
      row("agency-recommendation-records", expectedLimits.max_agency_recommendation_records, L.record_authority),
      row("authority-revocation-records", expectedLimits.max_authority_revocation_records, L.record_authority),
      row("evidence-records", expectedLimits.max_evidence_records, L.record_standard),
      row("task-result-records", expectedLimits.max_task_result_records, L.record_standard),
      row("manual-observation-records", expectedLimits.max_manual_observation_records, L.record_standard),
      row("export-decision-records", expectedLimits.max_export_decision_records, L.record_standard),
      row("claim-records", expectedLimits.max_claim_records, L.record_standard),
      row("finding-records", expectedLimits.max_finding_records, L.record_standard),
      row("waiver-records", expectedLimits.max_waiver_records, L.record_standard),
      row("gate-result-records", G, L.record_standard),
      row("evaluation-result-records", E, L.record_standard),
      row("artifact-records", R, L.record_standard),
      row("redaction-derivative-records", expectedLimits.max_preseal_custody_events / 2, L.record_standard),
      row("runtime-manifests", 2, L.manifest),
      row("final-report-projections", 3, L.report),
    ]);
    const required = [...eventFamilies, ...fileFamilies].reduce(
      (sum, family) => add(sum, multiply(family.cardinality, family.max_bytes)), 0,
    );
    if (required > checked(input.limit_policy.control_plane_output_reserve_bytes)) {
      return { ok: false, reason: "CONTROL_PLANE_BUDGET_EXCEEDS_RESERVE" };
    }
    return {
      ok: true,
      value: Object.freeze({
        required_control_plane_output_bytes: required,
        k_non_clock_primary_event_max: K,
        clock_event_max: clocks,
        terminal_event_reservation_max: C === 0 ? 8 : add(15, multiply(2, C)),
        event_families: eventFamilies,
        file_families: fileFamilies,
      }),
    };
  } catch {
    return { ok: false, reason: "CONTROL_PLANE_BUDGET_OVERFLOW" };
  }
}

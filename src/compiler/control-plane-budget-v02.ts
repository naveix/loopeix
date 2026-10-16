type RetryRuleInputV02 = Readonly<{ task_ref: string; max_task_executions: number }>;
type SideEffectInputV02 = Readonly<{ task_id: string; effects: readonly Readonly<{ effect_id: string }>[] }>;
type RuntimeRecordLimitsInputV02 = Readonly<{
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

export type ControlPlaneBudgetInputV02 = Readonly<{
  goal: Readonly<{ success_criteria: readonly Readonly<{ id: string }>[] }>;
  tasks: readonly Readonly<{ id: string }>[];
  gates: readonly Readonly<{ id: string }>[];
  evaluations: readonly Readonly<{ id: string }>[];
  artifacts: readonly Readonly<{ id: string }>[];
  progress: Readonly<{ observations: readonly Readonly<{ id: string }>[] }>;
  compensations: readonly Readonly<{ id: string }>[];
  side_effects: readonly SideEffectInputV02[];
  retry_policy: Readonly<{ rules: readonly RetryRuleInputV02[] }>;
  runtime_record_limits: RuntimeRecordLimitsInputV02;
  limit_policy: Readonly<{
    max_loop_attempts: number;
    max_tool_calls: number;
    control_plane_output_reserve_bytes: number;
  }>;
}>;

export type ControlPlaneBudgetDerivationErrorV02 =
  | "CONTROL_PLANE_BUDGET_CONTRACT_INVALID"
  | "CONTROL_PLANE_BUDGET_OVERFLOW"
  | "CONTROL_PLANE_BUDGET_EXCEEDS_RESERVE";

export type ControlPlaneBudgetFamilyCeilingV02 = Readonly<{
  family: string;
  cardinality: number;
  max_bytes: number;
}>;

export const CONTROL_PLANE_CHARGE_PROFILE_V02 = "control-plane-charge-ceilings-v02-s35-1" as const;
export const CONTROL_PLANE_BYTE_CEILINGS_V02 = Object.freeze({
  ledger_standard: 131_072,
  ledger_authority: 524_288,
  record_standard: 262_144,
  record_authority: 1_048_576,
  manifest: 4_194_304,
  report: 4_194_304,
} as const);

export type ControlPlaneBudgetDerivationV02 = Readonly<{
  required_control_plane_output_bytes: number;
  k_non_clock_primary_event_max: number;
  clock_event_max: number;
  terminal_event_reservation_max: number;
  event_families: readonly ControlPlaneBudgetFamilyCeilingV02[];
  file_families: readonly ControlPlaneBudgetFamilyCeilingV02[];
}>;

type ControlPlaneBudgetResultV02 =
  | Readonly<{ ok: true; value: ControlPlaneBudgetDerivationV02 }>
  | Readonly<{ ok: false; reason: ControlPlaneBudgetDerivationErrorV02; message: string }>;

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

function invalid(message: string): ControlPlaneBudgetResultV02 {
  return { ok: false, reason: "CONTROL_PLANE_BUDGET_CONTRACT_INVALID", message };
}

function overflow(): ControlPlaneBudgetResultV02 {
  return { ok: false, reason: "CONTROL_PLANE_BUDGET_OVERFLOW", message: "Control-plane budget arithmetic exceeds the non-negative safe-integer domain." };
}

function toBigInt(value: number): bigint | null {
  return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
}

function toSafeNumber(value: bigint): number | null {
  return value >= 0n && value <= MAX_SAFE ? Number(value) : null;
}

function makeRow(family: string, cardinality: bigint, maxBytes: number): ControlPlaneBudgetFamilyCeilingV02 | null {
  const count = toSafeNumber(cardinality);
  return count === null ? null : Object.freeze({ family, cardinality: count, max_bytes: maxBytes });
}

function expectedRecordLimits(A: bigint, G: bigint, E: bigint, R: bigint, S: bigint, C: bigint): Readonly<Record<keyof RuntimeRecordLimitsInputV02, bigint>> {
  const evidence = 8n * A + 12n * G + 4n * E + 2n * R + 32n;
  return {
    max_authority_records: 9n * A + 10n * G,
    max_agency_recommendation_records: 8n * (2n * A + C),
    max_authority_revocation_records: A + 2n * G,
    max_evidence_records: evidence,
    max_task_result_records: A,
    max_manual_observation_records: evidence,
    max_export_decision_records: R + evidence,
    max_claim_records: S + G + E,
    max_finding_records: 4n * A + 2n * G + 2n * E + 2n * R + 32n,
    max_waiver_records: G,
    max_preseal_custody_events: 2n * (R + evidence),
  };
}

function charge(rows: readonly ControlPlaneBudgetFamilyCeilingV02[]): bigint {
  return rows.reduce((sum, row) => sum + BigInt(row.cardinality) * BigInt(row.max_bytes), 0n);
}

export function deriveControlPlaneBudgetV02(input: ControlPlaneBudgetInputV02): ControlPlaneBudgetResultV02 {
  const counts = {
    G: toBigInt(input.gates.length), E: toBigInt(input.evaluations.length),
    R: toBigInt(input.artifacts.length), S: toBigInt(input.goal.success_criteria.length),
    C: toBigInt(input.compensations.length), P: toBigInt(input.progress.observations.length),
    T: toBigInt(input.limit_policy.max_loop_attempts), tools: toBigInt(input.limit_policy.max_tool_calls),
    reserve: toBigInt(input.limit_policy.control_plane_output_reserve_bytes),
  };
  if (Object.values(counts).some((value) => value === null)) {
    return invalid("Control-plane limits and collection cardinalities must be non-negative safe integers.");
  }
  const { G, E, R, S, C, P, T, tools, reserve } = counts as Record<keyof typeof counts, bigint>;

  const retryByTask = new Map<string, bigint>();
  for (const rule of input.retry_policy.rules) {
    const maximum = toBigInt(rule.max_task_executions);
    if (maximum === null || maximum < 1n) return invalid("Every retry maximum must be a positive safe integer.");
    const current = retryByTask.get(rule.task_ref) ?? 0n;
    if (maximum > current) retryByTask.set(rule.task_ref, maximum);
  }
  let A = 0n;
  for (const task of input.tasks) {
    const maximum = retryByTask.get(task.id);
    if (maximum === undefined) return invalid(`Task ${task.id} has no retry maximum.`);
    A += maximum;
  }

  const expected = expectedRecordLimits(A, G, E, R, S, C);
  for (const [key, value] of Object.entries(expected) as [keyof RuntimeRecordLimitsInputV02, bigint][]) {
    const supplied = toBigInt(input.runtime_record_limits[key]);
    if (supplied === null || supplied !== value) {
      return invalid("Runtime record limits do not match the frozen S35 plan-derived formulas.");
    }
  }

  const taskIds = new Set(input.tasks.map(({ id }) => id));
  const effectRows = new Map<string, number>();
  for (const row of input.side_effects) {
    if (!taskIds.has(row.task_id) || effectRows.has(row.task_id) || row.effects.length < 1) {
      return invalid("Side-effect rows must name each task exactly once with at least one effect.");
    }
    effectRows.set(row.task_id, row.effects.length);
  }
  let F = 0n;
  for (const task of input.tasks) {
    const effectCount = effectRows.get(task.id);
    if (effectCount === undefined) return invalid(`Task ${task.id} has no side-effect row.`);
    F += BigInt(effectCount) * retryByTask.get(task.id)!;
  }

  const D = 2n * A + C;
  const terminalReservation = C === 0n ? 8n : 15n + 2n * C;
  const L = CONTROL_PLANE_BYTE_CEILINGS_V02;
  const rawNonClock = [
    ["initialize", 1n, L.ledger_standard],
    ["fence-advances-plus-abort", A + 3n, L.ledger_standard],
    ["gate-required-results", 2n * G, L.ledger_standard],
    ["evaluation-required-results", 2n * E, L.ledger_standard],
    ["authority-events", 26n * A + 13n * G + 8n * C, L.ledger_authority],
    ["policy-decisions", D, L.ledger_authority],
    ["evidence-recorded", expected.max_evidence_records, L.ledger_standard],
    ["manual-observations", expected.max_manual_observation_records, L.ledger_standard],
    ["export-decisions", expected.max_export_decision_records, L.ledger_standard],
    ["claims-findings", expected.max_claim_records + expected.max_finding_records, L.ledger_standard],
    ["action-lifecycle", 7n * A, L.ledger_standard],
    ["tool-admission", tools, L.ledger_standard],
    ["artifact-write-record", 2n * R, L.ledger_standard],
    ["prospective-limit-blocks", C + 1n, L.ledger_standard],
    ["effect-outcomes", F, L.ledger_standard],
    ["preseal-redaction-custody", expected.max_preseal_custody_events, L.ledger_standard],
    ["task-progress-facts", A, L.ledger_standard],
    ["progress-attempt-boundaries", T * (P + 1n), L.ledger_standard],
    ["terminal-freeze", 7n, L.ledger_standard],
    ["compensation-requests", C === 0n ? 0n : C + 3n, L.ledger_standard],
    ["compensation-phase-escalation", C === 0n ? 0n : 4n, L.ledger_standard],
    ["compensation-settlements", C, L.ledger_standard],
    ["terminal-seal", 1n, L.ledger_standard],
  ] as const;
  const K = rawNonClock.reduce((sum, [, cardinality]) => sum + cardinality, 0n);
  const clocks = 2n * A + G + K;
  const rawEvents = [rawNonClock[0], ["clocks", clocks, L.ledger_standard] as const, ...rawNonClock.slice(1)];
  const rawFiles = [
    ["authority-records", expected.max_authority_records, L.record_authority],
    ["agency-recommendation-records", expected.max_agency_recommendation_records, L.record_authority],
    ["authority-revocation-records", expected.max_authority_revocation_records, L.record_authority],
    ["evidence-records", expected.max_evidence_records, L.record_standard],
    ["task-result-records", expected.max_task_result_records, L.record_standard],
    ["manual-observation-records", expected.max_manual_observation_records, L.record_standard],
    ["export-decision-records", expected.max_export_decision_records, L.record_standard],
    ["claim-records", expected.max_claim_records, L.record_standard],
    ["finding-records", expected.max_finding_records, L.record_standard],
    ["waiver-records", expected.max_waiver_records, L.record_standard],
    ["gate-result-records", G, L.record_standard],
    ["evaluation-result-records", E, L.record_standard],
    ["artifact-records", R, L.record_standard],
    ["redaction-derivative-records", expected.max_preseal_custody_events / 2n, L.record_standard],
    ["runtime-manifests", 2n, L.manifest],
    ["final-report-projections", 3n, L.report],
  ] as const;

  const eventFamilies = rawEvents.map(([name, cardinality, maximum]) => makeRow(name, cardinality, maximum));
  const fileFamilies = rawFiles.map(([name, cardinality, maximum]) => makeRow(name, cardinality, maximum));
  if ([...eventFamilies, ...fileFamilies].some((row) => row === null)) return overflow();
  const events = Object.freeze(eventFamilies as ControlPlaneBudgetFamilyCeilingV02[]);
  const files = Object.freeze(fileFamilies as ControlPlaneBudgetFamilyCeilingV02[]);
  const required = charge(events) + charge(files);
  const requiredNumber = toSafeNumber(required);
  const KNumber = toSafeNumber(K);
  const clockNumber = toSafeNumber(clocks);
  const terminalNumber = toSafeNumber(terminalReservation);
  if (requiredNumber === null || KNumber === null || clockNumber === null || terminalNumber === null) return overflow();
  if (required > reserve) {
    return {
      ok: false,
      reason: "CONTROL_PLANE_BUDGET_EXCEEDS_RESERVE",
      message: `Required control-plane output ${requiredNumber} bytes exceeds reserve ${reserve} bytes.`,
    };
  }
  return {
    ok: true,
    value: Object.freeze({
      required_control_plane_output_bytes: requiredNumber,
      k_non_clock_primary_event_max: KNumber,
      clock_event_max: clockNumber,
      terminal_event_reservation_max: terminalNumber,
      event_families: events,
      file_families: files,
    }),
  };
}

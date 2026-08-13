import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CONTROL_PLANE_BYTE_CEILINGS_V02,
  CONTROL_PLANE_CHARGE_PROFILE_V02,
  deriveControlPlaneBudgetV02,
} from "../../src/compiler/control-plane-budget-v02.js";
import { hashCanonical } from "../../src/hash.js";
import { ArtifactRecordV02, RunInitializedEventV02 } from "../../src/schema/runtime.js";
import { validateRuntimeLedgerV02 } from "../../src/run/runtime-ledger-v02.js";
import {
  S35_CONTROL_PLANE_FAMILY_CEILINGS,
  deriveControlPlaneBudgetOracleS35,
  expectedRuntimeRecordLimitsOracleS35,
} from "../helpers/control-plane-budget-oracle-s35.js";
import { appendWorkActionAdmissionEvents, type RuntimeLedgerEventV02 } from "../helpers/runtime-admission-fixture-s35.js";

const HASH = `sha256:${"a".repeat(64)}`;

function runtimeSchemaInventory(): Record<string, "0.2"> {
  return {
    resolved_run_plan: "0.2", ledger_event: "0.2", run_manifest: "0.2", artifact_manifest: "0.2",
    redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
    agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2", manual_observation: "0.2",
    export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2", evaluation_result: "0.2",
    claim: "0.2", finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2",
  };
}

function blockedHistory(count: number): RuntimeLedgerEventV02[] {
  const events: RuntimeLedgerEventV02[] = [];
  const add = (eventType: string, payload: Record<string, unknown>, source: string, authority: string | null): void => {
    const previous = events.at(-1);
    const preimage = {
      schema_version: "0.2", event_id: `event_${events.length + 1}`, run_id: "run_budget",
      sequence: events.length + 1, recorded_at: "2026-08-10T12:00:00Z", event_type: eventType,
      source, authority_ref: authority, risk_tier: "T2", related_ids: [], previous_event_hash: previous?.event_hash ?? null,
      payload,
    };
    events.push({ ...preimage, event_hash: hashCanonical(preimage) });
  };
  add("run.initialized", { plan_hash: HASH, initial_fence_epoch: 0, runtime_schema_versions: runtimeSchemaInventory() }, "kernel", null);
  for (let index = 0; index < count; index += 1) {
    add("limit.admission-blocked", {
      request_id: `request_${index + 1}`, task_ref: "task-a", phase: "work", compensation_ref: null,
      request_kind: "action", request_hash: HASH,
      violations: [{ limit_ref: "max-output-bytes", consumed: 10, requested: 1, ceiling: 10 }],
    }, "policy-enforcement-point", "pep_1");
  }
  return events;
}

function budgetFixture(compensationCount: number, reserveBytes = 5_000_000_000) {
  const tasks = Array.from({ length: 3 }, (_, index) => ({ id: `task-${index + 1}` }));
  const retryRules = tasks.flatMap((task, index) => [
    { task_ref: task.id, max_task_executions: index + 2 },
    { task_ref: task.id, max_task_executions: 1 },
  ]);
  const A = 2 + 3 + 4;
  const G = 2;
  const E = 3;
  const R = 2;
  const S = 2;
  return {
    goal: { success_criteria: Array.from({ length: S }, (_, index) => ({ id: `criterion-${index + 1}` })) },
    tasks,
    gates: Array.from({ length: G }, (_, index) => ({ id: `gate-${index + 1}` })),
    evaluations: Array.from({ length: E }, (_, index) => ({ id: `evaluation-${index + 1}` })),
    artifacts: Array.from({ length: R }, (_, index) => ({ id: `artifact-${index + 1}` })),
    progress: { observations: [{ id: "progress-1" }, { id: "progress-2" }] },
    compensations: Array.from({ length: compensationCount }, (_, index) => ({ id: `compensation-${index + 1}` })),
    side_effects: tasks.map((task, index) => ({
      task_id: task.id,
      effects: Array.from({ length: index + 1 }, (_, effectIndex) => ({ effect_id: `effect-${task.id}-${effectIndex + 1}` })),
    })),
    retry_policy: { rules: retryRules },
    runtime_record_limits: expectedRuntimeRecordLimitsOracleS35(A, G, E, R, S, compensationCount),
    limit_policy: { max_loop_attempts: 5, max_tool_calls: 11, control_plane_output_reserve_bytes: reserveBytes },
  };
}

describe("S35 control-plane budget ledger history", () => {
  it("accepts the sole durable prospective block for a work phase", () => {
    expect(validateRuntimeLedgerV02(blockedHistory(1)).ok).toBe(true);
  });

  it("rejects a second admission block in the same work phase", () => {
    const result = validateRuntimeLedgerV02(blockedHistory(2));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("LEDGER_HISTORY_INVALID");
  });

  it("rejects admitting work action after limit block for that phase", () => {
    const result = validateRuntimeLedgerV02(appendWorkActionAdmissionEvents(blockedHistory(1)).events);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason, JSON.stringify(result.issues)).toBe("LEDGER_HISTORY_INVALID");
      expect(result.issues[0]!.message).toBe("No action may be admitted after its phase has recorded a limit block.");
    }
  });
});

describe("S35 control-plane budget calculator", () => {
  it("uses the immutable registered ceiling profile", () => {
    expect(CONTROL_PLANE_CHARGE_PROFILE_V02).toBe("control-plane-charge-ceilings-v02-s35-1");
    expect(CONTROL_PLANE_BYTE_CEILINGS_V02).toEqual(S35_CONTROL_PLANE_FAMILY_CEILINGS);
  });

  it("matches an independent formula and family inventory", () => {
    const fixture = budgetFixture(0);
    const oracle = deriveControlPlaneBudgetOracleS35(fixture);
    const production = deriveControlPlaneBudgetV02(fixture);
    expect(oracle.ok).toBe(true);
    expect(production.ok).toBe(true);
    if (!oracle.ok || !production.ok) return;
    expect(production.value).toEqual(oracle.value);
    expect(production.value.event_families).toHaveLength(24);
    expect(production.value.file_families).toHaveLength(16);
  });

  it("accepts an exact reserve and rejects one byte less", () => {
    const provisional = deriveControlPlaneBudgetOracleS35(budgetFixture(0));
    expect(provisional.ok).toBe(true);
    if (!provisional.ok) return;
    const required = provisional.value.required_control_plane_output_bytes;
    expect(deriveControlPlaneBudgetV02(budgetFixture(0, required)).ok).toBe(true);
    const short = deriveControlPlaneBudgetV02(budgetFixture(0, required - 1));
    expect(short).toMatchObject({ ok: false, reason: "CONTROL_PLANE_BUDGET_EXCEEDS_RESERVE" });
  });

  it("rejects record-limit drift and arithmetic overflow", () => {
    const fixture = budgetFixture(0);
    const drifted = {
      ...fixture,
      runtime_record_limits: { ...fixture.runtime_record_limits, max_claim_records: fixture.runtime_record_limits.max_claim_records + 1 },
    };
    expect(deriveControlPlaneBudgetV02(drifted)).toMatchObject({ ok: false, reason: "CONTROL_PLANE_BUDGET_CONTRACT_INVALID" });
    const overflowing = {
      ...fixture,
      limit_policy: { ...fixture.limit_policy, max_tool_calls: Number.MAX_SAFE_INTEGER, control_plane_output_reserve_bytes: Number.MAX_SAFE_INTEGER },
    };
    expect(deriveControlPlaneBudgetV02(overflowing)).toMatchObject({ ok: false, reason: "CONTROL_PLANE_BUDGET_OVERFLOW" });
  });

  it("enforces free-string and related-ID boundaries in exported runtime schemas", () => {
    const related = Array.from({ length: 256 }, (_, index) => `related-${index.toString().padStart(3, "0")}`);
    const initialized = {
      schema_version: "0.2", event_id: "event_1", run_id: "run_1", sequence: 1,
      recorded_at: "2026-08-12T12:00:00Z", source: "kernel", authority_ref: null,
      risk_tier: "T2", related_ids: related, previous_event_hash: null, event_hash: HASH,
      event_type: "run.initialized", payload: { plan_hash: HASH, initial_fence_epoch: 0, runtime_schema_versions: runtimeSchemaInventory() },
    };
    expect(RunInitializedEventV02.safeParse(initialized).success).toBe(true);
    expect(RunInitializedEventV02.safeParse({ ...initialized, related_ids: [...related, "related-256"] }).success).toBe(false);
    expect(RunInitializedEventV02.safeParse({ ...initialized, related_ids: ["a".repeat(16_385)] }).success).toBe(false);

    const artifact = {
      schema_version: "0.2", artifact_ref: "artifact-main", run_id: "run_1", plan_hash: HASH,
      producer_task_ref: "task-main", producer_action_id: "action_1",
      write_admission_ref: { ledger_sequence: 1, event_hash: HASH }, artifact_path: "artifacts/output.txt",
      content_hash: HASH, size_bytes: 1, media_type: "a".repeat(16_384), record_hash: HASH,
    };
    expect(ArtifactRecordV02.safeParse(artifact).success).toBe(true);
    expect(ArtifactRecordV02.safeParse({ ...artifact, media_type: "a".repeat(16_385) }).success).toBe(false);
  });

  it("keeps the oracle isolated from production calculator and hash helpers", () => {
    const source = readFileSync(resolve("tests/helpers/control-plane-budget-oracle-s35.ts"), "utf8");
    expect(source).not.toContain("control-plane-budget-v02");
    expect(source).not.toContain("../../src/hash.js");
    expect(source).not.toContain("witness_bytes");
  });
});

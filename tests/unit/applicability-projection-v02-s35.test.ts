import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import {
  ResolvedRunPlanV02,
  RuntimeEventV02,
  type RuntimeEventV02Value,
} from "../../src/schema/runtime.js";
import { projectApplicabilityAndDueV02 } from "../../src/run/applicability-projection-v02.js";

const PLAN = ResolvedRunPlanV02.parse(JSON.parse(readFileSync(join(
  process.cwd(),
  "tests/fixtures/compat/s35/v02/planned-run/resolved-run-plan.json",
), "utf8")));

const RUNTIME_SCHEMA_VERSIONS = {
  resolved_run_plan: "0.2",
  ledger_event: "0.2",
  run_manifest: "0.2",
  artifact_manifest: "0.2",
  redaction_derivative: "0.2",
  evidence_item: "0.2",
  human_authorization_proof: "0.2",
  authority_envelope: "0.2",
  agency_recommendation: "0.2",
  authority_revocation: "0.2",
  task_result: "0.2",
  manual_observation: "0.2",
  export_decision: "0.2",
  gate_result: "0.2",
  evaluation_result: "0.2",
  claim: "0.2",
  finding: "0.2",
  waiver: "0.2",
  gate_waiver_authority: "0.2",
} as const;

function appendEvent(
  events: RuntimeEventV02Value[],
  eventType: RuntimeEventV02Value["event_type"],
  source: RuntimeEventV02Value["source"],
  payload: Record<string, unknown>,
): RuntimeEventV02Value {
  const previous = events.at(-1);
  const preimage = {
    schema_version: "0.2",
    event_id: `event_projection_${events.length + 1}`,
    run_id: PLAN.run_id,
    sequence: events.length + 1,
    recorded_at: `2026-08-12T12:00:${String(events.length).padStart(2, "0")}Z`,
    event_type: eventType,
    source,
    authority_ref: null,
    risk_tier: "T2",
    related_ids: [],
    previous_event_hash: previous?.event_hash ?? null,
    payload,
  };
  const event = RuntimeEventV02.parse({ ...preimage, event_hash: hashCanonical(preimage) });
  events.push(event);
  return event;
}

function initializedEvents(): RuntimeEventV02Value[] {
  const events: RuntimeEventV02Value[] = [];
  appendEvent(events, "run.initialized", "kernel", {
    plan_hash: `sha256:${"1".repeat(64)}`,
    initial_fence_epoch: 0,
    runtime_schema_versions: RUNTIME_SCHEMA_VERSIONS,
  });
  return events;
}

function ref(event: RuntimeEventV02Value) {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

describe("S35 V02 applicability and due projection", () => {
  it("keeps canonical plan order and does not invent due controls", () => {
    const projected = projectApplicabilityAndDueV02({
      plan: PLAN,
      events: [],
      phase: "work",
      active_compensation_refs: [],
    });

    expect(projected.ok).toBe(true);
    if (!projected.ok) return;
    expect(projected.value.gates.map(({ ref }) => ref)).toEqual(PLAN.gates.map(({ id }) => id));
    expect(projected.value.evaluations.map(({ ref }) => ref)).toEqual(PLAN.evaluations.map(({ id }) => id));
    expect(Object.isFrozen(projected.value)).toBe(true);
    expect(Object.isFrozen(projected.value.gates)).toBe(true);
    expect(Object.isFrozen(projected.value.evaluations)).toBe(true);
    expect(projected.value.gates).toEqual(PLAN.gates.map((gate) => expect.objectContaining({
      ref: gate.id,
      applicable: true,
      due: false,
      status: "missing",
      required_event_ref: null,
      result_event_ref: null,
    })));
    expect(projected.value.evaluations).toEqual(PLAN.evaluations.map((evaluation) => expect.objectContaining({
      ref: evaluation.id,
      applicable: true,
      due: false,
      status: "missing",
      required_event_ref: null,
      result_event_ref: null,
    })));
  });

  it("makes a gate due only from its exact prerequisite-bound requirement and projects PASS lineage", () => {
    const events = initializedEvents();
    const gate = PLAN.gates[0]!;
    const required = appendEvent(events, "gate.result-required", "kernel", {
      gate_ref: gate.id,
      requirement_revision: 1,
      applicability: "always",
      compensation_ref: null,
      prerequisite_set_hash: hashCanonical(gate.prerequisites),
      prerequisite_refs: [ref(events[0]!)],
    });
    const result = appendEvent(events, "gate.result-recorded", "evaluator", {
      gate_ref: gate.id,
      result_id: "gate_result_projection_1",
      status: "PASS",
      evaluator_identity_ref: gate.evaluator_binding.evaluator_identity_ref,
      policy_digest: gate.evaluator_binding.policy_digest,
      record_path: `records/gates/${gate.id}.json`,
      record_hash: `sha256:${"2".repeat(64)}`,
      required_event_ref: ref(required),
      waiver_event_ref: null,
    });

    const projected = projectApplicabilityAndDueV02({
      plan: PLAN,
      events,
      phase: "work",
      active_compensation_refs: [],
    });

    expect(projected).toMatchObject({ ok: true });
    if (!projected.ok) return;
    expect(projected.value.gates[0]).toEqual({
      ref: gate.id,
      applicable: true,
      due: true,
      status: "pass",
      required_event_ref: ref(required),
      result_event_ref: ref(result),
      condition_evidence_refs: [ref(result)],
      waiver_active_at_use: null,
      waiver_use_event_refs: [],
    });
    expect(projectApplicabilityAndDueV02({
      plan: PLAN,
      events: [...events].reverse(),
      phase: "work",
      active_compensation_refs: [],
    })).toEqual(projected);
  });

  it("projects evaluation SKIPPED without treating it as success", () => {
    const events = initializedEvents();
    const evaluation = PLAN.evaluations[0]!;
    const required = appendEvent(events, "evaluation.result-required", "kernel", {
      evaluation_ref: evaluation.id,
      requirement_revision: 1,
      applicability: "always",
      compensation_ref: null,
      prerequisite_set_hash: hashCanonical(evaluation.prerequisites),
      prerequisite_refs: [ref(events[0]!)],
    });
    const result = appendEvent(events, "evaluation.result-recorded", "evaluator", {
      evaluation_ref: evaluation.id,
      result_id: "evaluation_result_projection_1",
      status: "SKIPPED",
      evaluator_identity_ref: evaluation.evaluator_binding.evaluator_identity_ref,
      policy_digest: evaluation.evaluator_binding.policy_digest,
      export_check_role: evaluation.evaluator_binding.export_check_role,
      record_path: `records/evaluations/${evaluation.id}.json`,
      record_hash: `sha256:${"3".repeat(64)}`,
      required_event_ref: ref(required),
    });

    const projected = projectApplicabilityAndDueV02({
      plan: PLAN,
      events,
      phase: "work",
      active_compensation_refs: [],
    });

    expect(projected).toMatchObject({ ok: true });
    if (projected.ok) expect(projected.value.evaluations[0]).toMatchObject({
      due: true,
      status: "skipped",
      required_event_ref: ref(required),
      result_event_ref: ref(result),
    });
  });

  it("fails closed when a result has no requirement or plan-bound evaluator identity", () => {
    const gate = PLAN.gates[0]!;
    const withoutRequirement = initializedEvents();
    appendEvent(withoutRequirement, "gate.result-recorded", "evaluator", {
      gate_ref: gate.id,
      result_id: "gate_result_without_requirement",
      status: "PASS",
      evaluator_identity_ref: gate.evaluator_binding.evaluator_identity_ref,
      policy_digest: gate.evaluator_binding.policy_digest,
      record_path: `records/gates/${gate.id}.json`,
      record_hash: `sha256:${"4".repeat(64)}`,
      required_event_ref: ref(withoutRequirement[0]!),
      waiver_event_ref: null,
    });
    expect(projectApplicabilityAndDueV02({
      plan: PLAN,
      events: withoutRequirement,
      phase: "work",
      active_compensation_refs: [],
    })).toEqual({ ok: false, error: "APPLICABILITY_OR_DUE_INVALID" });

    const wrongIdentity = initializedEvents();
    const required = appendEvent(wrongIdentity, "gate.result-required", "kernel", {
      gate_ref: gate.id,
      requirement_revision: 1,
      applicability: "always",
      compensation_ref: null,
      prerequisite_set_hash: hashCanonical(gate.prerequisites),
      prerequisite_refs: [ref(wrongIdentity[0]!)],
    });
    appendEvent(wrongIdentity, "gate.result-recorded", "evaluator", {
      gate_ref: gate.id,
      result_id: "gate_result_wrong_identity",
      status: "PASS",
      evaluator_identity_ref: "evaluator_wrong",
      policy_digest: gate.evaluator_binding.policy_digest,
      record_path: `records/gates/${gate.id}.json`,
      record_hash: `sha256:${"5".repeat(64)}`,
      required_event_ref: ref(required),
      waiver_event_ref: null,
    });
    expect(projectApplicabilityAndDueV02({
      plan: PLAN,
      events: wrongIdentity,
      phase: "work",
      active_compensation_refs: [],
    })).toEqual({ ok: false, error: "APPLICABILITY_OR_DUE_INVALID" });
  });

  it("fails closed on stale prerequisite lineage and duplicate requirement rows", () => {
    const gate = PLAN.gates[0]!;
    const stale = initializedEvents();
    appendEvent(stale, "gate.result-required", "kernel", {
      gate_ref: gate.id,
      requirement_revision: 1,
      applicability: "always",
      compensation_ref: null,
      prerequisite_set_hash: hashCanonical(gate.prerequisites),
      prerequisite_refs: [{ ledger_sequence: 1, event_hash: `sha256:${"0".repeat(64)}` }],
    });
    expect(projectApplicabilityAndDueV02({
      plan: PLAN,
      events: stale,
      phase: "work",
      active_compensation_refs: [],
    })).toEqual({ ok: false, error: "APPLICABILITY_OR_DUE_INVALID" });

    const duplicate = initializedEvents();
    const payload = {
      gate_ref: gate.id,
      requirement_revision: 1,
      applicability: "always",
      compensation_ref: null,
      prerequisite_set_hash: hashCanonical(gate.prerequisites),
      prerequisite_refs: [ref(duplicate[0]!)],
    };
    appendEvent(duplicate, "gate.result-required", "kernel", payload);
    appendEvent(duplicate, "gate.result-required", "kernel", payload);
    expect(projectApplicabilityAndDueV02({
      plan: PLAN,
      events: duplicate,
      phase: "work",
      active_compensation_refs: [],
    })).toEqual({ ok: false, error: "APPLICABILITY_OR_DUE_INVALID" });
  });

  it("keeps a compensation control inapplicable until its exact sticky ref activates", () => {
    const compensationGate = {
      ...PLAN.gates[0]!,
      applicability: { mode: "compensation" as const, compensation_ref: "restore-workspace" },
    };
    const plan = { ...PLAN, gates: [compensationGate, ...PLAN.gates.slice(1)] };

    const inactive = projectApplicabilityAndDueV02({
      plan,
      events: [],
      phase: "work",
      active_compensation_refs: [],
    });
    const active = projectApplicabilityAndDueV02({
      plan,
      events: [],
      phase: "compensation",
      active_compensation_refs: ["restore-workspace"],
    });

    expect(inactive).toMatchObject({ ok: true });
    expect(active).toMatchObject({ ok: true });
    if (!inactive.ok || !active.ok) return;
    expect(inactive.value.gates[0]).toMatchObject({
      applicable: false,
      due: false,
      status: "missing",
    });
    expect(active.value.gates[0]).toMatchObject({
      applicable: true,
      due: false,
      status: "missing",
    });

    const prematurelyRequired = initializedEvents();
    appendEvent(prematurelyRequired, "gate.result-required", "kernel", {
      gate_ref: compensationGate.id,
      requirement_revision: 1,
      applicability: "compensation",
      compensation_ref: "restore-workspace",
      prerequisite_set_hash: hashCanonical(compensationGate.prerequisites),
      prerequisite_refs: [ref(prematurelyRequired[0]!)],
    });
    expect(projectApplicabilityAndDueV02({
      plan,
      events: prematurelyRequired,
      phase: "work",
      active_compensation_refs: [],
    })).toEqual({ ok: false, error: "APPLICABILITY_OR_DUE_INVALID" });
  });
});

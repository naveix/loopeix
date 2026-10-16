import { describe, expect, it } from "vitest";
import { hashCanonical } from "../../src/hash.js";
import { validateRuntimeLedgerV02 } from "../../src/run/runtime-ledger-v02.js";

const HASH = `sha256:${"a".repeat(64)}`;
type Event = Record<string, unknown> & { event_hash: string };

function base(): Event[] {
  const events: Event[] = [];
  add(events, "run.initialized", {
    plan_hash: HASH, initial_fence_epoch: 0,
    runtime_schema_versions: {
      resolved_run_plan: "0.2", ledger_event: "0.2", run_manifest: "0.2", artifact_manifest: "0.2",
      redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
      agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2", manual_observation: "0.2",
      export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2", evaluation_result: "0.2",
      claim: "0.2", finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2",
    },
  }, "kernel");
  return events;
}

function add(events: Event[], eventType: string, payload: Record<string, unknown>, source = "kernel"): void {
  const previous = events.at(-1);
  const preimage = {
    schema_version: "0.2", event_id: `event_${events.length + 1}`, run_id: "run_gate",
    sequence: events.length + 1, recorded_at: "2026-08-10T12:00:00Z", event_type: eventType,
    source, authority_ref: null, risk_tier: "T2", related_ids: [], previous_event_hash: previous?.event_hash ?? null,
    payload,
  };
  events.push({ ...preimage, event_hash: hashCanonical(preimage) });
}

function requiredPayload(kind: "gate" | "evaluation", ref: string, first: Event): Record<string, unknown> {
  return {
    [`${kind}_ref`]: ref, requirement_revision: 1, applicability: "always", compensation_ref: null,
    prerequisite_set_hash: HASH, prerequisite_refs: [{ ledger_sequence: 1, event_hash: first.event_hash }],
  };
}

describe("S35 gate and evaluation history", () => {
  it("accepts one required row per distinct gate and evaluation", () => {
    const events = base();
    add(events, "gate.result-required", requiredPayload("gate", "gate-a", events[0]!));
    add(events, "evaluation.result-required", requiredPayload("evaluation", "evaluation-a", events[0]!));
    expect(validateRuntimeLedgerV02(events).ok).toBe(true);
  });

  it.each(["gate", "evaluation"] as const)("rejects a duplicate %s required row", (kind) => {
    const events = base();
    const eventType = `${kind}.result-required`;
    const payload = requiredPayload(kind, `${kind}-a`, events[0]!);
    add(events, eventType, payload);
    add(events, eventType, payload);
    const result = validateRuntimeLedgerV02(events);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("LEDGER_HISTORY_INVALID");
  });
});

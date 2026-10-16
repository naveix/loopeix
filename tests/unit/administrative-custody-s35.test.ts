import { describe, expect, it } from "vitest";
import { hashCanonical } from "../../src/hash.js";
import { validateRuntimeLedgerV02 } from "../../src/run/runtime-ledger-v02.js";

const HASH = `sha256:${"a".repeat(64)}`;

function eventsWithCustody(count: number): unknown[] {
  const events: Array<Record<string, unknown> & { event_hash: string }> = [];
  const add = (eventType: string, payload: Record<string, unknown>): void => {
    const previous = events.at(-1);
    const preimage = {
      schema_version: "0.2", event_id: `event_${events.length + 1}`, run_id: "run_custody",
      sequence: events.length + 1, recorded_at: "2026-08-10T12:00:00Z", event_type: eventType,
      source: "kernel", authority_ref: null, risk_tier: "T2", related_ids: [],
      previous_event_hash: previous?.event_hash ?? null, payload,
    };
    events.push({ ...preimage, event_hash: hashCanonical(preimage) });
  };
  add("run.initialized", {
    plan_hash: HASH, initial_fence_epoch: 0,
    runtime_schema_versions: {
      resolved_run_plan: "0.2", ledger_event: "0.2", run_manifest: "0.2", artifact_manifest: "0.2",
      redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
      agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2", manual_observation: "0.2",
      export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2", evaluation_result: "0.2",
      claim: "0.2", finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2",
    },
  });
  for (let index = 0; index < count; index += 1) {
    add("record.custody-state-recorded", {
      subject_kind: "artifact", subject_ref: "artifact-a", subject_hash: HASH, previous_state_event_ref: null,
      retention_class: "run", expires_at: null, quarantine_status: "clear", quarantine_reason: null,
      integrity_status: "valid", integrity_finding_refs: [], export_state: "not-exportable",
      export_reason: "no-current-decision", export_decision_event_ref: null, policy_version: "policy-v1", evidence_refs: [],
    });
  }
  return events;
}

describe("S35 administrative custody boundary", () => {
  it("accepts one immutable pre-seal custody state per subject", () => {
    expect(validateRuntimeLedgerV02(eventsWithCustody(1)).ok).toBe(true);
  });

  it("rejects a second primary-ledger custody state for the same subject", () => {
    const result = validateRuntimeLedgerV02(eventsWithCustody(2));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("LEDGER_HISTORY_INVALID");
  });
});

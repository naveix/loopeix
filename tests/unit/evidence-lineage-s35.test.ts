import { describe, expect, it } from "vitest";
import { hashCanonical } from "../../src/hash.js";
import { validateRuntimeLedgerV02 } from "../../src/run/runtime-ledger-v02.js";

const HASH = `sha256:${"a".repeat(64)}`;

describe("S35 evidence lineage history", () => {
  it("rejects duplicate manual-observation record identity", () => {
    const inventory = {
      resolved_run_plan: "0.2", ledger_event: "0.2", run_manifest: "0.2", artifact_manifest: "0.2",
      redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2", agency_recommendation: "0.2",
      authority_revocation: "0.2", task_result: "0.2", manual_observation: "0.2", export_decision: "0.2",
      evidence_item: "0.2", gate_result: "0.2", evaluation_result: "0.2", claim: "0.2", finding: "0.2",
      waiver: "0.2", gate_waiver_authority: "0.2",
    };
    const events: Array<Record<string, unknown> & { event_hash: string }> = [];
    const add = (eventType: string, payload: Record<string, unknown>, source: string, authority: string | null): void => {
      const previous = events.at(-1);
      const preimage = {
        schema_version: "0.2", event_id: `event_${events.length + 1}`, run_id: "run_evidence", sequence: events.length + 1,
        recorded_at: "2026-08-10T12:00:00Z", event_type: eventType, source, authority_ref: authority,
        risk_tier: "T2", related_ids: [], previous_event_hash: previous?.event_hash ?? null, payload,
      };
      events.push({ ...preimage, event_hash: hashCanonical(preimage) });
    };
    add("run.initialized", { plan_hash: HASH, initial_fence_epoch: 0, runtime_schema_versions: inventory }, "kernel", null);
    const observation = {
      observation_id: "observation_1", record_path: "evidence/observation_1.json", record_hash: HASH,
      run_id: "run_evidence", authenticated_principal_ref: "principal_1", subject_hash: HASH,
      observation_scope_hash: HASH, observed_at: "2026-08-10T12:00:00Z", limitations: [],
    };
    add("observation.manual-recorded", observation, "operator", "principal_1");
    add("observation.manual-recorded", observation, "operator", "principal_1");
    const result = validateRuntimeLedgerV02(events);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("LEDGER_HISTORY_INVALID");
  });
});

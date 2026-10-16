import { describe, expect, it } from "vitest";
import { hashCanonical } from "../../src/hash.js";
import { validateRuntimeLedgerV02 } from "../../src/run/runtime-ledger-v02.js";

const HASH = `sha256:${"a".repeat(64)}`;
const inventory = {
  resolved_run_plan: "0.2", ledger_event: "0.2", run_manifest: "0.2", artifact_manifest: "0.2",
  redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
  agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2", manual_observation: "0.2",
  export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2", evaluation_result: "0.2",
  claim: "0.2", finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2",
};

function seal(preimage: Record<string, unknown>): Record<string, unknown> & { event_hash: string } {
  return { ...preimage, event_hash: hashCanonical(preimage) };
}

describe("S35 action admission and quiescence history", () => {
  it("rejects a tool admission that has no matching unsettled action admission", () => {
    const first = seal({
      schema_version: "0.2", event_id: "event_1", run_id: "run_action", sequence: 1,
      recorded_at: "2026-08-10T12:00:00Z", event_type: "run.initialized", source: "kernel",
      authority_ref: null, risk_tier: "T2", related_ids: [], previous_event_hash: null,
      payload: { plan_hash: HASH, initial_fence_epoch: 0, runtime_schema_versions: inventory },
    });
    const second = seal({
      schema_version: "0.2", event_id: "event_2", run_id: "run_action", sequence: 2,
      recorded_at: "2026-08-10T12:00:01Z", event_type: "tool.call-admitted", source: "policy-enforcement-point",
      authority_ref: "pep_1", risk_tier: "T2", related_ids: [], previous_event_hash: first.event_hash,
      payload: { tool_call_id: "tool_call_1", action_id: "action_1", task_ref: "task-a", tool_grant_ref: "tool-a", fence_epoch: 0, tool_calls_after: 1 },
    });
    const result = validateRuntimeLedgerV02([first, second]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("LEDGER_HISTORY_INVALID");
  });
});

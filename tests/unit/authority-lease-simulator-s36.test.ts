import { describe, expect, it } from "vitest";
import { simulateAuthorityDecisionV02, revalidateSimulatedAuthorityLeaseV02, S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";

const H = `sha256:${"a".repeat(64)}`;
const input = {
  proposal: { action_proposal_id: "proposal_1", action_proposal_hash: H, action_class: "task", policy_action_kind: "planning", action_approval_class: "automatic", policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02, action_scope_hash: H, normalized_dispatch_hash: H, repository_pre_state_hash: H, classifier_rule_hash: H, data_flow_hash: H, effective_risk_tier: "T1" },
  reviewer_view_hash: H, reviewed_through_ref: { ledger_sequence: 1, event_hash: H }, recommendations: [],
  authority: { envelope_verified: true, contained: true, proof_fresh: true, revocation_epoch_current: true },
  enforcement: { available: true, information_flow_allowed: true, gates_passed: true, immediate_revalidation_passed: true },
  condition_results: [], issued_at: "2026-08-13T12:00:00Z", expires_at: "2026-08-13T12:01:00Z", fence_epoch: 0,
} as const;

describe("S36 in-memory simulated lease", () => {
  it("exposes exactly one deterministic non-durable slot only for lease-eligible allow", () => {
    const result = simulateAuthorityDecisionV02(input);
    expect(result).toMatchObject({ ok: true, value: { decision: "allow", simulated_lease: { durable: false, single_use_slot: 0 } } });
  });

  it("revalidates the exact invalidation fingerprint and rejects any relevant drift", () => {
    const result = simulateAuthorityDecisionV02(input);
    if (!result.ok || result.value.simulated_lease === null) throw new Error("lease fixture failed");
    expect(revalidateSimulatedAuthorityLeaseV02(result.value.simulated_lease, input)).toEqual({ ok: true });
    expect(revalidateSimulatedAuthorityLeaseV02(result.value.simulated_lease, { ...input, proposal: { ...input.proposal, repository_pre_state_hash: `sha256:${"b".repeat(64)}` } })).toMatchObject({ ok: false });
    expect(revalidateSimulatedAuthorityLeaseV02(result.value.simulated_lease, { ...input, enforcement: { ...input.enforcement, immediate_revalidation_passed: false } })).toMatchObject({ ok: false });
    expect(revalidateSimulatedAuthorityLeaseV02(result.value.simulated_lease, { ...input, reviewer_view_hash: `sha256:${"c".repeat(64)}` })).toMatchObject({ ok: false });
  });

  it("cannot be mistaken for the persisted lease event shape", () => {
    const result = simulateAuthorityDecisionV02(input);
    if (!result.ok) return;
    expect(result.value.simulated_lease).not.toHaveProperty("lease_id");
    expect(result.value.simulated_lease).not.toHaveProperty("policy_decision_ref");
    expect(result.value.simulated_lease).not.toHaveProperty("issued_at");
  });
});

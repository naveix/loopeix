import { describe, expect, it } from "vitest";
import { resolveAgencyQuorumRequirementV02, simulateAuthorityDecisionV02 } from "../../src/run/action-classifier-policy-v02.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";

const hash = (digit: string) => `sha256:${digit.repeat(64)}`;
const roles = ["authority-governor", "evidence-reviewer", "scope-guardian", "security-information-flow-reviewer"] as const;
const proposal = {
  action_proposal_id: "proposal_1", action_proposal_hash: hash("1"), action_class: "tool",
  policy_action_kind: "authenticated-read", action_approval_class: "agency",
  policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  action_scope_hash: hash("2"), normalized_dispatch_hash: hash("3"), repository_pre_state_hash: hash("4"),
  classifier_rule_hash: hash("5"), data_flow_hash: hash("6"), effective_risk_tier: "T2",
};
const prefix = { ledger_sequence: 10, event_hash: hash("7") };
const quorum = resolveAgencyQuorumRequirementV02({ policy_digest: proposal.policy_digest, action_class: proposal.action_class, policy_action_kind: proposal.policy_action_kind, action_approval_class: proposal.action_approval_class });
if (quorum === null) throw new Error("quorum fixture must resolve");
const recommendations = roles.map((role, index) => ({
  verified: true, event_ref: { ledger_sequence: 11 + index, event_hash: hash(String(index + 1)) },
  recommendation_id: `recommendation_${index}`, action_proposal_hash: proposal.action_proposal_hash, reviewer_view_hash: hash("8"),
  quorum_requirement_hash: quorum.quorum_requirement_hash, reviewed_through_ref: prefix, evaluator_role_ref: role,
  evaluator_stable_identity_hash: hash(String(index + 1)), decision: "allow",
  conditions: [], evidence_refs: [{ ledger_sequence: 1 + index, event_hash: hash(String(index + 1)) }],
  evidence_independence_keys: [hash(String(index + 5))], issued_at: "2026-08-13T12:00:00Z", expires_at: "2026-08-13T12:05:00Z",
}));
const base = {
  proposal, reviewer_view_hash: hash("8"), reviewed_through_ref: prefix, recommendations,
  authority: { envelope_verified: true, contained: true, proof_fresh: true, revocation_epoch_current: true },
  enforcement: { available: true, information_flow_allowed: true, gates_passed: true, immediate_revalidation_passed: true },
  condition_results: [], issued_at: "2026-08-13T12:02:00Z", expires_at: "2026-08-13T12:03:00Z", fence_epoch: 0,
};

describe("S36 pure authority decision point", () => {
  it("combines one exact independent required-role window into a deterministic allow", () => {
    const first = simulateAuthorityDecisionV02(base);
    const second = simulateAuthorityDecisionV02(structuredClone(base));
    expect(first).toEqual(second);
    expect(first).toMatchObject({ ok: true, value: { decision: "allow", decision_disposition: "lease-eligible" } });
    if (first.ok) expect(first.value.required_reviewer_role_refs).toEqual(roles);
  });

  it("applies abort, deny, and escalation precedence before allow", () => {
    for (const [decision, expected] of [["escalate", "escalate"], ["deny", "deny"], ["abort", "abort"]] as const) {
      const changed = structuredClone(base);
      changed.recommendations[0]!.decision = decision;
      expect(simulateAuthorityDecisionV02(changed)).toMatchObject({ ok: true, value: { decision: expected } });
    }
    const mixed = structuredClone(base);
    mixed.recommendations[0]!.decision = "escalate"; mixed.recommendations[1]!.decision = "deny"; mixed.recommendations[2]!.decision = "abort";
    expect(simulateAuthorityDecisionV02(mixed)).toMatchObject({ ok: true, value: { decision: "abort" } });
  });

  it("fails closed for missing role, duplicate root, stale recommendation, prefix mismatch, or enforcement failure", () => {
    const cases = [
      { ...structuredClone(base), recommendations: recommendations.slice(0, 3) },
      { ...structuredClone(base), recommendations: recommendations.map((row, index) => index === 1 ? { ...row, evaluator_stable_identity_hash: recommendations[0]!.evaluator_stable_identity_hash } : row) },
      { ...structuredClone(base), recommendations: recommendations.map((row, index) => index === 0 ? { ...row, expires_at: "2026-08-13T12:01:00Z" } : row) },
      { ...structuredClone(base), recommendations: recommendations.map((row, index) => index === 0 ? { ...row, reviewed_through_ref: { ledger_sequence: 9, event_hash: hash("8") } } : row) },
      { ...structuredClone(base), recommendations: base.recommendations.map((row, index) => index === 0 ? { ...row, reviewer_view_hash: hash("9") } : row) },
      { ...structuredClone(base), enforcement: { ...base.enforcement, available: false } },
    ];
    for (const candidate of cases) expect(simulateAuthorityDecisionV02(candidate)).toMatchObject({ ok: true, value: { decision: "hold", decision_disposition: "non-resumable", simulated_lease: null } });
  });

  it("never allows human-exception or blocked proposals", () => {
    expect(simulateAuthorityDecisionV02({ ...base, proposal: { ...proposal, policy_action_kind: "send", action_approval_class: "human_exception" }, recommendations: [] }))
      .toMatchObject({ ok: true, value: { decision: "hold", simulated_lease: null } });
    expect(simulateAuthorityDecisionV02({ ...base, proposal: { ...proposal, policy_action_kind: "self-widening", action_approval_class: "blocked" }, recommendations: [] }))
      .toMatchObject({ ok: true, value: { decision: "hold", simulated_lease: null } });
  });

  it("returns a policy-resolved HOLD when automatic enforcement is unavailable", () => {
    const automatic = {
      ...base,
      proposal: { ...proposal, action_class: "task", policy_action_kind: "planning", action_approval_class: "automatic" },
      recommendations: [], enforcement: { ...base.enforcement, available: false },
    };
    expect(simulateAuthorityDecisionV02(automatic)).toMatchObject({
      ok: true,
      value: { decision: "hold", decision_disposition: "non-resumable", simulated_lease: null,
        reason_codes: [{ declaration_ref: "decision-automatic-enforcement-hold" }] },
    });
  });
});

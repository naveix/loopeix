import { describe, expect, it } from "vitest";

import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  resolveAgencyQuorumRequirementV02,
  revalidateSimulatedAuthorityLeaseV02,
  simulateAuthorityDecisionV02,
} from "../../src/run/action-classifier-policy-v02.js";

const hash = (digit: string) => `sha256:${digit.repeat(64)}`;
const roles = ["authority-governor", "evidence-reviewer", "scope-guardian", "security-information-flow-reviewer"] as const;

function baseAgencyInput() {
  const proposal = {
    action_proposal_id: "proposal_1",
    action_proposal_hash: hash("1"),
    action_class: "tool" as const,
    policy_action_kind: "authenticated-read" as const,
    action_approval_class: "agency" as const,
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    action_scope_hash: hash("2"),
    normalized_dispatch_hash: hash("3"),
    repository_pre_state_hash: hash("4"),
    classifier_rule_hash: hash("5"),
    data_flow_hash: hash("6"),
    effective_risk_tier: "T2" as const,
  };
  const reviewed_through_ref = { ledger_sequence: 10, event_hash: hash("7") };
  const quorum = resolveAgencyQuorumRequirementV02({
    policy_digest: proposal.policy_digest,
    action_class: proposal.action_class,
    policy_action_kind: proposal.policy_action_kind,
    action_approval_class: proposal.action_approval_class,
  });
  if (quorum === null) throw new Error("agency quorum fixture must resolve");
  const recommendations = roles.map((role, index) => ({
    verified: true as const,
    event_ref: { ledger_sequence: 11 + index, event_hash: hash(String(index + 1)) },
    recommendation_id: `recommendation_${index}`,
    action_proposal_hash: proposal.action_proposal_hash,
    reviewer_view_hash: hash("8"),
    quorum_requirement_hash: quorum.quorum_requirement_hash,
    reviewed_through_ref,
    evaluator_role_ref: role,
    evaluator_stable_identity_hash: hash(String(index + 1)),
    decision: "allow" as const,
    conditions: [],
    evidence_refs: [{ ledger_sequence: 101 + index, event_hash: hash(String(index + 1)) }],
    evidence_independence_keys: [hash(String(index + 5))],
    issued_at: "2026-08-13T12:00:00Z",
    expires_at: "2026-08-13T12:05:00Z",
  }));
  return {
    proposal,
    reviewer_view_hash: hash("8"),
    reviewed_through_ref,
    recommendations,
    authority: { envelope_verified: true, contained: true, proof_fresh: true, revocation_epoch_current: true },
    enforcement: { available: true, information_flow_allowed: true, gates_passed: true, immediate_revalidation_passed: true },
    condition_results: [],
    issued_at: "2026-08-13T12:02:00Z",
    expires_at: "2026-08-13T12:03:00Z",
    fence_epoch: 0,
  };
}

describe("S36 adversarial authority corpus", () => {
  it("fails closed on approval flood, missing approver, prefix skew, and information-flow poisoning", () => {
    const base = baseAgencyInput();
    const cases = [
      {
        ...structuredClone(base),
        recommendations: base.recommendations.map((row, index) =>
          index === 1 ? { ...row, evaluator_stable_identity_hash: base.recommendations[0]!.evaluator_stable_identity_hash } : row),
      },
      { ...structuredClone(base), recommendations: base.recommendations.slice(0, 3) },
      {
        ...structuredClone(base),
        recommendations: base.recommendations.map((row, index) =>
          index === 0 ? { ...row, reviewed_through_ref: { ledger_sequence: 9, event_hash: hash("9") } } : row),
      },
      { ...structuredClone(base), enforcement: { ...base.enforcement, information_flow_allowed: false } },
      { ...structuredClone(base), authority: { ...base.authority, contained: false } },
    ];
    for (const candidate of cases) {
      expect(simulateAuthorityDecisionV02(candidate)).toMatchObject({
        ok: true,
        value: { decision: "hold", decision_disposition: "non-resumable", simulated_lease: null },
      });
    }
  });

  it("turns conditional allow into resumable HOLD and keeps the failed subset exact", () => {
    const base = baseAgencyInput();
    const conditional = structuredClone(base);
    conditional.recommendations[0]!.decision = "allow_with_conditions";
    conditional.recommendations[0]!.conditions = [{ kind: "require-gate-pass", gate_ref: "gate-main" }];
    const result = simulateAuthorityDecisionV02(conditional);
    expect(result).toMatchObject({
      ok: true,
      value: { decision: "hold", decision_disposition: "redecide-after-prefix-change" },
    });
    if (!result.ok) return;
    expect(result.value.failed_condition_hashes).toEqual(result.value.condition_hashes);
    expect(result.value.condition_hashes.length).toBe(1);
  });

  it("invalidates the simulated lease on repository, dispatch, or enforcement drift", () => {
    const base = baseAgencyInput();
    const decision = simulateAuthorityDecisionV02(base);
    if (!decision.ok || decision.value.simulated_lease === null) throw new Error("lease fixture failed");
    expect(revalidateSimulatedAuthorityLeaseV02(decision.value.simulated_lease, base)).toEqual({ ok: true });
    expect(revalidateSimulatedAuthorityLeaseV02(decision.value.simulated_lease, {
      ...base,
      proposal: { ...base.proposal, repository_pre_state_hash: hash("a") },
    })).toMatchObject({ ok: false });
    expect(revalidateSimulatedAuthorityLeaseV02(decision.value.simulated_lease, {
      ...base,
      proposal: { ...base.proposal, normalized_dispatch_hash: hash("b") },
    })).toMatchObject({ ok: false });
    expect(revalidateSimulatedAuthorityLeaseV02(decision.value.simulated_lease, {
      ...base,
      enforcement: { ...base.enforcement, immediate_revalidation_passed: false },
    })).toMatchObject({ ok: false });
  });
});

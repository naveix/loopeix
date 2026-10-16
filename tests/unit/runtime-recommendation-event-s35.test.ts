import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import * as runtime from "../../src/schema/runtime.js";

const schemas = runtime as unknown as { ApprovalRecommendationRecordedEventV02: ZodType };
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const ref = (sequence: number) => ({ ledger_sequence: sequence, event_hash: HASH_A });

function event(payload: Record<string, unknown>): Record<string, unknown> {
  return {
    schema_version: "0.2", event_id: "event_recommendation_1", run_id: "run_main", sequence: 3,
    recorded_at: "2026-08-10T12:00:00Z", event_type: "approval.recommendation-recorded",
    source: "evaluator", authority_ref: null, risk_tier: "T2", related_ids: [],
    previous_event_hash: HASH_A, event_hash: HASH_B, payload,
  };
}

describe("S35 approval recommendation event", () => {
  it("enforces agency recommendation phase, evidence, identity, and decision branches", () => {
    const payload = {
      recommendation_id: "recommendation_1", record_path: "approval/recommendation_1.json", record_hash: HASH_A,
      run_id: "run_main", plan_hash: HASH_A, task_ref: "task-main", phase: "work", compensation_ref: null,
      action_proposal_id: "proposal_1", action_proposal_hash: HASH_A, action_actor_ref: "actor_1",
      action_actor_stable_identity_hash: HASH_A, on_behalf_of_chain_hash: HASH_A,
      repository_root_ref: "repository_1", repository_base_ref_identity_hash: HASH_A,
      repository_pre_state_hash: HASH_A, authorized_change_set_hash: HASH_A, normalized_dispatch_hash: HASH_A,
      action_scope_hash: HASH_A, action_class: "task", classifier_input_hash: HASH_A,
      classifier_registry_hash: HASH_A, classifier_rule_hash: HASH_A, data_flow_hash: HASH_A,
      policy_action_kind: "network-read", action_approval_class: "agency",
      recommendation_subject_hash: HASH_A, quorum_requirement_hash: HASH_A, policy_digest: HASH_A,
      reviewed_through_ref: ref(1), evidence_refs: [{
        record_kind: "evidence", record_id: "evidence_1", record_event_ref: ref(1),
      }], evidence_independence_keys: [HASH_A], evaluator_role_ref: "reviewer",
      evaluator_actor_ref: "evaluator_1", evaluator_stable_identity_hash: HASH_B,
      evaluator_authentication_context_hash: HASH_A, decision: "allow", condition_hashes: [],
      reason_codes: [{ policy_digest: HASH_A, declaration_ref: "allow-evidence" }],
      issued_at: "2026-08-10T12:00:00Z", expires_at: "2026-08-10T12:05:00Z",
      signer_key_ref: "key_1", statement_hash: HASH_A,
    };
    expect(schemas.ApprovalRecommendationRecordedEventV02.safeParse(event(payload)).success).toBe(true);
    expect(schemas.ApprovalRecommendationRecordedEventV02.safeParse(event({ ...payload, phase: "compensation" })).success).toBe(false);
    expect(schemas.ApprovalRecommendationRecordedEventV02.safeParse(event({ ...payload, condition_hashes: [HASH_A] })).success).toBe(false);
    expect(schemas.ApprovalRecommendationRecordedEventV02.safeParse(event({
      ...payload, evaluator_stable_identity_hash: payload.action_actor_stable_identity_hash,
    })).success).toBe(false);
    expect(schemas.ApprovalRecommendationRecordedEventV02.safeParse(event({
      ...payload, reason_codes: [{ policy_digest: HASH_B, declaration_ref: "allow-evidence" }],
    })).success).toBe(false);
    expect(schemas.ApprovalRecommendationRecordedEventV02.safeParse(event({
      ...payload,
      evidence_refs: [{ record_kind: "human-authorization", record_id: "authorization_1", record_event_ref: ref(1) }],
    })).success).toBe(false);
  });
});

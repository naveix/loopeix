import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import { hashCanonical } from "../../src/hash.js";
import * as runtime from "../../src/schema/runtime.js";

const schemas = runtime as unknown as { TaskActionSettledEventV02: ZodType };
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const head = { algorithm: "sha1", value: "a".repeat(40) } as const;
const ref = (sequence: number) => ({ ledger_sequence: sequence, event_hash: HASH_A });

function event(payload: Record<string, unknown>): Record<string, unknown> {
  return {
    schema_version: "0.2", event_id: "event_settled_1", run_id: "run_main", sequence: 5,
    recorded_at: "2026-08-10T12:00:00Z", event_type: "task.action-settled", source: "kernel",
    authority_ref: null, risk_tier: "T2", related_ids: [], previous_event_hash: HASH_A,
    event_hash: HASH_B, payload,
  };
}

describe("S35 task action settlement event", () => {
  it("recomputes unchanged repository transition and canonical effect outcomes", () => {
    const repositoryStateFields = {
      repository_root_ref: "repository_1",
      base_ref_identity_hash: HASH_A, head, merge_base: head, head_state_hash: HASH_A,
      tracked_diff_hash: HASH_A, staged_diff_hash: HASH_A, untracked_content_hash: HASH_A,
      submodule_state_hash: HASH_A,
    };
    const repositoryStateHash = hashCanonical({ purpose: "repository-state-v02", ...repositoryStateFields });
    const repositoryPostState = { ...repositoryStateFields, repository_state_hash: repositoryStateHash };
    const observedFields = {
      repository_root_ref: "repository_1",
      base_ref_identity_hash: HASH_A, repository_pre_state_hash: repositoryStateHash,
      repository_post_state_hash: repositoryStateHash, head_before: head, head_after: head, changes: [],
    };
    const observedChangeSetHash = hashCanonical({ purpose: "observed-repository-change-set-v02", ...observedFields });
    const payload = {
      action_id: "action_1", task_ref: "task-main", terminal_event_ref: ref(4),
      action_proposal_id: "proposal_1", action_proposal_hash: HASH_A, action_actor_ref: "actor_1",
      action_actor_stable_identity_hash: HASH_A, on_behalf_of_chain_hash: HASH_A,
      repository_root_ref: "repository_1", repository_base_ref_identity_hash: HASH_A,
      repository_pre_state_hash: repositoryStateHash, authorized_change_set_hash: HASH_A,
      normalized_dispatch_hash: HASH_A, policy_action_kind: "planning", action_approval_class: "automatic",
      repository_post_state: repositoryPostState, repository_post_state_hash: repositoryStateHash,
      observed_change_set: { ...observedFields, observed_change_set_hash: observedChangeSetHash },
      observed_change_set_hash: observedChangeSetHash, repository_transition_status: "unchanged",
      effect_outcomes: [
        { effect_ref: "effect-a", outcome: "committed", outcome_event_ref: ref(2) },
        { effect_ref: "effect-b", outcome: "not-committed", outcome_event_ref: ref(3) },
      ],
    };
    expect(schemas.TaskActionSettledEventV02.safeParse(event(payload)).success).toBe(true);
    expect(schemas.TaskActionSettledEventV02.safeParse(event({ ...payload, repository_post_state_hash: HASH_B })).success).toBe(false);
    expect(schemas.TaskActionSettledEventV02.safeParse(event({
      ...payload, policy_action_kind: "network-read", action_approval_class: "automatic",
    })).success).toBe(false);
    expect(schemas.TaskActionSettledEventV02.safeParse(event({
      ...payload, effect_outcomes: [...payload.effect_outcomes].reverse(),
    })).success).toBe(false);
  });
});

import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import * as runtime from "../../src/schema/runtime.js";

type AdmissionEventSchemas = {
  ToolCallAdmittedEventV02: ZodType;
  ArtifactWriteAdmittedEventV02: ZodType;
  LimitAdmissionBlockedEventV02: ZodType;
  TaskExecutionStartedEventV02: ZodType;
};

const schemas = runtime as unknown as AdmissionEventSchemas;
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;

function envelope(
  eventType: string,
  source: string,
  payload: Record<string, unknown>,
  authorityRef: string | null,
): Record<string, unknown> {
  return {
    schema_version: "0.2",
    event_id: "event_admission_1",
    run_id: "run_main",
    sequence: 1,
    recorded_at: "2026-08-10T12:00:00Z",
    event_type: eventType,
    source,
    authority_ref: authorityRef,
    risk_tier: "T2",
    related_ids: [],
    previous_event_hash: null,
    event_hash: HASH_B,
    payload,
  };
}

describe("S35 admission and execution-start events", () => {
  it("enforces the exact tool.call-admitted contract", () => {
    const payload = {
      tool_call_id: "tool_call_1",
      action_id: "action_1",
      task_ref: "task-main",
      tool_grant_ref: "tool-grant-main",
      fence_epoch: 2,
      tool_calls_after: 1,
    };

    expect(schemas.ToolCallAdmittedEventV02.safeParse(envelope(
      "tool.call-admitted",
      "policy-enforcement-point",
      payload,
      "authority_pep",
    )).success).toBe(true);
    expect(schemas.ToolCallAdmittedEventV02.safeParse(envelope(
      "tool.call-admitted",
      "adapter",
      payload,
      "authority_pep",
    )).success).toBe(false);
    expect(schemas.ToolCallAdmittedEventV02.safeParse(envelope(
      "tool.call-admitted",
      "policy-enforcement-point",
      { ...payload, tool_calls_after: 0 },
      "authority_pep",
    )).success).toBe(false);
    expect(schemas.ToolCallAdmittedEventV02.safeParse(envelope(
      "tool.call-admitted",
      "policy-enforcement-point",
      payload,
      null,
    )).success).toBe(false);
  });

  it("enforces prospective artifact byte accounting and exact paths", () => {
    const payload = {
      write_id: "write_1",
      artifact_ref: "artifact-main",
      action_id: "action_1",
      task_ref: "task-main",
      artifact_path: "artifacts/content/report.md",
      prospective_bytes: 8,
      fence_epoch: 2,
      action_output_bytes_after: 13,
    };

    expect(schemas.ArtifactWriteAdmittedEventV02.safeParse(envelope(
      "artifact.write-admitted",
      "policy-enforcement-point",
      payload,
      "authority_pep",
    )).success).toBe(true);
    expect(schemas.ArtifactWriteAdmittedEventV02.safeParse(envelope(
      "artifact.write-admitted",
      "policy-enforcement-point",
      { ...payload, action_output_bytes_after: 7 },
      "authority_pep",
    )).success).toBe(false);
    expect(schemas.ArtifactWriteAdmittedEventV02.safeParse(envelope(
      "artifact.write-admitted",
      "policy-enforcement-point",
      { ...payload, artifact_path: "../report.md" },
      "authority_pep",
    )).success).toBe(false);
  });

  it("requires a complete canonical prospective-limit violation set", () => {
    const payload = {
      request_id: "request_1",
      task_ref: "task-main",
      phase: "work",
      compensation_ref: null,
      request_kind: "tool-call",
      request_hash: HASH_A,
      violations: [
        { limit_ref: "max-cost", consumed: 8, requested: 3, ceiling: 10 },
        { limit_ref: "max-tool-calls", consumed: 4, requested: 1, ceiling: 4 },
      ],
    };

    expect(schemas.LimitAdmissionBlockedEventV02.safeParse(envelope(
      "limit.admission-blocked",
      "policy-enforcement-point",
      payload,
      "authority_pep",
    )).success).toBe(true);
    expect(schemas.LimitAdmissionBlockedEventV02.safeParse(envelope(
      "limit.admission-blocked",
      "policy-enforcement-point",
      { ...payload, violations: [] },
      "authority_pep",
    )).success).toBe(false);
    expect(schemas.LimitAdmissionBlockedEventV02.safeParse(envelope(
      "limit.admission-blocked",
      "policy-enforcement-point",
      { ...payload, violations: [...payload.violations].reverse() },
      "authority_pep",
    )).success).toBe(false);
    expect(schemas.LimitAdmissionBlockedEventV02.safeParse(envelope(
      "limit.admission-blocked",
      "policy-enforcement-point",
      { ...payload, violations: [{ limit_ref: "max-cost", consumed: Number.MAX_SAFE_INTEGER, requested: 1, ceiling: 1 }] },
      "authority_pep",
    )).success).toBe(false);
    expect(schemas.LimitAdmissionBlockedEventV02.safeParse(envelope(
      "limit.admission-blocked",
      "policy-enforcement-point",
      { ...payload, phase: "compensation", compensation_ref: null },
      "authority_pep",
    )).success).toBe(false);
  });

  it("binds task.execution-started to an automatic or agency admission", () => {
    const base = {
      action_id: "action_1",
      task_ref: "task-main",
      admission_ref: { ledger_sequence: 3, event_hash: HASH_A },
      adapter_invocation_id: "adapter_invocation_1",
      action_proposal_id: "proposal_1",
      action_proposal_hash: HASH_A,
      action_actor_ref: "actor_1",
      action_actor_stable_identity_hash: HASH_A,
      on_behalf_of_chain_hash: HASH_A,
      repository_root_ref: "repository_1",
      repository_base_ref_identity_hash: HASH_A,
      repository_pre_state_hash: HASH_A,
      authorized_change_set_hash: HASH_A,
      normalized_dispatch_hash: HASH_A,
    };

    expect(schemas.TaskExecutionStartedEventV02.safeParse(envelope(
      "task.execution-started",
      "adapter",
      { ...base, policy_action_kind: "planning", action_approval_class: "automatic" },
      null,
    )).success).toBe(true);
    expect(schemas.TaskExecutionStartedEventV02.safeParse(envelope(
      "task.execution-started",
      "adapter",
      { ...base, policy_action_kind: "network-read", action_approval_class: "agency" },
      null,
    )).success).toBe(true);
    expect(schemas.TaskExecutionStartedEventV02.safeParse(envelope(
      "task.execution-started",
      "adapter",
      { ...base, policy_action_kind: "network-read", action_approval_class: "automatic" },
      null,
    )).success).toBe(false);
    expect(schemas.TaskExecutionStartedEventV02.safeParse(envelope(
      "task.execution-started",
      "adapter",
      { ...base, policy_action_kind: "commit", action_approval_class: "agency" },
      null,
    )).success).toBe(false);
    expect(schemas.TaskExecutionStartedEventV02.safeParse(envelope(
      "task.execution-started",
      "adapter",
      { ...base, policy_action_kind: "planning", action_approval_class: "automatic" },
      "authority_adapter",
    )).success).toBe(false);
  });
});

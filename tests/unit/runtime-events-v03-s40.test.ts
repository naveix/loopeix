import { describe, expect, it } from "vitest";

import {
  ProcessTerminationAttemptedEventV03,
  RunPausedEventV03,
  RunQuarantinedEventV03,
  RunStartedEventV03,
  RuntimeEventTypesV03,
  RuntimeEventV03,
  RuntimeSchemaInventoryV03,
} from "../../src/schema/runtime-v03.js";
import {
  RuntimeEventTypesV02,
  RuntimeEventV02,
  RuntimeSchemaInventoryV02,
} from "../../src/schema/runtime.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const ref = (ledger_sequence: number) => ({ ledger_sequence, event_hash: H(String(ledger_sequence % 10)) });

const inventoryV02 = {
  resolved_run_plan: "0.2", ledger_event: "0.2", run_manifest: "0.2", artifact_manifest: "0.2",
  redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
  agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2",
  manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2",
  evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2",
  gate_waiver_authority: "0.2",
} as const;

const envelope = {
  schema_version: "0.3",
  event_id: "ev_s40_1",
  run_id: "run_s40_1",
  sequence: 2,
  recorded_at: "2026-08-24T10:00:00Z",
  risk_tier: "T1",
  related_ids: [],
  previous_event_hash: H("1"),
  event_hash: H("2"),
} as const;

const NEW_TYPES = [
  "run.started",
  "run.paused",
  "run.quarantined",
  "process.termination-attempted",
] as const;

describe("S40 closed V03 runtime event family", () => {
  it("changes only ledger_event in the independent runtime inventory", () => {
    expect(RuntimeSchemaInventoryV02.parse(inventoryV02)).toEqual(inventoryV02);
    expect(RuntimeSchemaInventoryV03.parse({ ...inventoryV02, ledger_event: "0.3" })).toEqual({
      ...inventoryV02,
      ledger_event: "0.3",
    });
    expect(RuntimeSchemaInventoryV03.safeParse(inventoryV02).success).toBe(false);
    expect(RuntimeSchemaInventoryV03.safeParse({ ...inventoryV02, ledger_event: "0.3", extra: true }).success).toBe(false);
  });

  it("contains the frozen 46 V02 names plus exactly four V03 lifecycle names", () => {
    expect(RuntimeEventTypesV03).toEqual([...RuntimeEventTypesV02, ...NEW_TYPES]);
    expect(new Set(RuntimeEventTypesV03).size).toBe(50);
    expect(RuntimeEventTypesV02).toHaveLength(46);
  });

  it("rebuilds legacy event envelopes for V03 without widening V02", () => {
    const initializedV03 = {
      ...envelope,
      sequence: 1,
      previous_event_hash: null,
      source: "kernel",
      authority_ref: null,
      event_type: "run.initialized",
      payload: {
        plan_hash: H("3"),
        initial_fence_epoch: 0,
        runtime_schema_versions: { ...inventoryV02, ledger_event: "0.3" },
      },
    };
    expect(RuntimeEventV03.safeParse(initializedV03).success).toBe(true);
    expect(RuntimeEventV02.safeParse(initializedV03).success).toBe(false);
    expect(RuntimeEventV03.safeParse({ ...initializedV03, schema_version: "0.2" }).success).toBe(false);
  });

  const newEvents = [
    {
      schema: RunStartedEventV03,
      value: {
        ...envelope, source: "kernel", authority_ref: null, event_type: "run.started",
        payload: { executor_profile_hash: H("4") },
      },
    },
    {
      schema: RunPausedEventV03,
      value: {
        ...envelope, source: "operator", authority_ref: "auth_pause_1", event_type: "run.paused",
        payload: { requested_by: "operator", reason_code: "operator-request", request_event_ref: ref(1) },
      },
    },
    {
      schema: RunQuarantinedEventV03,
      value: {
        ...envelope, source: "integrity", authority_ref: null, event_type: "run.quarantined",
        payload: { reason_code: "capture-gap", evidence_refs: [ref(1)] },
      },
    },
    {
      schema: ProcessTerminationAttemptedEventV03,
      value: {
        ...envelope, source: "adapter", authority_ref: null, event_type: "process.termination-attempted",
        payload: {
          trigger: "quarantine", trigger_event_ref: ref(1), adapter_invocation_id: "adapter_s40_1",
          observed_outcome: "unknown",
        },
      },
    },
  ] as const;

  it.each(newEvents)("accepts the exact independent source/authority fixture for $value.event_type", ({ schema, value }) => {
    expect(schema.safeParse(value).success).toBe(true);
    expect(RuntimeEventV03.safeParse(value).success).toBe(true);
    expect(schema.safeParse({ ...value, extra: true }).success).toBe(false);
  });

  it.each(newEvents)("rejects source or authority substitution for $value.event_type", ({ schema, value }) => {
    expect(schema.safeParse({ ...value, source: "evaluator" }).success).toBe(false);
    expect(schema.safeParse({ ...value, authority_ref: value.authority_ref === null ? "auth_wrong_1" : null }).success).toBe(false);
  });

  it("binds pause requester to its source and closed reason", () => {
    const policyPause = {
      ...envelope, source: "policy-enforcement-point", authority_ref: "auth_pause_1", event_type: "run.paused",
      payload: { requested_by: "policy", reason_code: "policy-hold", request_event_ref: ref(1) },
    };
    expect(RunPausedEventV03.safeParse(policyPause).success).toBe(true);
    expect(RunPausedEventV03.safeParse({ ...policyPause, source: "operator" }).success).toBe(false);
    expect(RunPausedEventV03.safeParse({ ...policyPause, payload: { ...policyPause.payload, reason_code: "free-form" } }).success).toBe(false);
  });

  it.each([
    "process.termination_attempted",
    "process.termination.attempted",
    "process.terminate-attempted",
    "authority.grant-consumed",
  ])("rejects forbidden alias %s", (event_type) => {
    expect(RuntimeEventV03.safeParse({ event_type }).success).toBe(false);
    expect(RuntimeEventTypesV03).not.toContain(event_type);
  });
});

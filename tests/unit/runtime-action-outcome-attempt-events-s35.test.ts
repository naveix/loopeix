import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import * as runtime from "../../src/schema/runtime.js";

type ActionOutcomeAttemptSchemas = {
  TaskActionOutcomeUnknownEventV02: ZodType;
  TaskActionOutcomeReconciledEventV02: ZodType;
  LoopAttemptCompletedEventV02: ZodType;
};

const schemas = runtime as unknown as ActionOutcomeAttemptSchemas;
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;
const HASH_D = `sha256:${"d".repeat(64)}`;
const HASH_E = `sha256:${"e".repeat(64)}`;

const UNKNOWN_PAYLOAD_KEYS = [
  "action_id",
  "admission_ref",
  "detection_reason",
  "evidence_refs",
  "observation_ref",
  "task_ref",
] as const;

const RECONCILED_PAYLOAD_KEYS = [
  "action_id",
  "admission_ref",
  "process_cannot_continue_ref",
  "reconciliation_evidence_refs",
  "reconciliation_status",
  "task_ref",
] as const;

const ATTEMPT_PAYLOAD_KEYS = [
  "attempt_ordinal",
  "prefix_head_hash",
  "prefix_sequence",
  "previous_attempt_event_ref",
  "progress_observation_refs",
  "work_action_refs",
] as const;

const DETECTION_REASONS = [
  "process-status-unavailable",
  "dispatch-ack-ambiguous",
  "adapter-stream-lost-after-start",
] as const;

function ledgerRef(sequence: number, eventHash = HASH_A): Record<string, unknown> {
  return { ledger_sequence: sequence, event_hash: eventHash };
}

function envelope(eventType: string, source: string, payload: Record<string, unknown>): Record<string, unknown> {
  return {
    schema_version: "0.2",
    event_id: "event_outcome",
    run_id: "run_main",
    sequence: 4,
    recorded_at: "2026-08-03T12:00:00Z",
    event_type: eventType,
    source,
    authority_ref: null,
    risk_tier: "T2",
    related_ids: ["action_main", "task-main"],
    previous_event_hash: HASH_D,
    event_hash: HASH_E,
    payload,
  };
}

function unknownPayload(): Record<string, unknown> {
  return {
    action_id: "action_main",
    task_ref: "task-main",
    admission_ref: ledgerRef(99, HASH_A),
    detection_reason: "process-status-unavailable",
    observation_ref: ledgerRef(101, HASH_B),
    evidence_refs: [ledgerRef(1, HASH_A), ledgerRef(1, HASH_B), ledgerRef(2, HASH_A)],
  };
}

function reconciledPayload(): Record<string, unknown> {
  return {
    action_id: "action_main",
    task_ref: "task-main",
    admission_ref: ledgerRef(99, HASH_A),
    process_cannot_continue_ref: ledgerRef(101, HASH_B),
    reconciliation_status: "outcome-remains-unknown",
    reconciliation_evidence_refs: [ledgerRef(1, HASH_A), ledgerRef(1, HASH_B), ledgerRef(2, HASH_A)],
  };
}

function attemptPayload(): Record<string, unknown> {
  return {
    attempt_ordinal: 3,
    previous_attempt_event_ref: null,
    prefix_sequence: 99,
    prefix_head_hash: HASH_C,
    work_action_refs: [ledgerRef(1, HASH_A), ledgerRef(1, HASH_B), ledgerRef(2, HASH_A)],
    progress_observation_refs: [],
  };
}

function expectExactKeys(value: unknown, keys: readonly string[]): void {
  expect(Object.keys(value as Record<string, unknown>).sort()).toEqual(keys);
}

describe("Task 3C0d task.action-outcome-unknown", () => {
  it("accepts the exact strict payload and all three detection reasons", () => {
    for (const detectionReason of DETECTION_REASONS) {
      const parsed = schemas.TaskActionOutcomeUnknownEventV02.safeParse(envelope(
        "task.action-outcome-unknown",
        "adapter",
        { ...unknownPayload(), detection_reason: detectionReason },
      ));
      expect(parsed.success).toBe(true);
      if (parsed.success) expectExactKeys((parsed.data as { payload: unknown }).payload, UNKNOWN_PAYLOAD_KEYS);
    }
    expect(schemas.TaskActionOutcomeUnknownEventV02.safeParse(envelope(
      "task.action-outcome-unknown",
      "adapter",
      { ...unknownPayload(), detection_reason: "heartbeat-missing" },
    )).success).toBe(false);
  });

  it("requires its exact literal, adapter/null matrix, and strict keys", () => {
    const event = envelope("task.action-outcome-unknown", "adapter", unknownPayload());
    expect(schemas.TaskActionOutcomeUnknownEventV02.safeParse({ ...event, source: "integrity" }).success).toBe(false);
    expect(schemas.TaskActionOutcomeUnknownEventV02.safeParse({ ...event, authority_ref: "authority_main" }).success).toBe(false);
    expect(schemas.TaskActionOutcomeUnknownEventV02.safeParse({ ...event, event_type: "task.action-outcome-reconciled" }).success).toBe(false);
    expect(schemas.TaskActionOutcomeUnknownEventV02.safeParse({ ...event, extra: true }).success).toBe(false);
    expect(schemas.TaskActionOutcomeUnknownEventV02.safeParse(envelope(
      "task.action-outcome-unknown",
      "adapter",
      { ...unknownPayload(), retry_allowed: false },
    )).success).toBe(false);
  });

  it("reuses strict LedgerRef values and canonical evidence arrays without history checks", () => {
    expect(schemas.TaskActionOutcomeUnknownEventV02.safeParse(envelope(
      "task.action-outcome-unknown",
      "adapter",
      { ...unknownPayload(), evidence_refs: [] },
    )).success).toBe(true);
    expect(schemas.TaskActionOutcomeUnknownEventV02.safeParse(envelope(
      "task.action-outcome-unknown",
      "adapter",
      { ...unknownPayload(), observation_ref: ledgerRef(0) },
    )).success).toBe(false);
    for (const evidenceRefs of [
      [ledgerRef(2, HASH_A), ledgerRef(1, HASH_B)],
      [ledgerRef(1, HASH_B), ledgerRef(1, HASH_A)],
      [ledgerRef(1, HASH_A), ledgerRef(1, HASH_A)],
    ]) {
      expect(schemas.TaskActionOutcomeUnknownEventV02.safeParse(envelope(
        "task.action-outcome-unknown",
        "adapter",
        { ...unknownPayload(), evidence_refs: evidenceRefs },
      )).success).toBe(false);
    }
  });
});

describe("Task 3C0d task.action-outcome-reconciled", () => {
  it("accepts only the exact strict payload and integrity/null matrix", () => {
    const event = envelope("task.action-outcome-reconciled", "integrity", reconciledPayload());
    const parsed = schemas.TaskActionOutcomeReconciledEventV02.safeParse(event);
    expect(parsed.success).toBe(true);
    if (parsed.success) expectExactKeys((parsed.data as { payload: unknown }).payload, RECONCILED_PAYLOAD_KEYS);

    expect(schemas.TaskActionOutcomeReconciledEventV02.safeParse({ ...event, source: "adapter" }).success).toBe(false);
    expect(schemas.TaskActionOutcomeReconciledEventV02.safeParse({ ...event, authority_ref: "authority_main" }).success).toBe(false);
    expect(schemas.TaskActionOutcomeReconciledEventV02.safeParse({ ...event, event_type: "task.action-outcome-unknown" }).success).toBe(false);
    expect(schemas.TaskActionOutcomeReconciledEventV02.safeParse({ ...event, extra: true }).success).toBe(false);
    expect(schemas.TaskActionOutcomeReconciledEventV02.safeParse(envelope(
      "task.action-outcome-reconciled",
      "integrity",
      { ...reconciledPayload(), reconciliation_status: "outcome-known" },
    )).success).toBe(false);
  });

  it("reuses strict singular refs and canonical reconciliation evidence arrays", () => {
    expect(schemas.TaskActionOutcomeReconciledEventV02.safeParse(envelope(
      "task.action-outcome-reconciled",
      "integrity",
      { ...reconciledPayload(), reconciliation_evidence_refs: [] },
    )).success).toBe(true);
    expect(schemas.TaskActionOutcomeReconciledEventV02.safeParse(envelope(
      "task.action-outcome-reconciled",
      "integrity",
      { ...reconciledPayload(), process_cannot_continue_ref: { ...ledgerRef(1), extra: true } },
    )).success).toBe(false);
    expect(schemas.TaskActionOutcomeReconciledEventV02.safeParse(envelope(
      "task.action-outcome-reconciled",
      "integrity",
      { ...reconciledPayload(), reconciliation_evidence_refs: [ledgerRef(1, HASH_B), ledgerRef(1, HASH_A)] },
    )).success).toBe(false);
  });
});

describe("Task 3C0d loop.attempt-completed", () => {
  it("accepts the exact strict payload and kernel/null matrix without contiguity or prefix equality", () => {
    const event = envelope("loop.attempt-completed", "kernel", attemptPayload());
    const parsed = schemas.LoopAttemptCompletedEventV02.safeParse(event);
    expect(parsed.success).toBe(true);
    if (parsed.success) expectExactKeys((parsed.data as { payload: unknown }).payload, ATTEMPT_PAYLOAD_KEYS);

    expect(schemas.LoopAttemptCompletedEventV02.safeParse({ ...event, source: "evaluator" }).success).toBe(false);
    expect(schemas.LoopAttemptCompletedEventV02.safeParse({ ...event, authority_ref: "authority_main" }).success).toBe(false);
    expect(schemas.LoopAttemptCompletedEventV02.safeParse({ ...event, event_type: "loop.attempt-started" }).success).toBe(false);
    expect(schemas.LoopAttemptCompletedEventV02.safeParse({ ...event, extra: true }).success).toBe(false);
    expect(schemas.LoopAttemptCompletedEventV02.safeParse(envelope(
      "loop.attempt-completed",
      "kernel",
      { ...attemptPayload(), observations_complete: true },
    )).success).toBe(false);
  });

  it("requires positive-safe attempt and prefix scalars", () => {
    for (const field of ["attempt_ordinal", "prefix_sequence"] as const) {
      expect(schemas.LoopAttemptCompletedEventV02.safeParse(envelope(
        "loop.attempt-completed",
        "kernel",
        { ...attemptPayload(), [field]: Number.MAX_SAFE_INTEGER },
      )).success).toBe(true);
      expect(schemas.LoopAttemptCompletedEventV02.safeParse(envelope(
        "loop.attempt-completed",
        "kernel",
        { ...attemptPayload(), [field]: 0 },
      )).success).toBe(false);
      expect(schemas.LoopAttemptCompletedEventV02.safeParse(envelope(
        "loop.attempt-completed",
        "kernel",
        { ...attemptPayload(), [field]: Number.MAX_SAFE_INTEGER + 1 },
      )).success).toBe(false);
    }
  });

  it("accepts nullable prior-attempt refs and enforces both canonical ref arrays", () => {
    expect(schemas.LoopAttemptCompletedEventV02.safeParse(envelope(
      "loop.attempt-completed",
      "kernel",
      {
        ...attemptPayload(),
        previous_attempt_event_ref: ledgerRef(100, HASH_B),
        work_action_refs: [],
        progress_observation_refs: [],
      },
    )).success).toBe(true);
    expect(schemas.LoopAttemptCompletedEventV02.safeParse(envelope(
      "loop.attempt-completed",
      "kernel",
      { ...attemptPayload(), previous_attempt_event_ref: ledgerRef(0) },
    )).success).toBe(false);

    for (const field of ["work_action_refs", "progress_observation_refs"] as const) {
      for (const refs of [
        [ledgerRef(2, HASH_A), ledgerRef(1, HASH_B)],
        [ledgerRef(1, HASH_B), ledgerRef(1, HASH_A)],
        [ledgerRef(1, HASH_A), ledgerRef(1, HASH_A)],
      ]) {
        expect(schemas.LoopAttemptCompletedEventV02.safeParse(envelope(
          "loop.attempt-completed",
          "kernel",
          { ...attemptPayload(), [field]: refs },
        )).success).toBe(false);
      }
    }
  });
});

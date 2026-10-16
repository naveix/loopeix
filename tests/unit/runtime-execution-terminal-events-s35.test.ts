import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import * as runtime from "../../src/schema/runtime.js";

type ExecutionTerminalSchemas = {
  TaskExecutionCompletedEventV02: ZodType;
  TaskExecutionFailedEventV02: ZodType;
};

const schemas = runtime as unknown as ExecutionTerminalSchemas;
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;
const HASH_D = `sha256:${"d".repeat(64)}`;
const HASH_E = `sha256:${"e".repeat(64)}`;

const COMPLETED_PAYLOAD_KEYS = [
  "action_id",
  "action_output_bytes_after",
  "admission_ref",
  "observed_cost",
  "output_bytes",
  "result_hash",
  "result_id",
  "result_path",
  "task_ref",
  "token_count",
  "token_count_after",
  "tool_calls",
  "tool_calls_after",
] as const;

const FAILED_PAYLOAD_KEYS = [
  "action_id",
  "action_output_bytes_after",
  "admission_ref",
  "failure_class",
  "failure_clock_ref",
  "failure_ordinal",
  "observed_cost",
  "output_bytes",
  "result_hash",
  "result_id",
  "result_path",
  "retry_safety_evidence_refs",
  "task_ref",
  "token_count",
  "token_count_after",
  "tool_calls",
  "tool_calls_after",
] as const;

const RETRY_CLASSES = [
  "transient-adapter",
  "transient-network",
  "contention",
  "verification-failed",
  "policy-hold",
  "invalid-input",
  "permanent-execution",
] as const;

function ledgerRef(sequence: number, eventHash = HASH_A): Record<string, unknown> {
  return { ledger_sequence: sequence, event_hash: eventHash };
}

function observedCost(): Record<string, unknown> {
  return {
    capture: "captured",
    cost_minor_units: 7,
    cost_currency: "GBP",
    cost_minor_units_after: 3,
  };
}

function completedPayload(): Record<string, unknown> {
  return {
    action_id: "action_main",
    task_ref: "task-main",
    admission_ref: ledgerRef(99, HASH_A),
    result_id: "result_main",
    result_path: "records/task-results/result_main.json",
    result_hash: HASH_B,
    output_bytes: 8,
    tool_calls: 3,
    token_count: 5,
    observed_cost: observedCost(),
    action_output_bytes_after: 2,
    tool_calls_after: 1,
    token_count_after: 4,
  };
}

function failedPayload(): Record<string, unknown> {
  return {
    ...completedPayload(),
    failure_class: "transient-adapter",
    failure_ordinal: 1,
    failure_clock_ref: ledgerRef(100, HASH_C),
    retry_safety_evidence_refs: [
      ledgerRef(1, HASH_A),
      ledgerRef(1, HASH_B),
      ledgerRef(2, HASH_A),
    ],
  };
}

function envelope(eventType: string, payload: Record<string, unknown>): Record<string, unknown> {
  return {
    schema_version: "0.2",
    event_id: "event_terminal",
    run_id: "run_main",
    sequence: 4,
    recorded_at: "2026-08-03T12:00:00Z",
    event_type: eventType,
    source: "adapter",
    authority_ref: null,
    risk_tier: "T2",
    related_ids: ["action_main", "task-main"],
    previous_event_hash: HASH_D,
    event_hash: HASH_E,
    payload,
  };
}

function expectExactKeys(value: unknown, keys: readonly string[]): void {
  expect(Object.keys(value as Record<string, unknown>).sort()).toEqual(keys);
}

describe("Task 3C0c task.execution-completed", () => {
  it("accepts the exact strict payload without adding history, equality, or cumulative semantics", () => {
    const event = envelope("task.execution-completed", completedPayload());
    const parsed = schemas.TaskExecutionCompletedEventV02.safeParse(event);
    expect(parsed.success).toBe(true);
    if (parsed.success) expectExactKeys((parsed.data as { payload: unknown }).payload, COMPLETED_PAYLOAD_KEYS);

    expect(schemas.TaskExecutionCompletedEventV02.safeParse({ ...event, extra: true }).success).toBe(false);
    expect(schemas.TaskExecutionCompletedEventV02.safeParse(envelope("task.execution-completed", {
      ...completedPayload(),
      task_result_status: "completed",
    })).success).toBe(false);
  });

  it("requires the exact literal, adapter source, and null authority", () => {
    const event = envelope("task.execution-completed", completedPayload());
    expect(schemas.TaskExecutionCompletedEventV02.safeParse({ ...event, source: "kernel" }).success).toBe(false);
    expect(schemas.TaskExecutionCompletedEventV02.safeParse({ ...event, authority_ref: "authority_main" }).success).toBe(false);
    expect(schemas.TaskExecutionCompletedEventV02.safeParse({ ...event, event_type: "task.execution-failed" }).success).toBe(false);
  });

  it("enforces relative result paths and non-negative safe accounting counters", () => {
    const payload = completedPayload();
    for (const field of [
      "output_bytes",
      "tool_calls",
      "token_count",
      "action_output_bytes_after",
      "tool_calls_after",
      "token_count_after",
    ] as const) {
      expect(schemas.TaskExecutionCompletedEventV02.safeParse(envelope("task.execution-completed", {
        ...payload,
        [field]: Number.MAX_SAFE_INTEGER,
      })).success).toBe(true);
      expect(schemas.TaskExecutionCompletedEventV02.safeParse(envelope("task.execution-completed", {
        ...payload,
        [field]: -1,
      })).success).toBe(false);
      expect(schemas.TaskExecutionCompletedEventV02.safeParse(envelope("task.execution-completed", {
        ...payload,
        [field]: Number.MAX_SAFE_INTEGER + 1,
      })).success).toBe(false);
    }
    expect(schemas.TaskExecutionCompletedEventV02.safeParse(envelope("task.execution-completed", {
      ...payload,
      result_path: "../result.json",
    })).success).toBe(false);
  });

  it("reuses the strict ObservedCostV02 branches", () => {
    expect(schemas.TaskExecutionCompletedEventV02.safeParse(envelope("task.execution-completed", {
      ...completedPayload(),
      observed_cost: {
        capture: "not-applicable",
        cost_minor_units: 0,
        cost_currency: null,
        cost_minor_units_after: 0,
      },
    })).success).toBe(true);
    expect(schemas.TaskExecutionCompletedEventV02.safeParse(envelope("task.execution-completed", {
      ...completedPayload(),
      observed_cost: {
        capture: "captured",
        cost_minor_units: -1,
        cost_currency: "gbp",
        cost_minor_units_after: 0,
      },
    })).success).toBe(false);
  });
});

describe("Task 3C0c task.execution-failed", () => {
  it("accepts the exact strict failed payload and all seven retry literals", () => {
    for (const failureClass of RETRY_CLASSES) {
      const parsed = schemas.TaskExecutionFailedEventV02.safeParse(envelope("task.execution-failed", {
        ...failedPayload(),
        failure_class: failureClass,
      }));
      expect(parsed.success).toBe(true);
      if (parsed.success) expectExactKeys((parsed.data as { payload: unknown }).payload, FAILED_PAYLOAD_KEYS);
    }
    expect(schemas.TaskExecutionFailedEventV02.safeParse(envelope("task.execution-failed", {
      ...failedPayload(),
      failure_class: "unknown-class",
    })).success).toBe(false);
  });

  it("requires the exact literal, adapter source, null authority, and strict keys", () => {
    const event = envelope("task.execution-failed", failedPayload());
    expect(schemas.TaskExecutionFailedEventV02.safeParse({ ...event, source: "integrity" }).success).toBe(false);
    expect(schemas.TaskExecutionFailedEventV02.safeParse({ ...event, authority_ref: "authority_main" }).success).toBe(false);
    expect(schemas.TaskExecutionFailedEventV02.safeParse({ ...event, event_type: "task.execution-completed" }).success).toBe(false);
    expect(schemas.TaskExecutionFailedEventV02.safeParse({ ...event, extra: true }).success).toBe(false);
    expect(schemas.TaskExecutionFailedEventV02.safeParse(envelope("task.execution-failed", {
      ...failedPayload(),
      retry_disposition: "retry",
    })).success).toBe(false);
  });

  it("requires a positive safe failure ordinal", () => {
    const payload = failedPayload();
    expect(schemas.TaskExecutionFailedEventV02.safeParse(envelope("task.execution-failed", {
      ...payload,
      failure_ordinal: Number.MAX_SAFE_INTEGER,
    })).success).toBe(true);
    expect(schemas.TaskExecutionFailedEventV02.safeParse(envelope("task.execution-failed", {
      ...payload,
      failure_ordinal: 0,
    })).success).toBe(false);
    expect(schemas.TaskExecutionFailedEventV02.safeParse(envelope("task.execution-failed", {
      ...payload,
      failure_ordinal: Number.MAX_SAFE_INTEGER + 1,
    })).success).toBe(false);
  });

  it("accepts empty retry evidence and otherwise enforces canonical LedgerRef order without sorting", () => {
    const payload = failedPayload();
    expect(schemas.TaskExecutionFailedEventV02.safeParse(envelope("task.execution-failed", {
      ...payload,
      retry_safety_evidence_refs: [],
    })).success).toBe(true);
    expect(schemas.TaskExecutionFailedEventV02.safeParse(envelope("task.execution-failed", {
      ...payload,
      retry_safety_evidence_refs: [ledgerRef(1, HASH_A), ledgerRef(1, HASH_B), ledgerRef(2, HASH_A)],
    })).success).toBe(true);
    expect(schemas.TaskExecutionFailedEventV02.safeParse(envelope("task.execution-failed", {
      ...payload,
      retry_safety_evidence_refs: [ledgerRef(2, HASH_A), ledgerRef(1, HASH_B)],
    })).success).toBe(false);
    expect(schemas.TaskExecutionFailedEventV02.safeParse(envelope("task.execution-failed", {
      ...payload,
      retry_safety_evidence_refs: [ledgerRef(1, HASH_B), ledgerRef(1, HASH_A)],
    })).success).toBe(false);
    expect(schemas.TaskExecutionFailedEventV02.safeParse(envelope("task.execution-failed", {
      ...payload,
      retry_safety_evidence_refs: [ledgerRef(1, HASH_A), ledgerRef(1, HASH_A)],
    })).success).toBe(false);
  });
});

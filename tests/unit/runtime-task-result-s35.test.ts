import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import * as runtime from "../../src/schema/runtime.js";

type RuntimeTaskResultSchemas = {
  ObservedCostV02: ZodType;
  TaskResultV02: ZodType;
};

const schemas = runtime as unknown as RuntimeTaskResultSchemas;
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;
const HASH_D = `sha256:${"d".repeat(64)}`;

const OBSERVED_COST_KEYS = [
  "capture",
  "cost_currency",
  "cost_minor_units",
  "cost_minor_units_after",
] as const;

const TASK_RESULT_KEYS = [
  "action_id",
  "adapter_invocation_id",
  "capture_gap_codes",
  "failure_class",
  "observation",
  "plan_hash",
  "record_hash",
  "result_id",
  "run_id",
  "schema_version",
  "status",
  "task_ref",
] as const;

const OBSERVATION_KEYS = {
  browser: [
    "browser_session_authority_ref",
    "capture_hash",
    "interaction_hash",
    "kind",
    "target_hash",
  ],
  command: ["command_hash", "cwd_identity_hash", "exit_code", "input_hash", "kind", "output_hash"],
  generic: ["kind", "output_hash"],
  "source-acquisition": [
    "auth_class",
    "authentication_scope_hash",
    "canonical_source_identity",
    "content_hash",
    "final_uri_hash",
    "kind",
    "locator_hash",
    "redaction_state",
    "requested_uri_hash",
    "response_class",
    "retrieval_method",
    "retrieved_at",
    "retriever_identity",
    "retriever_version",
    "selector_hash",
  ],
} as const;

const RETRY_CLASSES = [
  "transient-adapter",
  "transient-network",
  "contention",
  "verification-failed",
  "policy-hold",
  "invalid-input",
  "permanent-execution",
] as const;

function ledgerRef(): Record<string, unknown> {
  return { ledger_sequence: 1, event_hash: HASH_A };
}

function commandObservation(exitCode = 0): Record<string, unknown> {
  return {
    kind: "command",
    command_hash: HASH_A,
    cwd_identity_hash: HASH_B,
    input_hash: HASH_C,
    output_hash: HASH_D,
    exit_code: exitCode,
  };
}

function browserObservation(): Record<string, unknown> {
  return {
    kind: "browser",
    target_hash: HASH_A,
    interaction_hash: HASH_B,
    browser_session_authority_ref: ledgerRef(),
    capture_hash: HASH_C,
  };
}

function sourceAcquisitionObservation(): Record<string, unknown> {
  return {
    kind: "source-acquisition",
    requested_uri_hash: HASH_A,
    final_uri_hash: HASH_B,
    canonical_source_identity: "https://example.test/source",
    locator_hash: HASH_C,
    retrieval_method: "http",
    retrieved_at: "2026-08-03T12:00:00Z",
    retriever_identity: "source-fetcher",
    retriever_version: "v1",
    auth_class: "public",
    authentication_scope_hash: null,
    response_class: "success",
    content_hash: HASH_D,
    selector_hash: null,
    redaction_state: "none",
  };
}

function genericObservation(): Record<string, unknown> {
  return { kind: "generic", output_hash: HASH_A };
}

function validTaskResult(observation: Record<string, unknown> = commandObservation()): Record<string, unknown> {
  return {
    schema_version: "0.2",
    result_id: "result_main",
    run_id: "run_main",
    plan_hash: HASH_A,
    action_id: "action_main",
    task_ref: "task-main",
    adapter_invocation_id: "adapter_main",
    status: "completed",
    failure_class: null,
    observation,
    capture_gap_codes: ["missing-stderr", "partial-telemetry"],
    record_hash: HASH_B,
  };
}

function expectExactKeys(value: unknown, keys: readonly string[]): void {
  expect(Object.keys(value as Record<string, unknown>).sort()).toEqual(keys);
}

describe("Task 3C0b ObservedCostV02", () => {
  it("accepts only the exact three strict cost-capture branches", () => {
    const cases = [
      {
        capture: "not-applicable",
        cost_minor_units: 0,
        cost_currency: null,
        cost_minor_units_after: 0,
      },
      {
        capture: "captured",
        cost_minor_units: 0,
        cost_currency: "GBP",
        cost_minor_units_after: Number.MAX_SAFE_INTEGER,
      },
      {
        capture: "unavailable",
        cost_minor_units: null,
        cost_currency: null,
        cost_minor_units_after: null,
      },
      {
        capture: "unavailable",
        cost_minor_units: null,
        cost_currency: "USD",
        cost_minor_units_after: null,
      },
    ] as const;

    for (const value of cases) {
      const parsed = schemas.ObservedCostV02.safeParse(value);
      expect(parsed.success).toBe(true);
      if (parsed.success) expectExactKeys(parsed.data, OBSERVED_COST_KEYS);
    }
  });

  it("rejects invalid branch nullability, literals, unsafe costs, and currency syntax", () => {
    expect(schemas.ObservedCostV02.safeParse({
      capture: "not-applicable",
      cost_minor_units: 1,
      cost_currency: null,
      cost_minor_units_after: 0,
    }).success).toBe(false);
    expect(schemas.ObservedCostV02.safeParse({
      capture: "captured",
      cost_minor_units: -1,
      cost_currency: "GBP",
      cost_minor_units_after: 0,
    }).success).toBe(false);
    expect(schemas.ObservedCostV02.safeParse({
      capture: "captured",
      cost_minor_units: 0,
      cost_currency: "gbp",
      cost_minor_units_after: Number.MAX_SAFE_INTEGER + 1,
    }).success).toBe(false);
    expect(schemas.ObservedCostV02.safeParse({
      capture: "unavailable",
      cost_minor_units: 0,
      cost_currency: "USDX",
      cost_minor_units_after: null,
    }).success).toBe(false);
    expect(schemas.ObservedCostV02.safeParse({
      capture: "captured",
      cost_minor_units: 0,
      cost_currency: "GBP",
      cost_minor_units_after: 0,
      extra: true,
    }).success).toBe(false);
  });
});

describe("Task 3C0b TaskResultV02", () => {
  it("accepts the exact strict command, browser, source-acquisition, and generic observations", () => {
    const cases = [
      ["command", commandObservation()],
      ["browser", browserObservation()],
      ["source-acquisition", sourceAcquisitionObservation()],
      ["generic", genericObservation()],
    ] as const;

    for (const [kind, observation] of cases) {
      const parsed = schemas.TaskResultV02.safeParse(validTaskResult(observation));
      expect(parsed.success).toBe(true);
      if (parsed.success) {
        expectExactKeys(parsed.data, TASK_RESULT_KEYS);
        expectExactKeys((parsed.data as { observation: unknown }).observation, OBSERVATION_KEYS[kind]);
      }
    }
  });

  it("reuses all seven exact RetryClassV02 literals without coupling status to failure_class", () => {
    for (const failureClass of RETRY_CLASSES) {
      expect(schemas.TaskResultV02.safeParse({
        ...validTaskResult(genericObservation()),
        status: "completed",
        failure_class: failureClass,
      }).success).toBe(true);
    }
    expect(schemas.TaskResultV02.safeParse({
      ...validTaskResult(genericObservation()),
      status: "failed",
      failure_class: null,
    }).success).toBe(true);
    expect(schemas.TaskResultV02.safeParse({
      ...validTaskResult(genericObservation()),
      failure_class: "unknown-retry-class",
    }).success).toBe(false);
  });

  it("rejects unknown top-level, observation, and progress-value fields", () => {
    const result = validTaskResult();
    expect(schemas.TaskResultV02.safeParse({ ...result, result_path: "../result.json" }).success).toBe(false);
    expect(schemas.TaskResultV02.safeParse({ ...result, progress_values: { score: 1 } }).success).toBe(false);
    expect(schemas.TaskResultV02.safeParse({
      ...result,
      observation: { ...commandObservation(), capture_hash: HASH_A },
    }).success).toBe(false);
    expect(schemas.TaskResultV02.safeParse({
      ...result,
      observation: { kind: "generic", output_hash: HASH_A, progress_value: 1 },
    }).success).toBe(false);
  });

  it("enforces safe command exit codes and strict branch-specific fields", () => {
    expect(schemas.TaskResultV02.safeParse(validTaskResult(commandObservation(Number.MIN_SAFE_INTEGER))).success).toBe(true);
    expect(schemas.TaskResultV02.safeParse(validTaskResult(commandObservation(Number.MAX_SAFE_INTEGER))).success).toBe(true);
    expect(schemas.TaskResultV02.safeParse(validTaskResult(commandObservation(Number.MAX_SAFE_INTEGER + 1))).success).toBe(false);
    expect(schemas.TaskResultV02.safeParse(validTaskResult(commandObservation(0.5))).success).toBe(false);
    expect(schemas.TaskResultV02.safeParse(validTaskResult({
      ...browserObservation(),
      browser_session_authority_ref: null,
    })).success).toBe(false);
    expect(schemas.TaskResultV02.safeParse(validTaskResult({
      ...sourceAcquisitionObservation(),
      authentication_scope_hash: 7,
    })).success).toBe(false);
  });

  it("rejects malformed IDs, hashes, timestamps, and non-blank source strings", () => {
    const result = validTaskResult(sourceAcquisitionObservation());
    expect(schemas.TaskResultV02.safeParse({ ...result, result_id: "result-main" }).success).toBe(false);
    expect(schemas.TaskResultV02.safeParse({ ...result, plan_hash: "sha256:BAD" }).success).toBe(false);
    expect(schemas.TaskResultV02.safeParse({
      ...result,
      observation: { ...sourceAcquisitionObservation(), retrieved_at: "2026-08-03" },
    }).success).toBe(false);
    expect(schemas.TaskResultV02.safeParse({
      ...result,
      observation: { ...sourceAcquisitionObservation(), retriever_identity: "  " },
    }).success).toBe(false);
    expect(schemas.TaskResultV02.safeParse({
      ...result,
      observation: { ...sourceAcquisitionObservation(), canonical_source_identity: "\ud800" },
    }).success).toBe(false);
  });

  it("requires non-blank duplicate-free UTF-8-ordered gap codes without an invented maximum", () => {
    const result = validTaskResult(genericObservation());
    expect(schemas.TaskResultV02.safeParse({ ...result, capture_gap_codes: [] }).success).toBe(true);
    expect(schemas.TaskResultV02.safeParse({ ...result, capture_gap_codes: ["z", "é"] }).success).toBe(true);
    expect(schemas.TaskResultV02.safeParse({ ...result, capture_gap_codes: ["é", "z"] }).success).toBe(false);
    expect(schemas.TaskResultV02.safeParse({ ...result, capture_gap_codes: ["same", "same"] }).success).toBe(false);
    expect(schemas.TaskResultV02.safeParse({ ...result, capture_gap_codes: ["valid", "  "] }).success).toBe(false);
    expect(schemas.TaskResultV02.safeParse({ ...result, capture_gap_codes: ["\ud800"] }).success).toBe(false);

    const largeOrderedSet = Array.from({ length: 1_024 }, (_, index) => `gap-${index.toString().padStart(4, "0")}`);
    expect(schemas.TaskResultV02.safeParse({ ...result, capture_gap_codes: largeOrderedSet }).success).toBe(true);
  });
});

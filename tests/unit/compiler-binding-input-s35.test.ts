import { describe, expect, it } from "vitest";
import {
  BindingInputRecordV02,
  CompileBindingPayloadV02,
  admitCompileBindingPayloadV02,
  decodeCompileBindingPayloadV02,
  projectPlanInputV02,
  validateBindingsForCatalogEntryV02,
} from "../../src/compiler/binding-input-v02.js";
import { DEFAULT_LOOP_CATALOG_V02 } from "../../src/catalog/default-items.js";
import { AdapterPlanInputV02, WorkspaceBoundaryInputV02 } from "../../src/catalog/item-v02.js";

const encode = (value: string): Uint8Array => new TextEncoder().encode(value);
const hash = `sha256:${"a".repeat(64)}`;

describe("S35 V02 binding input foundation", () => {
  it("normalizes omission but rejects a bare array envelope", () => {
    expect(decodeCompileBindingPayloadV02(undefined)).toEqual({ ok: true, payload: { bindings: [] } });
    expect(decodeCompileBindingPayloadV02(encode("[]"))).toMatchObject({
      ok: false,
      reason: "INVALID_DOCUMENT_ENVELOPE",
    });
    expect(decodeCompileBindingPayloadV02(encode('{"bindings":[],"extra":true}'))).toMatchObject({
      ok: false,
      reason: "INVALID_BINDING_INPUT",
    });
  });

  it("enforces strict JSON values and source lineage", () => {
    const sparse: unknown[] = [];
    sparse[1] = "value";
    expect(
      CompileBindingPayloadV02.safeParse({
        bindings: [{ key: "project.goal", source: "operator", value: sparse, source_ref: null, source_hash: null }],
      }).success,
    ).toBe(false);

    expect(
      CompileBindingPayloadV02.safeParse({
        bindings: [
          {
            key: "project.workspace-root",
            source: "workspace-observation",
            value: { root: "/workspace", read: ["src"], write: ["artifacts"] },
            source_ref: "workspace:root",
            source_hash: hash,
          },
        ],
      }).success,
    ).toBe(true);

    const adapterPlan = { engine: "codex", command: "codex", permission_mode: "workspace-write", known_gaps: [] } as const;
    const workspaceBoundary = { root: "/workspace", read: ["src"], write: ["artifacts"] } as const;
    expect(AdapterPlanInputV02.safeParse(adapterPlan).success).toBe(true);
    expect(WorkspaceBoundaryInputV02.safeParse(workspaceBoundary).success).toBe(true);
    expect(AdapterPlanInputV02.safeParse({ ...adapterPlan, extra: true }).success).toBe(false);
    expect(WorkspaceBoundaryInputV02.safeParse({ ...workspaceBoundary, extra: true }).success).toBe(false);

    const entry = DEFAULT_LOOP_CATALOG_V02.find((candidate) => candidate.item_id === "safe-bugfix");
    expect(entry).toBeDefined();
    expect(validateBindingsForCatalogEntryV02({ bindings: [
      { key: "project.engine", source: "operator", value: adapterPlan, source_ref: null, source_hash: null },
      { key: "project.workspace-root", source: "workspace-observation", value: workspaceBoundary, source_ref: "workspace:root", source_hash: hash },
    ] }, entry!)).toMatchObject({ ok: true });
  });

  it("projects only complete approved plan input without defaults or shared mutation", () => {
    const adapterPlan = {
      engine: "codex",
      command: "codex",
      permission_mode: "workspace-write",
      known_gaps: ["shell events are adapter-observed"],
    } as const;
    const workspaceBoundary = { root: "/workspace", read: ["src"], write: ["artifacts"] } as const;
    const record = BindingInputRecordV02.parse({
      schema_version: "0.2",
      binding_input_id: "binding_plan_input",
      work_item_id: "work_plan_input",
      submitted_at: "2026-08-10T12:00:00.000Z",
      bindings: [
        { key: "project.engine", source: "operator", value: adapterPlan, source_ref: null, source_hash: null, approved_by: "operator" },
        { key: "project.workspace-root", source: "workspace-observation", value: workspaceBoundary, source_ref: "workspace:root", source_hash: hash, approved_by: "operator" },
      ],
    });

    const result = projectPlanInputV02(record);
    expect(result).toEqual({
      ok: true,
      plan_input: { adapter_plan: adapterPlan, workspace_boundary: workspaceBoundary },
    });
    if (result.ok) {
      (record.bindings[0]!.value as { known_gaps: string[] }).known_gaps.push("caller mutation");
      expect(result.plan_input.adapter_plan.known_gaps).toEqual(["shell events are adapter-observed"]);
    }

    expect(projectPlanInputV02({ ...record, bindings: record.bindings.slice(0, 1) })).toEqual({
      ok: false,
      reason: "INVALID_BINDING_INPUT",
      message: "Binding input is invalid.",
    });
    expect(projectPlanInputV02({ ...record, bindings: record.bindings.map((binding) =>
      binding.key === "project.engine" ? { ...binding, value: { ...adapterPlan, extra: true } } : binding) })).toEqual({
      ok: false,
      reason: "INVALID_BINDING_INPUT",
      message: "Binding input is invalid.",
    });
  });

  it("returns sanitized credential rejections and creates a sorted persisted record", () => {
    const secret = `sk-${"x".repeat(24)}`;
    const rejected = admitCompileBindingPayloadV02({
      prompt: "compile this",
      payload: {
        bindings: [{ key: "project.goal", source: "operator", value: secret, source_ref: null, source_hash: null }],
      },
      binding_input_id: "binding_test",
      work_item_id: "work_test",
      submitted_at: "2026-08-03T12:00:00.000Z",
    });
    expect(rejected).toMatchObject({
      ok: false,
      reason: "SENSITIVE_INPUT_REJECTED",
      location: "binding-value",
      binding_key: "project.goal",
      rule_id: "CRED_OPENAI_API_KEY",
    });
    expect(JSON.stringify(rejected)).not.toContain(secret);

    expect(
      admitCompileBindingPayloadV02({
        prompt: secret,
        payload: { malformed: true },
        binding_input_id: "binding_test",
        work_item_id: "work_test",
        submitted_at: "2026-08-03T12:00:00.000Z",
      }),
    ).toMatchObject({ reason: "SENSITIVE_INPUT_REJECTED", location: "prompt" });

    const admitted = admitCompileBindingPayloadV02({
      prompt: "compile this",
      payload: {
        bindings: [
          { key: "project.goal", source: "operator", value: { statement: "Fix it" }, source_ref: null, source_hash: null },
          { key: "project.engine", source: "operator", value: { engine: "codex", command: "codex", permission_mode: "workspace-write", known_gaps: [] }, source_ref: null, source_hash: null },
        ],
      },
      binding_input_id: "binding_test",
      work_item_id: "work_test",
      submitted_at: "2026-08-03T12:00:00.000Z",
    });
    expect(admitted.ok).toBe(true);
    if (admitted.ok) {
      expect(BindingInputRecordV02.parse(admitted.record).bindings.map((binding) => binding.key)).toEqual([
        "project.engine",
        "project.goal",
      ]);
    }
  });

  it("rejects unsupported engines and incomplete goal objects without echo", () => {
    const entry = DEFAULT_LOOP_CATALOG_V02.find((candidate) => candidate.item_id === "safe-bugfix");
    expect(entry).toBeDefined();

    for (const binding of [
      { key: "project.engine", source: "operator", value: "gpt", source_ref: null, source_hash: null },
      { key: "project.goal", source: "operator", value: {}, source_ref: null, source_hash: null },
    ] as const) {
      const result = validateBindingsForCatalogEntryV02({ bindings: [binding] }, entry!);
      expect(result).toEqual({ ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding input is invalid." });
      expect(JSON.stringify(result)).not.toContain(JSON.stringify(binding.value));
    }
  });

  it("rejects a representative malformed value for every initial project slot", () => {
    const entry = DEFAULT_LOOP_CATALOG_V02.find((candidate) => candidate.item_id === "safe-bugfix");
    expect(entry).toBeDefined();
    const malformedValues: Record<string, unknown> = {
      "project.compensations": [{}],
      "project.engine": "gpt",
      "project.evidence-requirements": [],
      "project.forbidden-context": ["duplicate", "duplicate"],
      "project.goal": {},
      "project.hard-limits": {},
      "project.objective": "   ",
      "project.progress": {},
      "project.recovery-policy": {},
      "project.required-context": [""],
      "project.retry-policy": { rules: [] },
      "project.side-effects": [],
      "project.stop-policy": {},
      "project.validation": [],
      "project.workspace-root": "relative/workspace",
    };

    for (const [key, value] of Object.entries(malformedValues)) {
      expect(
        validateBindingsForCatalogEntryV02({
          bindings: [{ key, source: key === "project.workspace-root" ? "workspace-observation" : "operator", value, source_ref: key === "project.workspace-root" ? "workspace:root" : null, source_hash: key === "project.workspace-root" ? hash : null }],
        }, entry!),
        key,
      ).toEqual({ ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding input is invalid." });
    }
  });

  it("rejects shaped policies that violate slot-local semantic invariants", () => {
    const entry = DEFAULT_LOOP_CATALOG_V02.find((candidate) => candidate.item_id === "safe-bugfix");
    expect(entry).toBeDefined();
    const completedState = {
      state: "completed",
      condition_mode: "all",
      conditions: [{ source: "task", ref: "implement", outcome: "completed" }],
      priority: 100,
    };
    const retryClasses = [
      "transient-adapter",
      "transient-network",
      "contention",
      "verification-failed",
      "policy-hold",
      "invalid-input",
      "permanent-execution",
    ] as const;
    const invalidValues = [
      { key: "project.stop-policy", value: { terminal_states: Array.from({ length: 7 }, () => completedState) } },
      {
        key: "project.retry-policy",
        value: {
          rules: retryClasses.map((failureClass) => ({
            task_ref: "implement",
            failure_class: failureClass,
            retryable: false,
            max_task_executions: 2,
            backoff: "fixed",
            base_delay_ms: 1,
            max_delay_ms: 1,
          })),
        },
      },
    ];

    for (const binding of invalidValues) {
      expect(
        validateBindingsForCatalogEntryV02({
          bindings: [{ ...binding, source: "operator", source_ref: null, source_hash: null }],
        }, entry!),
        binding.key,
      ).toEqual({ ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding input is invalid." });
    }
  });
});

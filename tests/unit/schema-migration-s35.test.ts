import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { hashRawBytes } from "../../src/hash.js";

const REQUIRED_GATE_KINDS = [
  "manifest-completeness", "risk-tier-consistency", "approval", "workspace-boundary",
  "context-and-source-freshness", "tool-grant-adherence", "evidence-integrity", "claim-support",
  "unresolved-findings", "secrets-privacy", "redaction-retention", "adapter-capability",
  "report-truthfulness", "ad-hoc-task-provenance", "no-t5", "intake-boundedness",
  "catalog-selection-evidence", "untrusted-instruction-provenance", "autonomy-escalation",
] as const;
const RETRY_CLASSES = ["transient-adapter", "transient-network", "contention", "verification-failed", "policy-hold", "invalid-input", "permanent-execution"] as const;
const HASH = `sha256:${"0".repeat(64)}`;

describe("S35 pure V01 to V02 migration", () => {
  it("returns a hash-bound HOLD for valid V01 with omitted project semantics and mutates nothing", async () => {
    const { migrateV01ToV02 } = await import("../../src/schema/migration.js");
    const source = new Uint8Array(
      readFileSync(join(import.meta.dirname, "../fixtures/valid/specs/minimal-bugfix.loop.yaml")),
    );
    const before = Uint8Array.from(source);

    const result = migrateV01ToV02({
      source_bytes: source,
      source_format: "yaml",
      migration_id: "migration_test",
      migrator_version: "1.0.0",
      created_at: "2026-08-03T12:00:00Z",
      bindings_bytes: new TextEncoder().encode("[]"),
    });

    expect(result).toMatchObject({
      migration_contract_version: "0.1",
      status: "hold-missing-semantics",
      source_version: "0.1",
      target_version: "0.2",
      source_format: "yaml",
      source_hash: hashRawBytes(before),
      input_part: null,
    });
    if (result.status !== "hold-missing-semantics") throw new Error("expected HOLD");
    expect(result.required_inputs.map((entry) => entry.field)).toContain("trigger");
    expect(result.required_inputs.map((entry) => entry.field)).toContain("goal");
    expect(source).toEqual(before);
    expect(result).not.toHaveProperty("output");
    expect(result).not.toHaveProperty("output_hash");
  });

  it("validates a recognized binding before calculating canonical missing semantics", async () => {
    const { migrateV01ToV02 } = await import("../../src/schema/migration.js");
    const source = new Uint8Array(
      readFileSync(join(import.meta.dirname, "../fixtures/valid/specs/minimal-bugfix.loop.yaml")),
    );
    const bindings = new TextEncoder().encode(JSON.stringify([
      { binding: "trigger", value: { type: "operator-invoked", entrypoint: "run-start" } },
    ]));

    const result = migrateV01ToV02({
      source_bytes: source,
      source_format: "yaml",
      migration_id: "migration_trigger",
      migrator_version: "1.0.0",
      created_at: "2026-08-03T12:00:00Z",
      bindings_bytes: bindings,
    });

    expect(result.status).toBe("hold-missing-semantics");
    if (result.status !== "hold-missing-semantics") throw new Error("expected HOLD");
    expect(result.required_inputs.map((entry) => entry.field)).not.toContain("trigger");
    expect(result.required_inputs.map((entry) => entry.field)).toContain("goal");
  });

  it("migrates a complete V01 control inventory when every required V02 semantic is supplied", async () => {
    const { canonicalizeMigratedOutputForTest, migrateV01ToV02 } = await import("../../src/schema/migration.js");
    const fixtureText = readFileSync(join(import.meta.dirname, "../fixtures/valid/specs/minimal-bugfix.loop.yaml"), "utf8");
    const sourceValue = parse(fixtureText) as Record<string, unknown>;
    const originalGate = (sourceValue.gates as Array<Record<string, unknown>>)[0]!;
    sourceValue.gates = REQUIRED_GATE_KINDS.map((kind) => ({ ...originalGate, id: `gate-${kind}` }));
    const source = new TextEncoder().encode(`${JSON.stringify(sourceValue, null, 2)}\n`);
    const evaluator = { role_ref: "fix-owner", evaluator_identity_ref: "actor_evaluator", policy_digest: HASH, export_check_role: null };
    const bindings: Array<Record<string, unknown>> = [
      { binding: "trigger", value: { type: "operator-invoked", entrypoint: "run-start" } },
      { binding: "goal", value: { statement: "Fix one small bug with evidence.", success_criteria: [{ id: "criterion-main", description: "The required evaluation passes.", evaluation_refs: ["best-available-check"], required: true }] } },
      { binding: "gates", value: REQUIRED_GATE_KINDS.map((kind) => ({ gate_id: `gate-${kind}`, applicability: { mode: "always" }, control_kind: kind, risk_tier: "T2", prerequisites: [{ kind: "run-initialized" }], evidence_requirement_refs: ["evidence-main"], evaluator_binding: evaluator })) },
      { binding: "evaluations", value: [{ id: "best-available-check", type: "command", required: true, command: "project-specific", success_condition: "The selected check succeeds.", applicability: { mode: "always" }, prerequisites: [{ kind: "run-initialized" }], evidence_requirement_refs: ["evidence-main"], evaluator_binding: evaluator }] },
      { binding: "evidence-requirements", value: [{ id: "evidence-main", minimum_independent_roots: 1, evidence_kinds: ["command-capture"], source_acquisition_policy: null }] },
      { binding: "progress", value: { observations: [{ id: "progress-main", description: "Observe evaluation status.", source: "evaluation", source_ref: "best-available-check", value_pointer: "/status", value_type: "string", improves_when: { operator: "equals", target: "pass" }, target: { operator: "equals", value: "pass" } }], stall_after_loop_attempts: 1 } },
      { binding: "stop-policy", value: { terminal_states: [
        { state: "completed", condition_mode: "all", conditions: [{ source: "success-criterion", ref: "criterion-main", outcome: "satisfied" }], priority: 100 },
        { state: "held", condition_mode: "any", conditions: [{ source: "gate", ref: "gate-approval", outcome: "hold" }], priority: 300 },
        { state: "blocked", condition_mode: "any", conditions: [{ source: "failure", task_ref: "diagnose", ref: "contention", outcome: "observed" }], priority: 200 },
        { state: "failed", condition_mode: "any", conditions: [{ source: "failure", task_ref: "diagnose", ref: "invalid-input", outcome: "observed" }], priority: 600 },
        { state: "stalled", condition_mode: "any", conditions: [{ source: "progress", ref: "progress-main", outcome: "stalled" }], priority: 400 },
        { state: "exhausted", condition_mode: "any", conditions: [{ source: "limit", ref: "max-loop-attempts", outcome: "reached" }], priority: 500 },
        { state: "aborted", condition_mode: "any", conditions: [{ source: "control", ref: "abort-requested", outcome: "present" }], priority: 700 },
      ] } },
      { binding: "limit-policy", value: { max_loop_attempts: 2, max_elapsed_ms: 60_000, max_tool_calls: 10, max_workers: 1, max_output_bytes: 1_000_000, control_plane_output_reserve_bytes: 1_000, max_tokens: null, max_cost_minor_units: null, cost_currency: null } },
      { binding: "retry-policy", value: { rules: ["diagnose", "verify-fix"].flatMap((task_ref) => RETRY_CLASSES.map((failure_class) => ({ task_ref, failure_class, retryable: false, max_task_executions: 1, backoff: "none", base_delay_ms: 0, max_delay_ms: 0 }))) } },
      { binding: "recovery-policy", value: { resume_from: "last-durable-boundary", require_input_hash_match: true, require_policy_hash_match: true, on_unknown_outcome: "hold", terminal_compensation: "before-terminal-seal", activation_reasons: ["terminal-failure", "terminal-exhaustion", "terminal-stall", "abort-recovery"], max_compensation_workers: 1, reserve: { max_elapsed_ms: 0, max_tool_calls: 0, max_output_bytes: 0, max_tokens: null, max_cost_minor_units: null } } },
      { binding: "artifact-path", artifact_id: "diagnosis-note", value: "artifacts/content/diagnosis.md" },
      { binding: "artifact-path", artifact_id: "verification-result", value: "artifacts/content/verification.json" },
    ];
    for (const taskId of ["diagnose", "verify-fix"]) {
      bindings.push(
        { binding: "task-kind", task_id: taskId, value: "work" },
        { binding: "task-pre-task-gate-refs", task_id: taskId, value: ["gate-approval"] },
        { binding: "side-effect", task_id: taskId, value: { task_id: taskId, effects: [{ effect_id: `effect-${taskId}`, effect_class: "none", description: "No task-owned side effect.", inspectable: true, reversible: false, idempotency: "not-required", last_safe_stop: { kind: "before-task", task_ref: taskId }, compensation_ref: null }] } },
      );
    }

    const result = migrateV01ToV02({ source_bytes: source, source_format: "json", migration_id: "migration_complete", migrator_version: "1.0.0", created_at: "2026-08-03T12:00:00Z", bindings_bytes: new TextEncoder().encode(JSON.stringify(bindings)) });
    expect(result.status).toBe("migrated");
    if (result.status !== "migrated") throw new Error(`${result.reason}: ${result.message}`);
    const canonical = canonicalizeMigratedOutputForTest(result.output);
    expect(canonical).not.toBeNull();
    expect(result.output_hash).toBe(hashRawBytes(new TextEncoder().encode(canonical!)));
    expect(result.output.schema_version).toBe("0.2");
    expect(result.supplied_bindings).toHaveLength(bindings.length);
  });

  it.each([
    ["goal", { binding: "goal", value: {} }, "goal"],
    ["gates", { binding: "gates", value: {} }, "gates"],
    ["evaluations", { binding: "evaluations", value: {} }, "evaluations"],
    ["evidence-requirements", { binding: "evidence-requirements", value: {} }, "evidence_requirements"],
    ["progress", { binding: "progress", value: {} }, "progress"],
    ["stop-policy", { binding: "stop-policy", value: {} }, "stop_policy"],
    ["limit-policy", { binding: "limit-policy", value: {} }, "limit_policy"],
    ["retry-policy", { binding: "retry-policy", value: {} }, "retry_policy"],
    ["recovery-policy", { binding: "recovery-policy", value: {} }, "recovery_policy"],
    ["task-kind", { binding: "task-kind", task_id: "diagnose", value: "invalid" }, "tasks.diagnose.kind"],
    ["task-pre-task-gate-refs", { binding: "task-pre-task-gate-refs", task_id: "diagnose", value: {} }, "tasks.diagnose.pre_task_gate_refs"],
    ["artifact-path", { binding: "artifact-path", artifact_id: "diagnosis-note", value: "invalid" }, "artifacts.diagnosis-note.path"],
    ["side-effect", { binding: "side-effect", task_id: "diagnose", value: {} }, "side_effects.diagnose"],
    ["compensation", { binding: "compensation", compensation_id: "undo-diagnose", value: {} }, "compensations.undo-diagnose"],
  ])("recognizes the %s binding before local value validation", async (_name, binding, field) => {
    const { migrateV01ToV02 } = await import("../../src/schema/migration.js");
    const source = new Uint8Array(
      readFileSync(join(import.meta.dirname, "../fixtures/valid/specs/minimal-bugfix.loop.yaml")),
    );
    const result = migrateV01ToV02({
      source_bytes: source,
      source_format: "yaml",
      migration_id: "migration_binding_matrix",
      migrator_version: "1.0.0",
      created_at: "2026-08-03T12:00:00Z",
      bindings_bytes: new TextEncoder().encode(JSON.stringify([binding])),
    });

    expect(result).toMatchObject({
      status: "rejected",
      reason: "INVALID_BINDING_VALUE",
      input_part: "bindings",
      field,
    });
  });

  it("rejects a locally shaped compensation with unresolved references before HOLD", async () => {
    const { migrateV01ToV02 } = await import("../../src/schema/migration.js");
    const source = new Uint8Array(
      readFileSync(join(import.meta.dirname, "../fixtures/valid/specs/minimal-bugfix.loop.yaml")),
    );
    const result = migrateV01ToV02({
      source_bytes: source,
      source_format: "yaml",
      migration_id: "migration_bad_compensation_refs",
      migrator_version: "1.0.0",
      created_at: "2026-08-03T12:00:00Z",
      bindings_bytes: new TextEncoder().encode(JSON.stringify([{
        binding: "compensation",
        compensation_id: "undo-diagnose",
        value: {
          id: "undo-diagnose",
          for_task: "missing-task",
          for_effect: "missing-effect",
          action_task: "missing-action",
          preconditions: [{
            source: "effect",
            task_ref: "missing-task",
            effect_ref: "missing-effect",
            outcome: "committed",
          }],
          verification_refs: ["missing-evaluation"],
          may_fail: true,
        },
      }])),
    });

    expect(result).toMatchObject({
      status: "rejected",
      reason: "INVALID_BINDING_VALUE",
      input_part: "bindings",
      field: "compensations.undo-diagnose",
    });
  });
});

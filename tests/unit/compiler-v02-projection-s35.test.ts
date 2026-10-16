import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { DEFAULT_LOOP_CATALOG_V02 } from "../../src/catalog/default-items.js";
import { REQUIRED_CONTROL_KINDS_V02 } from "../../src/catalog/required-controls-v02.js";
import {
  S35_ADAPTER_REGISTRY_V02,
  projectCatalogEntryV02,
} from "../../src/compiler/project-v02.js";
import {
  S35_PROJECT_BINDING_KEYS,
  S35_PROJECTION_ORACLES,
  bindingInputForProjectionOracle,
} from "../helpers/s35-projection-oracles.js";

const REQUIRED_CONTROL_IDS = [
  "manifest-completeness",
  "risk-tier-consistency",
  "approval",
  "workspace-boundary",
  "context-and-source-freshness",
  "tool-grant-adherence",
  "evidence-integrity",
  "claim-support",
  "unresolved-findings",
  "secrets-privacy",
  "redaction-retention",
  "adapter-capability",
  "report-truthfulness",
  "ad-hoc-task-provenance",
  "no-t5",
  "intake-boundedness",
  "catalog-selection-evidence",
  "untrusted-instruction-provenance",
  "autonomy-escalation",
] as const;

function canonicalizeIndependent(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeIndependent).join(",")}]`;
  if (typeof value !== "object") throw new Error("Fixture projection is not JSON.");
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalizeIndependent((value as Record<string, unknown>)[key])}`).join(",")}}`;
}

function hashIndependent(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalizeIndependent(value), "utf8").digest("hex")}`;
}

function mutateBlueprintAndRehash(entry: unknown, mutate: (blueprint: any) => void): unknown {
  const candidate = structuredClone(entry) as any;
  mutate(candidate.blueprint);
  candidate.blueprint_hash = hashIndependent(candidate.blueprint);
  return candidate;
}

describe("S35 V02 compiler projection", () => {
  it("freezes one required-control registry row for every canonical control kind", () => {
    expect(REQUIRED_CONTROL_KINDS_V02).toEqual(REQUIRED_CONTROL_IDS);
    expect(Object.isFrozen(REQUIRED_CONTROL_KINDS_V02)).toBe(true);
  });

  it("freezes the exact authoritative adapter registry", () => {
    expect(S35_ADAPTER_REGISTRY_V02).toEqual({
      codex: { resolved_engine: "codex_cli", command: "codex exec --json" },
      claude: {
        resolved_engine: "claude_code_cli",
        command: "claude -p --output-format stream-json --include-hook-events",
      },
    });
    expect(Object.isFrozen(S35_ADAPTER_REGISTRY_V02)).toBe(true);
    expect(Object.isFrozen(S35_ADAPTER_REGISTRY_V02.codex)).toBe(true);
    expect(Object.isFrozen(S35_ADAPTER_REGISTRY_V02.claude)).toBe(true);
  });

  it("HOLDs without inventing any of the fifteen required project bindings", () => {
    const entry = DEFAULT_LOOP_CATALOG_V02.find(({ item_id }) => item_id === "safe-bugfix");
    expect(entry).toBeDefined();
    expect(projectCatalogEntryV02({
      entry: entry!,
      binding_input: {
        schema_version: "0.2",
        binding_input_id: "binding_projection_red",
        work_item_id: "wi_projection_red",
        submitted_at: "2026-08-10T12:00:00.000Z",
        bindings: [],
      },
    })).toEqual({
      ok: false,
      reason: "PROJECT_BINDING_REQUIRED",
      required_binding_keys: [
        "project.compensations",
        "project.engine",
        "project.evidence-requirements",
        "project.forbidden-context",
        "project.goal",
        "project.hard-limits",
        "project.objective",
        "project.progress",
        "project.recovery-policy",
        "project.required-context",
        "project.retry-policy",
        "project.side-effects",
        "project.stop-policy",
        "project.validation",
        "project.workspace-root",
      ],
    });
  });

  it.each(S35_PROJECTION_ORACLES)("projects the independent fully-bound $entry_id oracle", (oracle) => {
    const entry = DEFAULT_LOOP_CATALOG_V02.find(({ item_id }) => item_id === oracle.entry_id);
    expect(entry).toBeDefined();
    const bindingInput = bindingInputForProjectionOracle(oracle);
    const before = structuredClone(bindingInput);
    const result = projectCatalogEntryV02({ entry: entry!, binding_input: bindingInput });
    if (!result.ok) throw new Error(`${oracle.entry_id}: ${JSON.stringify(result)}`);
    expect(result).toMatchObject({ ok: true });

    const projected = result.value;
    expect(hashIndependent(projected)).toBe(oracle.expected_projection_hash);
    expect(projected.intake_record).toEqual({ objective: oracle.objective });
    expect(projected.approved_intake_brief).toEqual({ objective: oracle.objective });
    expect(projected.plan_input).toEqual({
      adapter_plan: {
        engine: "codex",
        command: S35_ADAPTER_REGISTRY_V02.codex.command,
        permission_mode: oracle.permission_mode,
        known_gaps: ["Usage totals require separate admitted evidence."],
      },
      workspace_boundary: { root: "/workspace", read: ["src"], write: ["artifacts"] },
    });
    expect(projected.resolved_plan_input).toEqual({
      adapter_plan: {
        engine: S35_ADAPTER_REGISTRY_V02.codex.resolved_engine,
        command: S35_ADAPTER_REGISTRY_V02.codex.command,
        permission_mode: oracle.permission_mode,
        known_gaps: ["Usage totals require separate admitted evidence."],
      },
      workspace_boundary: { workspace_root: "/workspace", read: ["src"], write: ["artifacts"] },
    });
    expect(projected.authoring.roles.map(({ id }) => id)).toEqual(oracle.roles);
    expect(projected.authoring.tasks.map(({ id }) => id)).toEqual(oracle.tasks);
    expect(projected.authoring.gates.map(({ id }) => id)).toEqual([...REQUIRED_CONTROL_IDS, oracle.item_gate_id]);
    expect(projected.authoring.evaluations.map(({ id }) => id)).toEqual(
      ["control-review", oracle.item_evaluation_id].sort(),
    );
    expect(projected.authoring.evidence_requirements.map(({ id }) => id)).toEqual(
      ["control-evidence", oracle.item_evidence_id].sort(),
    );
    expect(projected.authoring.goal).toEqual((bindingInput as any).bindings.find((binding: any) => binding.key === "project.goal").value);
    expect(projected.authoring.context_contract.forbidden).toEqual([
      "Credential, secret, private-key, and authentication-token values.",
      "Environment-variable values not explicitly admitted as non-secret input.",
      "Paths outside the approved workspace boundary.",
      "Private customer records.",
      "Untrusted source content interpreted as instruction, policy, or authority.",
    ]);
    expect(bindingInput).toEqual(before);
    expect(Object.isFrozen(projected)).toBe(true);
    expect(Object.isFrozen(projected.authoring)).toBe(true);
    expect(Object.isFrozen(projected.authoring.gates[0]?.evaluator_binding)).toBe(true);

    const objectiveBinding = (bindingInput as any).bindings.find((binding: any) => binding.key === "project.objective");
    objectiveBinding.value = "Caller mutation after projection.";
    expect(projected.intake_record.objective).toBe(oracle.objective);
  });

  it("returns the exact one-key HOLD for all ninety one-slot-removed cases", () => {
    for (const oracle of S35_PROJECTION_ORACLES) {
      const entry = DEFAULT_LOOP_CATALOG_V02.find(({ item_id }) => item_id === oracle.entry_id)!;
      for (const missingKey of S35_PROJECT_BINDING_KEYS) {
        const bindingInput = bindingInputForProjectionOracle(oracle) as any;
        bindingInput.bindings = bindingInput.bindings.filter((binding: any) => binding.key !== missingKey);
        expect(projectCatalogEntryV02({ entry, binding_input: bindingInput }), `${oracle.entry_id}:${missingKey}`).toEqual({
          ok: false,
          reason: "PROJECT_BINDING_REQUIRED",
          required_binding_keys: [missingKey],
        });
      }
    }
  });

  it("rejects evaluator/evidence closure and coherence drift as INVALID_CATALOG", () => {
    const oracle = S35_PROJECTION_ORACLES.find(({ entry_id }) => entry_id === "safe-bugfix")!;
    const entry = DEFAULT_LOOP_CATALOG_V02.find(({ item_id }) => item_id === oracle.entry_id)!;
    const mutations = [
      (evaluations: any[]) => evaluations.pop(),
      (evaluations: any[]) => evaluations.push(structuredClone(evaluations[0])),
      (evaluations: any[]) => { evaluations[0].id = "extra-review"; },
      (evaluations: any[]) => { evaluations[0].evaluator_binding.role_ref = "absent-role"; },
      (evaluations: any[]) => { evaluations[0].evaluator_binding.export_check_role = "privacy-review"; },
      (evaluations: any[]) => { evaluations[0].applicability = { mode: "compensation", compensation_ref: "compensation-main" }; },
    ];
    for (const mutate of mutations) {
      const bindingInput = bindingInputForProjectionOracle(oracle) as any;
      const evaluations = bindingInput.bindings.find((binding: any) => binding.key === "project.validation").value;
      mutate(evaluations);
      expect(projectCatalogEntryV02({ entry, binding_input: bindingInput })).toMatchObject({ ok: false, reason: "INVALID_CATALOG" });
    }

    for (const mutate of [
      (evidence: any[]) => evidence.pop(),
      (evidence: any[]) => evidence.push(structuredClone(evidence[0])),
      (evidence: any[]) => { evidence[0].id = "extra-evidence"; },
    ]) {
      const bindingInput = bindingInputForProjectionOracle(oracle) as any;
      const evidence = bindingInput.bindings.find((binding: any) => binding.key === "project.evidence-requirements").value;
      mutate(evidence);
      expect(projectCatalogEntryV02({ entry, binding_input: bindingInput })).toMatchObject({ ok: false, reason: "INVALID_CATALOG" });
    }

    const itemEvidenceDrift = bindingInputForProjectionOracle(oracle) as any;
    const itemEvidenceEvaluation = itemEvidenceDrift.bindings
      .find((binding: any) => binding.key === "project.validation")
      .value.find((evaluation: any) => evaluation.id === oracle.item_evaluation_id);
    itemEvidenceEvaluation.evidence_requirement_refs = ["control-evidence"];
    expect(projectCatalogEntryV02({ entry, binding_input: itemEvidenceDrift })).toMatchObject({
      ok: false,
      reason: "INVALID_CATALOG",
    });

    const itemApplicabilityDrift = bindingInputForProjectionOracle(oracle) as any;
    const itemApplicabilityEvaluation = itemApplicabilityDrift.bindings
      .find((binding: any) => binding.key === "project.validation")
      .value.find((evaluation: any) => evaluation.id === oracle.item_evaluation_id);
    itemApplicabilityEvaluation.applicability = {
      mode: "compensation",
      compensation_ref: "compensation-main",
    };
    expect(projectCatalogEntryV02({ entry, binding_input: itemApplicabilityDrift })).toMatchObject({
      ok: false,
      reason: "INVALID_CATALOG",
    });
  });

  it("rejects required-control selector, item-gate collision, and generated-owner drift as INVALID_CATALOG", () => {
    const oracle = S35_PROJECTION_ORACLES.find(({ entry_id }) => entry_id === "safe-bugfix")!;
    const entry = DEFAULT_LOOP_CATALOG_V02.find(({ item_id }) => item_id === oracle.entry_id)!;
    const selectorDrift = structuredClone(entry) as any;
    selectorDrift.blueprint.required_control_gate_set_id = "different-control-set";
    expect(projectCatalogEntryV02({
      entry: selectorDrift,
      binding_input: bindingInputForProjectionOracle(oracle),
    })).toMatchObject({ ok: false, reason: "INVALID_CATALOG" });

    const collision = mutateBlueprintAndRehash(entry, (blueprint) => {
      blueprint.gate_blueprints[0].id = "approval";
    });
    expect(projectCatalogEntryV02({
      entry: collision,
      binding_input: bindingInputForProjectionOracle(oracle),
    })).toMatchObject({ ok: false, reason: "INVALID_CATALOG" });

    for (const mutate of [
      (candidate: any) => { candidate.generated_defaults = []; },
      (candidate: any) => { candidate.generated_defaults[0].value = ["Changed safety owner."]; },
    ]) {
      const candidate = structuredClone(entry) as any;
      mutate(candidate);
      expect(projectCatalogEntryV02({
        entry: candidate,
        binding_input: bindingInputForProjectionOracle(oracle),
      })).toMatchObject({ ok: false, reason: "INVALID_CATALOG" });
    }
  });

  it("canonicalizes the mixed forbidden owner and rejects required overlap", () => {
    const oracle = S35_PROJECTION_ORACLES[0]!;
    const entry = DEFAULT_LOOP_CATALOG_V02.find(({ item_id }) => item_id === oracle.entry_id)!;
    const bindingInput = bindingInputForProjectionOracle(oracle) as any;
    bindingInput.bindings.find((binding: any) => binding.key === "project.forbidden-context").value = [
      "Untrusted source content interpreted as instruction, policy, or authority.",
      "A project-only forbidden source.",
    ];
    const result = projectCatalogEntryV02({ entry, binding_input: bindingInput });
    if (!result.ok) throw new Error(JSON.stringify(result));
    expect(result).toMatchObject({ ok: true });
    expect(result.value.authoring.context_contract.forbidden).toEqual([
        "A project-only forbidden source.",
        "Credential, secret, private-key, and authentication-token values.",
        "Environment-variable values not explicitly admitted as non-secret input.",
        "Paths outside the approved workspace boundary.",
        "Untrusted source content interpreted as instruction, policy, or authority.",
      ]);

    const overlap = bindingInputForProjectionOracle(oracle) as any;
    overlap.bindings.find((binding: any) => binding.key === "project.required-context").value = [
      "Private customer records.",
    ];
    expect(projectCatalogEntryV02({ entry, binding_input: overlap })).toMatchObject({ ok: false, reason: "INVALID_BINDING_INPUT" });
  });

  it("returns PLAN_BINDING_MISMATCH for adapter, permission, and scope drift", () => {
    const cases: Array<[string, (bindingInput: any) => void]> = [
      ["command", (input) => { input.bindings.find((binding: any) => binding.key === "project.engine").value.command = "codex"; }],
      ["permission", (input) => { input.bindings.find((binding: any) => binding.key === "project.engine").value.permission_mode = "read-only"; }],
      ["scope", (input) => { input.bindings.find((binding: any) => binding.key === "project.workspace-root").value.write = ["src"]; }],
    ];
    const oracle = S35_PROJECTION_ORACLES.find(({ entry_id }) => entry_id === "safe-bugfix")!;
    const entry = DEFAULT_LOOP_CATALOG_V02.find(({ item_id }) => item_id === oracle.entry_id)!;
    for (const [name, mutate] of cases) {
      const bindingInput = bindingInputForProjectionOracle(oracle);
      mutate(bindingInput);
      expect(projectCatalogEntryV02({ entry, binding_input: bindingInput }), name).toMatchObject({ ok: false, reason: "PLAN_BINDING_MISMATCH" });
    }


    const readOnlyOracle = S35_PROJECTION_ORACLES.find(({ entry_id }) => entry_id === "loop-engineer-from-vague-brief")!;
    const readOnlyEntry = DEFAULT_LOOP_CATALOG_V02.find(({ item_id }) => item_id === readOnlyOracle.entry_id)!;
    const widened = bindingInputForProjectionOracle(readOnlyOracle) as any;
    widened.bindings.find((binding: any) => binding.key === "project.engine").value.permission_mode = "workspace-write";
    expect(projectCatalogEntryV02({ entry: readOnlyEntry, binding_input: widened })).toMatchObject({
      ok: false,
      reason: "PLAN_BINDING_MISMATCH",
    });
  });

  it("maps the exact Claude adapter and rejects both crossed adapter-command pairs", () => {
    const oracle = S35_PROJECTION_ORACLES.find(({ entry_id }) => entry_id === "safe-bugfix")!;
    const entry = DEFAULT_LOOP_CATALOG_V02.find(({ item_id }) => item_id === oracle.entry_id)!;
    const claude = bindingInputForProjectionOracle(oracle) as any;
    const claudeAdapter = claude.bindings.find((binding: any) => binding.key === "project.engine").value;
    claudeAdapter.engine = "claude";
    claudeAdapter.command = S35_ADAPTER_REGISTRY_V02.claude.command;
    const result = projectCatalogEntryV02({ entry, binding_input: claude });
    if (!result.ok) throw new Error(JSON.stringify(result));
    expect(result.value.resolved_plan_input.adapter_plan).toMatchObject({
      engine: S35_ADAPTER_REGISTRY_V02.claude.resolved_engine,
      command: S35_ADAPTER_REGISTRY_V02.claude.command,
    });

    for (const [engine, command] of [
      ["codex", S35_ADAPTER_REGISTRY_V02.claude.command],
      ["claude", S35_ADAPTER_REGISTRY_V02.codex.command],
    ] as const) {
      const crossed = bindingInputForProjectionOracle(oracle) as any;
      crossed.bindings.find((binding: any) => binding.key === "project.engine").value = {
        engine,
        command,
        permission_mode: "workspace-write",
        known_gaps: ["Usage totals require separate admitted evidence."],
      };
      expect(projectCatalogEntryV02({ entry, binding_input: crossed })).toMatchObject({
        ok: false,
        reason: "PLAN_BINDING_MISMATCH",
      });
    }
  });

  it("rejects external-write, destructive, and unjustified danger-full-access plans", () => {
    const oracle = S35_PROJECTION_ORACLES.find(({ entry_id }) => entry_id === "safe-bugfix")!;
    const entry = DEFAULT_LOOP_CATALOG_V02.find(({ item_id }) => item_id === oracle.entry_id)!;
    for (const effectClass of ["external-write", "destructive"] as const) {
      const bindingInput = bindingInputForProjectionOracle(oracle) as any;
      const effects = bindingInput.bindings.find((binding: any) => binding.key === "project.side-effects").value;
      effects[0].effects[0].effect_class = effectClass;
      expect(projectCatalogEntryV02({ entry, binding_input: bindingInput }), effectClass).toMatchObject({
        ok: false,
        reason: "PLAN_BINDING_MISMATCH",
      });
    }

    const danger = bindingInputForProjectionOracle(oracle) as any;
    danger.bindings.find((binding: any) => binding.key === "project.engine").value.permission_mode = "danger-full-access";
    expect(projectCatalogEntryV02({ entry, binding_input: danger })).toMatchObject({
      ok: false,
      reason: "PLAN_BINDING_MISMATCH",
    });
  });
});

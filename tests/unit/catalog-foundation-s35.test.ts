import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  LoopCatalogEntrySchema,
  LoopCatalogEntrySchemaV01,
} from "../../src/catalog/item.js";
import {
  CatalogBlueprintV02,
  CatalogEntryV02,
  CatalogSnapshotV02,
  compareUtf8BytesV02,
} from "../../src/catalog/item-v02.js";
import {
  DEFAULT_CATALOG_SNAPSHOT_V02,
  DEFAULT_LOOP_CATALOG,
  DEFAULT_LOOP_CATALOG_V01,
  DEFAULT_LOOP_CATALOG_V02,
  S35_COMPILER_BUNDLE_ID_V02,
} from "../../src/catalog/default-items.js";
import { lookupFrozenCatalogV01, lookupRegisteredCatalogV02 } from "../../src/catalog/registry.js";
import { V01_CATALOG_VERSION_HASH } from "../../src/compiler/strategy-v01.js";
import { resolveCatalogV02 } from "../../src/compiler/strategy-v02.js";
import { validateBindingsForCatalogEntryV02 } from "../../src/compiler/binding-input-v02.js";

const requiredSlots = [
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
];

const expectedEntryIds = [
  "adapter-truth-probe",
  "claims-check-pr",
  "expert-sprint",
  "loop-engineer-from-vague-brief",
  "research-need-cluster",
  "safe-bugfix",
];

const expectedSafetyContext = [
  "Credential, secret, private-key, and authentication-token values.",
  "Environment-variable values not explicitly admitted as non-secret input.",
  "Paths outside the approved workspace boundary.",
  "Untrusted source content interpreted as instruction, policy, or authority.",
];

const expectedTopologies = {
  "adapter-truth-probe": {
    phases: ["capability-probe", "gap-test", "independent-review", "report"],
    roles: ["capability-analyst", "fixture-tester", "gap-reviewer", "report-author"],
    tasks: ["probe-capabilities", "test-capture-gaps", "review-claim-strength", "report-proof-boundary"],
    gate: "no-strength-beyond-observation",
  },
  "claims-check-pr": {
    phases: ["extract", "trace", "contradict", "report"],
    roles: ["claim-analyst", "evidence-tracer", "contradiction-reviewer", "report-author"],
    tasks: ["extract-claims", "trace-evidence", "test-contradictions", "report-verdicts"],
    gate: "evidence-only-verdicts",
  },
  "expert-sprint": {
    phases: ["phase-zero", "contracts", "disjoint-build", "independent-qa"],
    roles: ["phase-zero-analyst", "contract-architect", "builder", "independent-qa"],
    tasks: ["produce-findings", "freeze-contracts", "build-disjoint-work", "perform-independent-qa"],
    gate: "qa-independence",
  },
  "loop-engineer-from-vague-brief": {
    phases: ["intake", "clarification", "contract", "review"],
    roles: ["intake-analyst", "contract-architect", "independent-reviewer"],
    tasks: ["bound-intake", "resolve-clarifications", "author-loop-contract", "review-loop-contract"],
    gate: "human-intake-approval",
  },
  "research-need-cluster": {
    phases: ["source-plan", "collect", "corroborate", "synthesize"],
    roles: ["source-planner", "source-researcher", "corroborator", "synthesizer"],
    tasks: ["plan-sources", "collect-sources", "corroborate-findings", "synthesize-need-clusters"],
    gate: "source-diversity",
  },
  "safe-bugfix": {
    phases: ["diagnose", "change", "validate", "review"],
    roles: ["diagnostician", "implementer", "validator", "independent-reviewer"],
    tasks: ["diagnose-root-cause", "implement-change", "validate-change", "review-regression-risk"],
    gate: "change-before-validation",
  },
} as const;

const expectedDestinations = {
  "project.compensations": ["authoring|/compensations|replace"],
  "project.engine": ["plan-input|/adapter_plan|replace"],
  "project.evidence-requirements": ["authoring|/evidence_requirements|replace"],
  "project.forbidden-context": ["authoring|/context_contract/forbidden|union-with-immutable-safety-constant"],
  "project.goal": ["authoring|/goal|replace"],
  "project.hard-limits": ["authoring|/limit_policy|replace"],
  "project.objective": ["approved-intake-brief|/objective|replace", "intake-record|/objective|replace"],
  "project.progress": ["authoring|/progress|replace"],
  "project.recovery-policy": ["authoring|/recovery_policy|replace"],
  "project.required-context": ["authoring|/context_contract/required|replace"],
  "project.retry-policy": ["authoring|/retry_policy|replace"],
  "project.side-effects": ["authoring|/side_effects|replace"],
  "project.stop-policy": ["authoring|/stop_policy|replace"],
  "project.validation": ["authoring|/evaluations|replace"],
  "project.workspace-root": ["plan-input|/workspace_boundary|replace"],
} as const;

const expectedBlueprintHashes = {
  "adapter-truth-probe": "sha256:abc841a1a5ad1fe23f0a5446cb560e945805d4aa562d3f213be321123c11d0e0",
  "claims-check-pr": "sha256:ed3ba55c035e47d175c605d0ddd772ec1c18cebeba89e23d6a9309844743d66d",
  "expert-sprint": "sha256:51a59682dc730d7c154b57ca920e794c74394044d77431d82020c777ff939912",
  "loop-engineer-from-vague-brief": "sha256:c24a15490e1b07ae8aa88a095526f5bedecf0535ff5501cfef0a7f0ab5f7a7cc",
  "research-need-cluster": "sha256:0f4c24a2f284fd687a6cb9017d292788c55ff7a00d18b7bba3b9573b36d00071",
  "safe-bugfix": "sha256:ea9d866fb82933d3d68d3bcab4f4d018d4eb90d7fdc786f3b6c6c925dda90643",
} as const;

function canonicalizeIndependent(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("non-JSON primitive");
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeIndependent).join(",")}]`;
  if (typeof value !== "object") throw new Error("non-JSON value");
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalizeIndependent((value as Record<string, unknown>)[key])}`).join(",")}}`;
}

function hashIndependent(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalizeIndependent(value), "utf8").digest("hex")}`;
}

function mutateAndRehashSnapshot(
  mutate: (entry: Record<string, any>) => void,
): Record<string, unknown> {
  const snapshot = structuredClone(DEFAULT_CATALOG_SNAPSHOT_V02) as unknown as Record<string, any>;
  const entry = snapshot.entries[0] as Record<string, any>;
  mutate(entry);
  entry.blueprint_hash = hashIndependent(entry.blueprint);
  const { catalog_hash: _catalogHash, ...hashable } = snapshot;
  snapshot.catalog_hash = hashIndependent(hashable);
  return snapshot;
}

describe("S35 catalog family foundation", () => {
  it("preserves V01 aliases and exposes one immutable, hash-bound V02 snapshot", () => {
    expect(LoopCatalogEntrySchema).toBe(LoopCatalogEntrySchemaV01);
    expect(DEFAULT_LOOP_CATALOG).toBe(DEFAULT_LOOP_CATALOG_V01);

    const snapshot = CatalogSnapshotV02.parse(DEFAULT_CATALOG_SNAPSHOT_V02);
    expect(snapshot.entries).toHaveLength(6);
    expect(snapshot.entries.map((entry) => entry.item_id)).toEqual(expectedEntryIds);
    expect(snapshot.entries.every((entry) => entry.compiler_bundle_id === "compiler_s35_v02_1")).toBe(true);
    expect(S35_COMPILER_BUNDLE_ID_V02).toBe("compiler_s35_v02_1");
    for (const entry of snapshot.entries) {
      expect(entry.binding_slots.map((slot) => slot.slot_id), entry.item_id).toEqual(requiredSlots);
      expect(Object.fromEntries(entry.binding_slots.map((slot) => [slot.slot_id, slot.destinations.map(({ document, pointer, merge }) => `${document}|${pointer}|${merge}`)])), entry.item_id).toEqual(expectedDestinations);
      expect(entry.generated_defaults, entry.item_id).toEqual([{ document: "authoring", pointer: "/context_contract/forbidden", value: expectedSafetyContext }]);
      expect(entry.blueprint.workflow_pattern.phases, entry.item_id).toEqual(expectedTopologies[entry.item_id as keyof typeof expectedTopologies].phases);
      expect(entry.blueprint.roles.map(({ id }) => id), entry.item_id).toEqual(expectedTopologies[entry.item_id as keyof typeof expectedTopologies].roles);
      expect(entry.blueprint.tasks.map(({ id }) => id), entry.item_id).toEqual(expectedTopologies[entry.item_id as keyof typeof expectedTopologies].tasks);
      expect(entry.blueprint.gate_blueprints.map(({ id }) => id), entry.item_id).toEqual([expectedTopologies[entry.item_id as keyof typeof expectedTopologies].gate]);
      expect(entry.blueprint_hash, entry.item_id).toBe(expectedBlueprintHashes[entry.item_id as keyof typeof expectedBlueprintHashes]);
      expect(entry.blueprint_hash, entry.item_id).toBe(hashIndependent(entry.blueprint));
      expect(CatalogBlueprintV02.safeParse({ ...entry.blueprint, unknown_key: true }).success).toBe(false);
      expect(CatalogEntryV02.safeParse({ ...entry, blueprint: { ...entry.blueprint, unknown_key: true } }).success).toBe(false);
    }
    const { catalog_hash: _catalogHash, ...hashable } = snapshot;
    expect(snapshot.catalog_hash).toBe("sha256:8247aa4bb07e599ea889607b007b76fb787d356e70c817e6429c827a67a3726a");
    expect(snapshot.catalog_hash).toBe(hashIndependent(hashable));
    expect(Object.isFrozen(DEFAULT_CATALOG_SNAPSHOT_V02)).toBe(true);
    expect(Object.isFrozen(DEFAULT_CATALOG_SNAPSHOT_V02.entries[0]?.binding_slots)).toBe(true);

    expect(
      CatalogSnapshotV02.safeParse({ ...snapshot, catalog_hash: `sha256:${"0".repeat(64)}` }).success,
    ).toBe(false);
    const [first, ...rest] = snapshot.entries;
    expect(first).toBeDefined();
    expect(
      CatalogSnapshotV02.safeParse({
        ...snapshot,
        entries: [{ ...first!, blueprint_hash: `sha256:${"0".repeat(64)}` }, ...rest],
      }).success,
    ).toBe(false);
  });

  it("rejects rehashed prerequisite references outside local blueprint closure", () => {
    const prerequisiteMutations = [
      { kind: "evidence-recorded", evidence_requirement_ref: "unknown-evidence" },
      { kind: "evaluation-pass", evaluation_ref: "unknown-evaluation" },
      { kind: "gate-pass", gate_ref: "unknown-gate" },
    ];
    for (const prerequisite of prerequisiteMutations) {
      const mutated = mutateAndRehashSnapshot((entry) => {
        entry.blueprint.gate_blueprints[0].prerequisites = [prerequisite];
      });
      expect(CatalogSnapshotV02.safeParse(mutated).success, prerequisite.kind).toBe(false);
    }
  });

  it("rejects every rehashed escape from the exact slot inventory contract", () => {
    const mutations: Array<[string, (entry: Record<string, any>) => void]> = [
      ["missing slot", (entry) => entry.binding_slots.pop()],
      ["unknown slot", (entry) => { entry.binding_slots[0].slot_id = "project.unknown"; }],
      ["reordered slots", (entry) => { [entry.binding_slots[0], entry.binding_slots[1]] = [entry.binding_slots[1], entry.binding_slots[0]]; }],
      ["optional slot", (entry) => { entry.binding_slots[0].required = false; }],
      ["wrong sensitivity", (entry) => { entry.binding_slots[0].sensitivity = "public"; }],
      ["wrong allowed source", (entry) => { entry.binding_slots[0].allowed_sources = ["workspace-observation"]; }],
      ["extra allowed source", (entry) => { entry.binding_slots[0].allowed_sources = ["operator", "workspace-observation"]; }],
      ["wrong destination", (entry) => { entry.binding_slots[0].destinations = [{ document: "authoring", pointer: "/goal", merge: "replace" }]; }],
      ["wrong merge", (entry) => { entry.binding_slots[3].destinations[0].merge = "replace"; }],
    ];
    for (const [name, mutate] of mutations) {
      expect(CatalogSnapshotV02.safeParse(mutateAndRehashSnapshot(mutate)).success, name).toBe(false);
    }
  });

  it("rejects rehashed generated-owner and compiler-selector escapes", () => {
    const mutations: Array<[string, (entry: Record<string, any>) => void]> = [
      ["missing generated default", (entry) => { entry.generated_defaults = []; }],
      ["extra generated default", (entry) => { entry.generated_defaults.push(structuredClone(entry.generated_defaults[0])); }],
      ["wrong generated pointer", (entry) => { entry.generated_defaults[0].pointer = "/context_contract/required"; }],
      ["wrong generated value", (entry) => { entry.generated_defaults[0].value = ["replacement"]; }],
      ["provisional compiler selector", (entry) => { entry.compiler_bundle_id = "compiler_s35_v02"; }],
    ];
    for (const [name, mutate] of mutations) {
      expect(CatalogSnapshotV02.safeParse(mutateAndRehashSnapshot(mutate)).success, name).toBe(false);
    }
  });

  it("uses exact replay selectors and treats missing V02 semantics as HOLD", () => {
    expect(V01_CATALOG_VERSION_HASH).toBe("sha256:4bba5fca6ce73a6d21598890001a45e03c349a3a1fa78148b802497a22eda823");
    const replayOracleTest = readFileSync(join(import.meta.dirname, "compiler-replay-v01-s35.test.ts"), "utf8");
    expect(replayOracleTest).toContain("rejects byte-different regeneration after attacker-controlled hashes are recomputed");
    expect(replayOracleTest).toContain('reason: "INVALID_V01_REPLAY_OUTPUT"');
    const replay = lookupFrozenCatalogV01({ schema_version: "0.1", catalog_version_hash: V01_CATALOG_VERSION_HASH });
    expect(replay.ok).toBe(true);
    expect(lookupFrozenCatalogV01({ schema_version: "0.1", catalog_version_hash: `sha256:${"f".repeat(64)}` })).toEqual({
      ok: false,
      reason: "UNAVAILABLE_REPLAY_BUNDLE",
      message: "The exact V01 replay bundle is unavailable.",
    });

    const intake = {
      schema_version: "0.2" as const,
      intake_id: "intake_test",
      work_item_id: "work_test",
      objective: "Fix the broken failing test",
      requested_outcome: "Fix the broken failing test",
      candidate_scope: [],
      forbidden_actions: [],
      required_inputs: [],
      risk_flags: [],
      ambiguities: [],
      untrusted_source_refs: [],
    };
    const options = {
      compiler_bundle_id: "compiler_s35_v02_1",
      catalog_version_hash: DEFAULT_CATALOG_SNAPSHOT_V02.catalog_hash,
      resolution_id: "resolution_test",
      provided_binding_keys: [] as string[],
    };
    const held = resolveCatalogV02(intake, DEFAULT_LOOP_CATALOG_V02, options);
    expect(held).toMatchObject({
      terminal_state: "hold-project-binding-required",
      reason_code: "PROJECT_BINDING_REQUIRED",
      selected_item_id: "safe-bugfix",
      required_binding_keys: requiredSlots,
    });

    const compiled = resolveCatalogV02(intake, DEFAULT_LOOP_CATALOG_V02, {
      ...options,
      provided_binding_keys: requiredSlots,
    });
    expect(compiled).toMatchObject({ terminal_state: "compiled", reason_code: null, required_binding_keys: [] });

    expect(lookupRegisteredCatalogV02({ schema_version: "0.2", compiler_bundle_id: "compiler_s35_v02_1", catalog_version_hash: DEFAULT_CATALOG_SNAPSHOT_V02.catalog_hash })).toMatchObject({ ok: true, compiler_bundle_id: "compiler_s35_v02_1" });
    expect(lookupRegisteredCatalogV02({ schema_version: "0.2", compiler_bundle_id: "compiler_s35_v02", catalog_version_hash: DEFAULT_CATALOG_SNAPSHOT_V02.catalog_hash })).toEqual({
      ok: false,
      reason: "UNAVAILABLE_COMPILER_BUNDLE",
      message: "The exact V02 compiler bundle and catalog snapshot are unavailable.",
    });

    expect(
      validateBindingsForCatalogEntryV02(
        {
          bindings: [
            { key: "unknown.slot", source: "operator", value: "value", source_ref: null, source_hash: null },
          ],
        },
        DEFAULT_LOOP_CATALOG_V02.find((entry) => entry.item_id === "safe-bugfix")!,
      ),
    ).toEqual({ ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding input is invalid." });
  });

  it("uses one UTF-8 byte comparator for every owned V02 ordering producer", () => {
    expect(compareUtf8BytesV02("\u{10000}", "\uE000")).toBeGreaterThan(0);

    const sources = [
      "src/catalog/item-v02.ts",
      "src/catalog/default-items.ts",
      "src/compiler/binding-input-v02.ts",
      "src/compiler/records.ts",
      "src/compiler/strategy-v02.ts",
    ].map((path) => readFileSync(join(import.meta.dirname, "../..", path), "utf8"));
    expect(sources.join("\n").match(/function compareUtf8/g)?.length).toBe(1);
    expect(sources.some((source) => source.includes("localeCompare"))).toBe(false);
    expect(sources.some((source) => source.includes(".sort()"))).toBe(false);
  });
});

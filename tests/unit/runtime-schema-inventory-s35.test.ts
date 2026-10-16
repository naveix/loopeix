import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type {
  ResolvedRunPlanDocumentParseResult,
  ResolvedRunPlanV01Value,
  ResolvedRunPlanV02Value,
} from "../../src/index.js";
import { ResolvedRunPlan } from "../../src/index.js";
import { RuntimeSchemaInventoryV02 } from "../../src/schema/runtime.js";

type Assert<T extends true> = T;
type IsAssignable<T, U> = T extends U ? true : false;
type _Task3BPublicTypeContract = [
  Assert<IsAssignable<ResolvedRunPlanV01Value["schema_version"], "0.1">>,
  Assert<IsAssignable<ResolvedRunPlanV02Value["schema_version"], "0.2">>,
  Assert<IsAssignable<ResolvedRunPlanDocumentParseResult, { ok: boolean }>>,
];

const runtimeFixture = JSON.parse(
  readFileSync(join(import.meta.dirname, "../fixtures/valid/runtime/resolved-run-plan-minimal-bugfix.json"), "utf8"),
) as Record<string, unknown>;

describe("S35 runtime resolved-plan family facade", () => {
  it("enumerates exactly 12 embedded and seven manifest-governed V02 families", () => {
    const embedded = [
      "resolved_run_plan",
      "ledger_event",
      "run_manifest",
      "artifact_manifest",
      "redaction_derivative",
      "human_authorization_proof",
      "authority_envelope",
      "agency_recommendation",
      "authority_revocation",
      "task_result",
      "manual_observation",
      "export_decision",
    ] as const;
    const manifestGoverned = [
      "evidence_item",
      "gate_result",
      "evaluation_result",
      "claim",
      "finding",
      "waiver",
      "gate_waiver_authority",
    ] as const;
    const expected = Object.fromEntries([...embedded, ...manifestGoverned].map((family) => [family, "0.2"]));

    expect(embedded).toHaveLength(12);
    expect(manifestGoverned).toHaveLength(7);
    expect(new Set([...embedded, ...manifestGoverned]).size).toBe(19);
    expect(RuntimeSchemaInventoryV02.parse(expected)).toEqual(expected);
    expect(RuntimeSchemaInventoryV02.safeParse({ ...expected, claim: undefined }).success).toBe(false);
    expect(RuntimeSchemaInventoryV02.safeParse({ ...expected, neighbouring_family: "0.2" }).success).toBe(false);
  });

  it("adds only the allowed public resolved-plan runtime values", async () => {
    const root = await import("../../src/index.js");
    const runtime = await import("../../src/schema/runtime.js");

    expect(root.ResolvedRunPlan).toBeDefined();
    expect(root.ResolvedRunPlanV01).toBeDefined();
    expect(root.ResolvedRunPlanV01).toBe(runtime.ResolvedRunPlanV01);
    expect(root.ResolvedRunPlanV02).toBeDefined();
    expect(root.ResolvedRunPlanV02).toBe(runtime.ResolvedRunPlanV02);
    expect(root.parseResolvedRunPlanDocument).toBeDefined();
    expect(root.parseResolvedRunPlanDocument).toBe(runtime.parseResolvedRunPlanDocument);

    for (const privateName of [
      "dispatchResolvedRunPlanValue",
      "RuntimeSchemaInventoryV02Shape",
      "ProgressEvaluationV02Shape",
      "TerminalObservationSnapshotV02Shape",
    ]) {
      expect(privateName in root, privateName).toBe(false);
    }
  });

  it("preserves V01 direct validation while normalizing family-aware parse results in memory", async () => {
    const root = await import("../../src/index.js");

    expect(ResolvedRunPlan.safeParse(runtimeFixture).success).toBe(true);
    expect(root.ResolvedRunPlanV01.safeParse(runtimeFixture).success).toBe(true);

    expect(root.parseResolvedRunPlanDocument(runtimeFixture)).toMatchObject({
      ok: true,
      schema_version: "0.1",
      execution_profile: "legacy-v01",
    });

    const parsed = root.parseResolvedRunPlanDocument(runtimeFixture);
    if (parsed.ok) {
      expect(Object.hasOwn(parsed.value, "execution_profile")).toBe(false);
    }
  });

  it("accepts and strips a profile-looking V01 key through the closed family parser", async () => {
    const root = await import("../../src/index.js");

    const parsed = root.parseResolvedRunPlanDocument({
      ...runtimeFixture,
      execution_profile: "bounded-v02",
    });
    expect(parsed).toMatchObject({
      ok: true,
      schema_version: "0.1",
      execution_profile: "legacy-v01",
    });
    if (parsed.ok) expect(Object.hasOwn(parsed.value, "execution_profile")).toBe(false);
  });
});

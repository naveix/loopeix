import { describe, expect, expectTypeOf, it } from "vitest";

import type {
  RuntimeProjectionErrorV02,
  TerminalObservationSnapshotV02,
  ValidatedRuntimeProjectionInputV02,
} from "../../src/schema/runtime.js";
import { TerminalSnapshotInvalidReasonsV02 } from "../../src/schema/runtime.js";
import {
  buildTerminalObservationSnapshotV02,
  captureSyntheticAuthorityTrustContextForS35TestV02,
  isTerminalObservationSnapshotV02,
  isValidatedRuntimeProjectionInputV02,
  validateRuntimeProjectionInputV02,
} from "../../src/run/terminal-snapshot.js";
import { evaluateTerminalV02 } from "../../src/run/terminal-evaluator.js";
import { buildInitializedRuntimePositiveFixtureS35 } from "../helpers/runtime-positive-fixture-s35.js";

describe("S35 terminal snapshot admission boundary", () => {
  const independentlyRepresentableCompoundStages = [
    2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14,
  ] as const;
  it.each(TerminalSnapshotInvalidReasonsV02.slice(1).map((laterReason) => [laterReason] as const))(
    "selects stage one over a structural %s defect when the private projection brand is absent",
    (laterReason) => {
      const unbrandedCompound = Object.freeze({
        plan: Object.freeze({}),
        events: Object.freeze([{ compound_later_reason: laterReason }]),
        compound_later_reason: laterReason,
      }) as unknown as ValidatedRuntimeProjectionInputV02;
      expect(isValidatedRuntimeProjectionInputV02(unbrandedCompound)).toBe(false);
      expect(buildTerminalObservationSnapshotV02(unbrandedCompound)).toEqual({
        ok: false,
        error: "PLAN_OR_LEDGER_LINEAGE_INVALID",
      });
    },
  );

  it("admits the frozen initialized fixture and builds the private work-open snapshot", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35();
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toEqual(expect.objectContaining({ ok: true }));
      if (!validated.ok) return;
      expect(isValidatedRuntimeProjectionInputV02(validated.value)).toBe(true);
      expect(Object.isFrozen(validated.value)).toBe(true);

      const built = buildTerminalObservationSnapshotV02(validated.value);
      expect(built.ok).toBe(true);
      if (!built.ok) return;
      expect(isTerminalObservationSnapshotV02(built.value)).toBe(true);
      expect(Object.isFrozen(built.value)).toBe(true);
      expect(built.value.progress).toEqual([{
        ref: "project-progress",
        target_reached: false,
        stalled: false,
        condition_evidence_refs: [],
      }]);
      expect(evaluateTerminalV02(built.value)).toEqual({
        decision: "continue",
        continuation: "work-open",
      });
    } finally {
      fixture.dispose();
    }
  });

  it("admits a schema-valid compensation-bearing plan without forged projection branding", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({ compensationPlan: true });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      const built = buildTerminalObservationSnapshotV02(validated.value);
      expect(built).toMatchObject({
        ok: true,
        value: {
          compensations: [{
            ref: "restore-workspace",
            activation_requested: false,
            settlement: { status: "pending" },
          }],
        },
      });
    } finally {
      fixture.dispose();
    }
  });

  it("projects a genuine admitted task-result failure into non-empty active failures", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({ activeFailureProjection: true });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      const built = buildTerminalObservationSnapshotV02(validated.value);
      expect(built).toMatchObject({
        ok: true,
        value: {
          active_failures: [{
            task_ref: "diagnose-root-cause",
            failure_class: "invalid-input",
            failure_ordinal: 1,
            retry_disposition: "ineligible",
          }],
        },
      });
    } finally {
      fixture.dispose();
    }
  });

  it("projects a genuine admitted non-allow policy decision into non-empty policy blocks", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({ policyBlockProjection: true });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      const built = buildTerminalObservationSnapshotV02(validated.value);
      expect(built).toMatchObject({
        ok: true,
        value: {
          policy_blocks: [{
            task_ref: "diagnose-root-cause",
            phase: "work",
            policy_action_kind: "approval-contract-edit",
            decision: "hold",
            decision_disposition: "non-resumable",
            active: true,
          }],
        },
      });
    } finally {
      fixture.dispose();
    }
  });

  it("retains the stage-nine request-time in-flight violation after the action later settles", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({
      historicalCompensationViolation: "request-in-flight-settled",
    });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({
        ok: false,
        error: "COMPENSATION_REQUEST_INVALID",
      });
    } finally {
      fixture.dispose();
    }
  });

  it("retains the stage-fourteen phase-entry worker violation after the action later settles", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({
      historicalCompensationViolation: "phase-entry-active-settled",
    });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({
        ok: false,
        error: "ACTIVE_WORKERS_AT_PHASE_ENTRY",
      });
    } finally {
      fixture.dispose();
    }
  });

  it.each([
    ["missing", "without a preceding fence"],
    ["wrong-reason", "after a non-recovery fence"],
  ] as const)("rejects compensation phase entry %s (%s)", async (phaseBoundaryViolation) => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({ phaseBoundaryViolation });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({
        ok: false,
        error: "PHASE_OR_PENDING_TERMINAL_INVALID",
      });
    } finally {
      fixture.dispose();
    }
  });

  it("selects ledger syntax before trust and never returns a partial brand", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({
      malformedLedger: true,
      forgedTrust: true,
    });
    try {
      const result = validateRuntimeProjectionInputV02(fixture.input);
      expect(result).toEqual({ ok: false, error: "LEDGER_SYNTAX_INVALID" });
      expect("value" in result).toBe(false);
      expect(isValidatedRuntimeProjectionInputV02(fixture.input)).toBe(false);
    } finally {
      fixture.dispose();
    }
  });

  it("selects plan/ledger lineage before trust and rejects a structural trust forgery", async () => {
    const compound = await buildInitializedRuntimePositiveFixtureS35({
      ledgerPlanHashMismatch: true,
      forgedTrust: true,
    });
    const trustOnly = await buildInitializedRuntimePositiveFixtureS35({ forgedTrust: true });
    try {
      expect(validateRuntimeProjectionInputV02(compound.input)).toEqual({
        ok: false,
        error: "PLAN_OR_LEDGER_LINEAGE_INVALID",
      });
      expect(validateRuntimeProjectionInputV02(trustOnly.input)).toEqual({
        ok: false,
        error: "AUTHORITY_TRUST_INVALID",
      });
    } finally {
      compound.dispose();
      trustOnly.dispose();
    }
  });

  it("admits a complete sealed history and projects its immutable terminal controls", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({ sealedOutcome: "aborted" });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      const built = buildTerminalObservationSnapshotV02(validated.value);
      expect(built).toMatchObject({ ok: true });
      if (!built.ok) return;
      expect(built.value).toMatchObject({
        ledger_sequence: 4,
        current_fence_epoch: 1,
        abort_requested: true,
        terminal_freeze: { revision: 1, candidate: "aborted", ledger_sequence: 3 },
        terminal_seal: {
          ledger_sequence: 4,
          outcome: "aborted",
          fence_epoch: 1,
          pre_seal_ledger_sequence: 3,
        },
      });
      expect(Object.isFrozen(built.value.terminal_seal)).toBe(true);
    } finally {
      fixture.dispose();
    }
  });

  it("keeps unproven terminal structure closed at stage seven", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({
      sealedOutcome: "aborted",
      unprovenAbortFreeze: true,
    });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({
        ok: false,
        error: "TERMINAL_FREEZE_INVALID",
      });
      expect(isTerminalObservationSnapshotV02(validated.value)).toBe(false);
    } finally {
      fixture.dispose();
    }
  });

  it("projects an exact-ceiling admission block as proven exhaustion", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({ sealedOutcome: "exhausted" });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      const built = buildTerminalObservationSnapshotV02(validated.value);
      expect(built).toMatchObject({ ok: true });
      if (!built.ok) return;
      expect(built.value.limits.find(({ ref }) => ref === "max-output-bytes")).toMatchObject({
        status: "would-exceed",
        next_requested: 1,
      });
      expect(built.value.terminal_freeze?.candidate).toBe("exhausted");
      expect(built.value.terminal_seal?.outcome).toBe("exhausted");
    } finally {
      fixture.dispose();
    }
  });

  it("keeps insufficient control-plane reserve closed at stage fifteen", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({ invalidControlPlaneBudget: true });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({
        ok: false,
        error: "CONTROL_PLANE_BUDGET_INVALID",
      });
    } finally {
      fixture.dispose();
    }
  });

  it("retains the validated contiguous completed-loop-attempt count", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({ completedLoopAttempts: 1 });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      expect(validated.value.completed_loop_attempts).toBe(1);
      const built = buildTerminalObservationSnapshotV02(validated.value);
      expect(built).toMatchObject({ ok: true });
      if (built.ok) expect(built.value.progress[0]?.ref).toBe("project-progress");
    } finally {
      fixture.dispose();
    }
  });

  it("recomputes the exact pre-seal projection hash at stage sixteen", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({
      sealedOutcome: "aborted",
      preSealSnapshotHash: `sha256:${"0".repeat(64)}`,
    });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({
        ok: false,
        error: "TERMINAL_SEAL_OR_FENCE_INVALID",
      });
    } finally {
      fixture.dispose();
    }
  });

  it.each([
    [2, "SNAPSHOT_COVERAGE_OR_ORDER_INVALID"],
    [3, "APPLICABILITY_OR_DUE_INVALID"],
    [4, "LIMIT_OBSERVATION_INVALID"],
    [5, "TASK_EFFECT_OR_FAILURE_INVALID"],
    [6, "ACTION_ADMISSION_OR_QUIESCENCE_INVALID"],
  ] as const)("returns the exact closed stage-%i reason from an admitted canonical history", async (stage, error) => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({ invalidSnapshotStage: stage });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({ ok: false, error });
    } finally {
      fixture.dispose();
    }
  });

  it.each(independentlyRepresentableCompoundStages.flatMap((earlier) => [
    [earlier, 7, { invalidSnapshotStage: earlier, frozenOutcome: "aborted", invalidFreezeFenceEpoch: true }],
    [earlier, 16, { invalidSnapshotStage: earlier, sealedOutcome: "aborted", preSealSnapshotHash: `sha256:${"0".repeat(64)}` }],
    [earlier, 17, { invalidSnapshotStage: earlier, sealedOutcome: "aborted", preSealSnapshotHash: `sha256:${"0".repeat(64)}`, postSealAction: true }],
  ] as const))(
    "selects stage %i over recomposed terminal stage %i",
    async (earlier, _later, options) => {
      const fixture = await buildInitializedRuntimePositiveFixtureS35(options);
      try {
        const validated = validateRuntimeProjectionInputV02(fixture.input);
        expect(validated).toMatchObject({ ok: true });
        if (!validated.ok) return;
        expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({
          ok: false,
          error: TerminalSnapshotInvalidReasonsV02[Math.min(earlier, _later) - 1],
        });
      } finally {
        fixture.dispose();
      }
    },
  );

  it.each([
    [7, 15, { frozenOutcome: "aborted", invalidFreezeFenceEpoch: true, invalidControlPlaneBudget: true }],
    [7, 16, { sealedOutcome: "aborted", invalidFreezeFenceEpoch: true, preSealSnapshotHash: `sha256:${"0".repeat(64)}` }],
    [7, 17, { sealedOutcome: "aborted", invalidFreezeFenceEpoch: true, preSealSnapshotHash: `sha256:${"0".repeat(64)}`, postSealAction: true }],
  ] as const)("selects stage %i over terminal stage %i after causal recomposition", async (earlier, _later, options) => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35(options);
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({
        ok: false,
        error: TerminalSnapshotInvalidReasonsV02[earlier - 1],
      });
    } finally {
      fixture.dispose();
    }
  });

  it.each([
    [8, "ACTIVATION_INVALID"],
    [9, "COMPENSATION_REQUEST_INVALID"],
    [10, "CANDIDATE_ESCALATION_INVALID"],
    [11, "PHASE_OR_PENDING_TERMINAL_INVALID"],
    [12, "COMPENSATION_REF_SET_INVALID"],
    [13, "COMPENSATION_SETTLEMENT_INVALID"],
    [14, "ACTIVE_WORKERS_AT_PHASE_ENTRY"],
  ] as const)("returns the exact closed stage-%i compensation reason from a genuinely admitted history", async (stage, error) => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({
      compensationPlan: true,
      invalidSnapshotStage: stage,
    });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({ ok: false, error });
    } finally {
      fixture.dispose();
    }
  });

  const compoundStagePairs = independentlyRepresentableCompoundStages.flatMap((earlier, index) =>
    independentlyRepresentableCompoundStages.slice(index + 1).map((later) => [earlier, later] as const),
  );
  it.each(compoundStagePairs)(
    "selects stage %i over stage %i with independent event order shuffled where representable",
    async (earlier, later) => {
      const expected = TerminalSnapshotInvalidReasonsV02[earlier - 1];
      const insertionOrders: ReadonlyArray<readonly [typeof earlier, typeof later]> = later <= 6
        ? [[earlier, later], [later, earlier]]
        : [[earlier, later]];
      for (const [first, second] of insertionOrders) {
        const fixture = await buildInitializedRuntimePositiveFixtureS35({
          invalidSnapshotStage: first,
          secondaryInvalidSnapshotStage: second,
        });
        try {
          const validated = validateRuntimeProjectionInputV02(fixture.input);
          expect(validated).toMatchObject({ ok: true });
          if (!validated.ok) continue;
          expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({
            ok: false,
            error: expected,
          });
        } finally {
          fixture.dispose();
        }
      }
    },
  );

  it.each(independentlyRepresentableCompoundStages.map((earlier) => [earlier] as const))(
    "selects stage %i over stage 15 control-plane exhaustion",
    async (earlier) => {
      const fixture = await buildInitializedRuntimePositiveFixtureS35({
        invalidSnapshotStage: earlier,
        invalidControlPlaneBudget: true,
      });
      try {
        const validated = validateRuntimeProjectionInputV02(fixture.input);
        expect(validated).toMatchObject({ ok: true });
        if (!validated.ok) return;
        expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({
          ok: false,
          error: TerminalSnapshotInvalidReasonsV02[earlier - 1],
        });
      } finally {
        fixture.dispose();
      }
    },
  );

  it.each([
    [15, 16, { invalidControlPlaneBudget: true, sealedOutcome: "aborted", preSealSnapshotHash: `sha256:${"0".repeat(64)}` }],
    [15, 17, { invalidControlPlaneBudget: true, sealedOutcome: "aborted", postSealAction: true }],
    [16, 17, { sealedOutcome: "aborted", preSealSnapshotHash: `sha256:${"0".repeat(64)}`, postSealAction: true }],
  ] as const)("selects stage %i over stage %i for compound terminal controls", async (earlier, _later, options) => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35(options);
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({
        ok: false,
        error: TerminalSnapshotInvalidReasonsV02[earlier - 1],
      });
    } finally {
      fixture.dispose();
    }
  });

  it("returns stage seventeen for an action appended after a valid sealed prefix", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35({
      sealedOutcome: "aborted",
      postSealAction: true,
    });
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      expect(buildTerminalObservationSnapshotV02(validated.value)).toEqual({
        ok: false,
        error: "POST_SEAL_ACTION",
      });
    } finally {
      fixture.dispose();
    }
  });


  it("returns the exact closed runtime result shape for hostile inputs", () => {
    const hostile = new Proxy({}, {
      getPrototypeOf() {
        throw new Error("caller trap must not escape");
      },
    });

    expect(() => validateRuntimeProjectionInputV02(hostile)).not.toThrow();
    expect(validateRuntimeProjectionInputV02(hostile)).toEqual({
      ok: false,
      error: "RUNTIME_INPUT_BYTE_VIEW_INVALID",
    });
    expectTypeOf<RuntimeProjectionErrorV02>().not.toEqualTypeOf<string>();
  });

  it("admits the plan byte view first and enforces its exact ceiling before decode", () => {
    expect(validateRuntimeProjectionInputV02({ resolved_run_plan_bytes: {} })).toEqual({
      ok: false,
      error: "RUNTIME_INPUT_BYTE_VIEW_INVALID",
    });
    expect(validateRuntimeProjectionInputV02({
      resolved_run_plan_bytes: new Uint8Array(4_194_305),
    })).toEqual({
      ok: false,
      error: "RUNTIME_INPUT_RESOURCE_LIMIT",
    });
    expect(validateRuntimeProjectionInputV02({
      resolved_run_plan_bytes: new TextEncoder().encode("{}\n"),
    })).toEqual({
      ok: false,
      error: "RESOLVED_RUN_PLAN_SCHEMA_INVALID",
    });
  });

  it("keeps the S35 trust mint narrow and rejects structural snapshot input", () => {
    const context = captureSyntheticAuthorityTrustContextForS35TestV02(
      "s35-valid-complete-authority-trust-v01",
    );
    expect(Object.isFrozen(context)).toBe(true);
    expect(() => captureSyntheticAuthorityTrustContextForS35TestV02(
      "unknown" as "s35-valid-complete-authority-trust-v01",
    )).toThrow(TypeError);

    expect(buildTerminalObservationSnapshotV02(
      {} as ValidatedRuntimeProjectionInputV02,
    )).toEqual({ ok: false, error: "PLAN_OR_LEDGER_LINEAGE_INVALID" });
    expect(isValidatedRuntimeProjectionInputV02({})).toBe(false);
    expect(isTerminalObservationSnapshotV02({})).toBe(false);
    expectTypeOf<TerminalObservationSnapshotV02>().not.toEqualTypeOf<Record<string, unknown>>();
  });

  it("never brands a partial runtime projection or fabricated semantic snapshot", () => {
    const partials = [
      {},
      { resolved_run_plan_bytes: new Uint8Array() },
      { resolved_run_plan_bytes: new TextEncoder().encode("{}\n") },
    ];
    for (const partial of partials) {
      const result = validateRuntimeProjectionInputV02(partial);
      expect(result.ok).toBe(false);
      expect("value" in result).toBe(false);
      expect(isValidatedRuntimeProjectionInputV02(partial)).toBe(false);
    }

    const fabricated = {
      plan: { gates: [] },
      events: [],
    } as unknown as ValidatedRuntimeProjectionInputV02;
    expect(buildTerminalObservationSnapshotV02(fabricated)).toEqual({
      ok: false,
      error: "PLAN_OR_LEDGER_LINEAGE_INVALID",
    });
    expect(isTerminalObservationSnapshotV02(fabricated)).toBe(false);
  });

  it("keeps all trust, admission, snapshot, and hash issuers off the package root", async () => {
    const root = await import("../../src/index.js");
    expect("captureSyntheticAuthorityTrustContextForS35TestV02" in root).toBe(false);
    expect("validateRuntimeProjectionInputV02" in root).toBe(false);
    expect("buildTerminalObservationSnapshotV02" in root).toBe(false);
    expect("hashTerminalObservationSnapshotV02" in root).toBe(false);
  });
});

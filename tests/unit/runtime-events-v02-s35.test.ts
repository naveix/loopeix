import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import * as runtime from "../../src/schema/runtime.js";

const EXPECTED_EVENT_TYPES = [
  "run.initialized",
  "run.clock-observed",
  "run.fence-advanced",
  "control.abort-requested",
  "gate.result-required",
  "gate.result-recorded",
  "evaluation.result-required",
  "evaluation.result-recorded",
  "authority.human-authorization-recorded",
  "authority.envelope-recorded",
  "approval.recommendation-recorded",
  "policy.decision-recorded",
  "authority.waiver-recorded",
  "authority.grant-revoked",
  "evidence.recorded",
  "observation.manual-recorded",
  "claim.recorded",
  "finding.recorded",
  "waiver.recorded",
  "lease.issued",
  "task.action-admitted",
  "tool.call-admitted",
  "artifact.write-admitted",
  "limit.admission-blocked",
  "task.execution-started",
  "task.execution-completed",
  "task.progress-fact-recorded",
  "task.execution-failed",
  "task.action-outcome-unknown",
  "task.action-outcome-reconciled",
  "artifact.recorded",
  "record.redaction-derivative-recorded",
  "record.custody-state-recorded",
  "record.export-decision-recorded",
  "effect.outcome",
  "task.action-settled",
  "loop.attempt-completed",
  "task.progress-observed",
  "run.terminal-freeze-entered",
  "run.terminal-freeze-revised",
  "run.compensation-requested",
  "run.compensation-request-revised",
  "run.compensation-phase-entered",
  "run.compensation-candidate-escalated",
  "compensation.settled",
  "run.terminal-sealed",
] as const;

type RuntimeEventExports = {
  RuntimeEventTypesV02: readonly string[];
  RuntimeEventV02: ZodType;
};

const schemas = runtime as unknown as RuntimeEventExports;

describe("S35 closed V02 runtime event union", () => {
  it("contains exactly the canonical 46 event discriminants in contract order", () => {
    expect(schemas.RuntimeEventTypesV02).toEqual(EXPECTED_EVENT_TYPES);
    expect(new Set(schemas.RuntimeEventTypesV02).size).toBe(46);
  });

  it("rejects event types outside the closed inventory", () => {
    expect(schemas.RuntimeEventV02.safeParse({ event_type: "run.future-event" }).success).toBe(false);
  });
});

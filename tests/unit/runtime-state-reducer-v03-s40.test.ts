import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import { inspectRuntimeLedgerV03 } from "../../src/run/runtime-ledger-v03.js";
import { reduceRuntimeEventPrefixV03 } from "../../src/run/runtime-state-reducer-v03.js";
import type { RuntimeEventV03Value } from "../../src/schema/runtime-v03.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const inventory = {
  resolved_run_plan: "0.2", ledger_event: "0.3", run_manifest: "0.2", artifact_manifest: "0.2",
  redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
  agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2",
  manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2",
  evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2",
} as const;

function event(events: Array<Record<string, unknown>>, event_type: string, source: string, authority_ref: string | null, payload: Record<string, unknown>) {
  const previous = events.at(-1);
  const preimage = {
    schema_version: "0.3", event_id: `event_s40_${events.length + 1}`, run_id: "run_s40_state",
    sequence: events.length + 1, recorded_at: `2026-08-24T10:00:${String(events.length).padStart(2, "0")}Z`,
    event_type, source, authority_ref, risk_tier: "T1", related_ids: [],
    previous_event_hash: previous?.event_hash ?? null, payload,
  };
  const sealed = { ...preimage, event_hash: hashCanonical(preimage) };
  events.push(sealed);
  return sealed;
}

function initialized() {
  const events: Array<Record<string, unknown>> = [];
  event(events, "run.initialized", "kernel", null, { plan_hash: H("a"), initial_fence_epoch: 0, runtime_schema_versions: inventory });
  return events;
}

function inspect(events: readonly Record<string, unknown>[]) {
  return inspectRuntimeLedgerV03(new TextEncoder().encode(
    `${events.map((candidate) => JSON.stringify(candidate)).join("\n")}\n`,
  ));
}

describe("S40 V03 pure run state reduction", () => {
  it("permits initialize, start, pause, quarantine, and observed termination in order", () => {
    const events = initialized();
    event(events, "run.started", "kernel", null, { executor_profile_hash: H("b") });
    const pauseRequest = events[0]!;
    event(events, "run.paused", "operator", "authority_pause_s40", {
      requested_by: "operator", reason_code: "operator-request",
      request_event_ref: { ledger_sequence: pauseRequest.sequence, event_hash: pauseRequest.event_hash },
    });
    const quarantine = event(events, "run.quarantined", "integrity", null, {
      reason_code: "capture-gap", evidence_refs: [{ ledger_sequence: 1, event_hash: events[0]!.event_hash }],
    });
    event(events, "process.termination-attempted", "adapter", null, {
      trigger: "quarantine", trigger_event_ref: { ledger_sequence: quarantine.sequence, event_hash: quarantine.event_hash },
      adapter_invocation_id: "adapter_s40_state", observed_outcome: "unknown",
    });

    expect(inspect(events)).toMatchObject({ ok: true, state: { state: "quarantined" } });
  });

  it("rejects quarantine before the run becomes active", () => {
    const events = initialized();
    const quarantine = event(events, "run.quarantined", "integrity", null, {
      reason_code: "capture-gap", evidence_refs: [{ ledger_sequence: 1, event_hash: events[0]!.event_hash }],
    });

    expect(reduceRuntimeEventPrefixV03(events as unknown as readonly RuntimeEventV03Value[])).toEqual({
      ok: false,
      path: `event[${Number(quarantine.sequence) - 1}]`,
      message: "run.quarantined requires a started non-terminal run.",
    });
  });

  it("rejects start twice, pause before start, and any event after a terminal seal", () => {
    const beforeStart = initialized();
    event(beforeStart, "run.paused", "operator", "authority_pause_s40", {
      requested_by: "operator", reason_code: "operator-request",
      request_event_ref: { ledger_sequence: 1, event_hash: beforeStart[0]!.event_hash },
    });
    expect(inspect(beforeStart)).toMatchObject({ ok: false, reason: "LEDGER_TRANSITION_INVALID" });

    const twice = initialized();
    event(twice, "run.started", "kernel", null, { executor_profile_hash: H("b") });
    event(twice, "run.started", "kernel", null, { executor_profile_hash: H("b") });
    expect(inspect(twice)).toMatchObject({ ok: false, reason: "LEDGER_TRANSITION_INVALID" });
  });

  it("rejects pause while an admitted action remains in flight", () => {
    const events = initialized();
    event(events, "run.started", "kernel", null, { executor_profile_hash: H("b") });
    const admitted = event(events, "task.action-admitted", "policy-enforcement-point", "authority_s40", {
      action_id: "action_s40_1",
    });
    event(events, "run.paused", "operator", "authority_pause_s40", {
      requested_by: "operator", reason_code: "operator-request",
      request_event_ref: { ledger_sequence: 1, event_hash: events[0]!.event_hash },
    });
    expect(reduceRuntimeEventPrefixV03(events as unknown as readonly RuntimeEventV03Value[])).toEqual({
      ok: false,
      path: `event[${Number(admitted.sequence)}]`,
      message: "run.paused requires a running quiescent boundary.",
    });
  });

  it("rejects a terminal seal with an in-flight action even after abort", () => {
    const events = initialized();
    event(events, "run.started", "kernel", null, { executor_profile_hash: H("b") });
    event(events, "task.action-admitted", "policy-enforcement-point", "authority_s40", {
      action_id: "action_s40_1",
    });
    event(events, "control.abort-requested", "operator", "authority_s40", {});
    event(events, "run.terminal-freeze-entered", "evaluator", null, {});
    const terminal = event(events, "run.terminal-sealed", "evaluator", null, {});

    expect(reduceRuntimeEventPrefixV03(events as unknown as readonly RuntimeEventV03Value[])).toEqual({
      ok: false,
      path: `event[${Number(terminal.sequence) - 1}]`,
      message: "Terminal seal requires no unresolved in-flight action.",
    });
  });

  it("rejects a terminal seal before terminal freeze", () => {
    const events = initialized();
    const terminal = event(events, "run.terminal-sealed", "evaluator", null, {});

    expect(reduceRuntimeEventPrefixV03(events as unknown as readonly RuntimeEventV03Value[])).toEqual({
      ok: false,
      path: `event[${Number(terminal.sequence) - 1}]`,
      message: "Terminal seal requires a preceding terminal freeze.",
    });
  });
});

import { describe, expect, it } from "vitest";
import { hashCanonical } from "../../src/hash.js";
import { validateRuntimeLedgerV02 } from "../../src/run/runtime-ledger-v02.js";

const HASH = `sha256:${"a".repeat(64)}`;
type Event = Record<string, unknown> & { event_hash: string; sequence: number; payload: Record<string, unknown> };

function build(settlementCount: number, seal: boolean): Event[] {
  const events: Event[] = [];
  const add = (eventType: string, payload: Record<string, unknown>, source = "evaluator", authority: string | null = null): Event => {
    const previous = events.at(-1);
    const preimage = {
      schema_version: "0.2", event_id: `event_${events.length + 1}`, run_id: "run_settlement", sequence: events.length + 1,
      recorded_at: "2026-08-10T12:00:00Z", event_type: eventType, source, authority_ref: authority,
      risk_tier: "T2", related_ids: [], previous_event_hash: previous?.event_hash ?? null, payload,
    };
    const event = { ...preimage, event_hash: hashCanonical(preimage) } as Event;
    events.push(event);
    return event;
  };
  const first = add("run.initialized", {
    plan_hash: HASH, initial_fence_epoch: 0,
    runtime_schema_versions: {
      resolved_run_plan: "0.2", ledger_event: "0.2", run_manifest: "0.2", artifact_manifest: "0.2", redaction_derivative: "0.2",
      human_authorization_proof: "0.2", authority_envelope: "0.2", agency_recommendation: "0.2", authority_revocation: "0.2",
      task_result: "0.2", manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2",
      evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2",
    },
  }, "kernel");
  const ref = (event: Event) => ({ ledger_sequence: event.sequence, event_hash: event.event_hash });
  const freeze = add("run.terminal-freeze-entered", {
    revision: 1, candidate: "failed", candidate_evidence_refs: [ref(first)], fence_epoch: 0,
  });
  const request = add("run.compensation-requested", {
    revision: 1, pending_terminal: "failed", activation_reason: "terminal-failure", compensation_refs: ["comp-a"],
    effect_evidence_refs: [ref(first)], freeze_event_hash: freeze.event_hash,
  });
  add("run.fence-advanced", {
    previous_fence_epoch: 0, fence_epoch: 1, reason: "recovery-boundary", evidence_refs: [ref(request)],
  }, "policy-enforcement-point", "pep_1");
  add("run.compensation-phase-entered", {
    request_revision: 1, request_event_hash: request.event_hash, pending_terminal: "failed",
    compensation_refs: ["comp-a"], freeze_event_hash: freeze.event_hash,
  });
  for (let index = 0; index < settlementCount; index += 1) {
    add("compensation.settled", {
      compensation_ref: "comp-a", status: "compensated", unable_reason: null, evidence_refs: [ref(first)],
    });
  }
  if (seal) {
    const prefix = events.at(-1)!;
    add("run.terminal-sealed", {
      outcome: "failed", pre_seal_ledger_sequence: prefix.sequence, pre_seal_ledger_head_hash: prefix.event_hash,
      pre_seal_snapshot_hash: HASH, previous_fence_epoch: 1, fence_epoch: 2,
    });
  }
  return events;
}

describe("S35 compensation settlement history", () => {
  it("accepts one settlement for the entered compensation", () => {
    expect(validateRuntimeLedgerV02(build(1, false)).ok).toBe(true);
  });

  it("rejects duplicate settlement of the same compensation", () => {
    const result = validateRuntimeLedgerV02(build(2, false));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("LEDGER_HISTORY_INVALID");
  });

  it("rejects seal before the entered compensation set is complete", () => {
    const result = validateRuntimeLedgerV02(build(0, true));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("LEDGER_HISTORY_INVALID");
  });
});

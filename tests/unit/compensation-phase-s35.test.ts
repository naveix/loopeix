import { describe, expect, it } from "vitest";
import { hashCanonical } from "../../src/hash.js";
import { validateRuntimeLedgerV02 } from "../../src/run/runtime-ledger-v02.js";
import { appendWorkActionAdmissionEvents } from "../helpers/runtime-admission-fixture-s35.js";

const HASH_A = `sha256:${"a".repeat(64)}`;

type Event = Record<string, unknown> & { event_hash: string; sequence: number; event_type: string; payload: Record<string, unknown> };

function append(events: Event[], eventType: string, payload: Record<string, unknown>, options: {
  source?: string;
  authorityRef?: string | null;
} = {}): Event {
  const previous = events.at(-1);
  const preimage = {
    schema_version: "0.2",
    event_id: `event_${events.length + 1}`,
    run_id: "run_control",
    sequence: events.length + 1,
    recorded_at: `2026-08-10T12:00:${String(events.length).padStart(2, "0")}Z`,
    event_type: eventType,
    source: options.source ?? "evaluator",
    authority_ref: options.authorityRef ?? null,
    risk_tier: "T2",
    related_ids: [],
    previous_event_hash: previous?.event_hash ?? null,
    payload,
  };
  const event = { ...preimage, event_hash: hashCanonical(preimage) } as Event;
  events.push(event);
  return event;
}

function initialized(): Event[] {
  const events: Event[] = [];
  append(events, "run.initialized", {
    plan_hash: HASH_A,
    initial_fence_epoch: 0,
    runtime_schema_versions: {
      resolved_run_plan: "0.2", ledger_event: "0.2", run_manifest: "0.2", artifact_manifest: "0.2",
      redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
      agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2",
      manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2",
      evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2",
    },
  }, { source: "kernel" });
  return events;
}

function ref(event: Event): { ledger_sequence: number; event_hash: string } {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function buildControlHistory(options: {
  freezeRevision?: number;
  requestRevision?: number;
  requestRefs?: string[];
  addedRefs?: string[];
  activeAction?: boolean;
} = {}): Event[] {
  const events = initialized();
  const first = events[0]!;
  const freeze = append(events, "run.terminal-freeze-entered", {
    revision: 1, candidate: "stalled", candidate_evidence_refs: [ref(first)], fence_epoch: 0,
  });
  const revisedFreeze = append(events, "run.terminal-freeze-revised", {
    revision: options.freezeRevision ?? 2,
    previous_candidate: "stalled", candidate: "exhausted", previous_freeze_event_hash: freeze.event_hash,
    candidate_evidence_refs: [ref(first)],
  });
  if (options.activeAction) {
    appendWorkActionAdmissionEvents(events, {
      taskRef: "task-main",
      authorityRef: "pep_1",
    });
  }
  const request = append(events, "run.compensation-requested", {
    revision: 1, pending_terminal: "exhausted", activation_reason: "terminal-exhaustion",
    compensation_refs: ["comp-a"], effect_evidence_refs: [ref(first)], freeze_event_hash: revisedFreeze.event_hash,
  });
  const revisedRequest = append(events, "run.compensation-request-revised", {
    revision: options.requestRevision ?? 2,
    previous_pending_terminal: "exhausted", pending_terminal: "exhausted",
    activation_reason: "terminal-exhaustion", compensation_refs: options.requestRefs ?? ["comp-a", "comp-b"],
    added_compensation_refs: options.addedRefs ?? ["comp-b"], previous_request_event_hash: request.event_hash,
    freeze_event_hash: revisedFreeze.event_hash, effect_evidence_refs: [ref(first)],
  });
  append(events, "run.fence-advanced", {
    previous_fence_epoch: 0, fence_epoch: 1, reason: "recovery-boundary", evidence_refs: [ref(revisedRequest)],
  }, { source: "policy-enforcement-point", authorityRef: "pep_1" });
  append(events, "run.compensation-phase-entered", {
    request_revision: options.requestRevision ?? 2, request_event_hash: revisedRequest.event_hash,
    pending_terminal: "exhausted", compensation_refs: options.requestRefs ?? ["comp-a", "comp-b"],
    freeze_event_hash: revisedFreeze.event_hash,
  });
  return events;
}

function expectHistoryInvalid(events: Event[]): void {
  const result = validateRuntimeLedgerV02(events);
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.reason).toBe("LEDGER_HISTORY_INVALID");
}

describe("S35 compensation phase history", () => {
  it("accepts contiguous freeze/request revisions and exact recovery-boundary phase entry", () => {
    expect(validateRuntimeLedgerV02(buildControlHistory()).ok).toBe(true);
  });

  it("rejects freeze and request revision gaps", () => {
    expectHistoryInvalid(buildControlHistory({ freezeRevision: 3 }));
    expectHistoryInvalid(buildControlHistory({ requestRevision: 3 }));
  });

  it("rejects compensation ref removal and invented added refs", () => {
    expectHistoryInvalid(buildControlHistory({ requestRefs: ["comp-b"], addedRefs: ["comp-b"] }));
    expectHistoryInvalid(buildControlHistory({ requestRefs: ["comp-a", "comp-b"], addedRefs: ["comp-a", "comp-b"] }));
  });

  it("rejects an admission after freeze and before compensation phase entry", () => {
    const result = validateRuntimeLedgerV02(buildControlHistory({ activeAction: true }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason, JSON.stringify(result.issues)).toBe("LEDGER_HISTORY_INVALID");
      expect(result.issues[0]!.message).toBe("No ordinary action may be admitted after terminal freeze.");
    }
  });
});

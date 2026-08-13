import { describe, expect, it } from "vitest";
import { hashCanonical } from "../../src/hash.js";
import { validateRuntimeLedgerV02 } from "../../src/run/runtime-ledger-v02.js";

const HASH = `sha256:${"a".repeat(64)}`;
type Event = Record<string, unknown> & { event_hash: string; sequence: number };

function history(outcome: string, previousFence = 0, nextFence = 1): Event[] {
  const events: Event[] = [];
  const add = (eventType: string, payload: Record<string, unknown>, source = "evaluator"): Event => {
    const previous = events.at(-1);
    const preimage = {
      schema_version: "0.2", event_id: `event_${events.length + 1}`, run_id: "run_seal", sequence: events.length + 1,
      recorded_at: "2026-08-10T12:00:00Z", event_type: eventType, source, authority_ref: null,
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
  add("run.terminal-freeze-entered", {
    revision: 1, candidate: "stalled", candidate_evidence_refs: [{ ledger_sequence: 1, event_hash: first.event_hash }], fence_epoch: 0,
  });
  const prefix = events.at(-1)!;
  add("run.terminal-sealed", {
    outcome, pre_seal_ledger_sequence: prefix.sequence, pre_seal_ledger_head_hash: prefix.event_hash,
    pre_seal_snapshot_hash: HASH, previous_fence_epoch: previousFence, fence_epoch: nextFence,
  });
  return events;
}

describe("S35 terminal seal and fence history", () => {
  it("accepts a seal matching the frozen candidate and current fence", () => {
    expect(validateRuntimeLedgerV02(history("stalled")).ok).toBe(true);
  });

  it("rejects a seal with a different terminal outcome", () => {
    const result = validateRuntimeLedgerV02(history("failed"));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("LEDGER_HISTORY_INVALID");
  });

  it("rejects a terminal seal that bypasses the mandatory freeze", () => {
    const [initialized, , originalSeal] = history("stalled");
    if (initialized === undefined || originalSeal === undefined) throw new Error("Invalid test fixture.");
    const { event_hash: _ignored, ...sealPreimage } = originalSeal;
    const resealedPreimage = {
      ...sealPreimage,
      sequence: 2,
      previous_event_hash: initialized.event_hash,
      payload: {
        ...(sealPreimage.payload as Record<string, unknown>),
        pre_seal_ledger_sequence: initialized.sequence,
        pre_seal_ledger_head_hash: initialized.event_hash,
      },
    };
    const seal = { ...resealedPreimage, event_hash: hashCanonical(resealedPreimage) };

    const result = validateRuntimeLedgerV02([initialized, seal]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("LEDGER_HISTORY_INVALID");
  });
});

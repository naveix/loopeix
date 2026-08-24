import { describe, expect, it, vi } from "vitest";

import { hashBytes, hashCanonical } from "../../src/hash.js";
import { classifyRuntimeDurabilityV03 } from "../../src/run/runtime-durability-policy-v03.js";

function base() {
  const priorPreimage = { sequence: 4, previous_event_hash: null, payload: { marker: "prior" } };
  const priorEvent = { ...priorPreimage, event_hash: hashCanonical(priorPreimage) };
  const priorLedgerText = `${JSON.stringify(priorEvent)}\n`;
  const targetPreimage = { sequence: 5, previous_event_hash: priorEvent.event_hash, payload: { marker: "target" } };
  const targetEvent = { ...targetPreimage, event_hash: hashCanonical(targetPreimage) };
  const eventLineBytes = `${JSON.stringify(targetEvent)}\n`;
  return {
    policy_version: "0.1",
    prior_head: { sequence: 4, event_hash: priorEvent.event_hash, ledger_bytes_hash: hashBytes(priorLedgerText) },
    target_head: { sequence: 5, event_hash: targetEvent.event_hash, ledger_bytes_hash: hashBytes(`${priorLedgerText}${eventLineBytes}`) },
    prior_ledger_text: priorLedgerText,
    event_line: {
      bytes: eventLineBytes,
      bytes_hash: hashBytes(eventLineBytes),
      byte_length: Buffer.byteLength(eventLineBytes, "utf8"),
    },
  };
}

describe("runtime durability policy V03", () => {
  it("classifies COMMITTED only after the complete ordered durability proof", () => {
    const result = classifyRuntimeDurabilityV03({
      ...base(),
      steps: [
        { step: "prefix-validation", outcome: "accepted" },
        { step: "append-write", outcome: "complete" },
        { step: "ledger-sync", outcome: "confirmed" },
        { step: "ledger-readback", outcome: "exact" },
        { step: "head-publish", outcome: "complete" },
        { step: "directory-sync", outcome: "confirmed" },
        { step: "final-readback", outcome: "exact" },
      ],
    });

    expect(result).toEqual({ classification: "COMMITTED", reason: "DURABLE_EXACT_READBACK" });
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("classifies NOT_COMMITTED only when zero written bytes and the prior state are proven", () => {
    expect(classifyRuntimeDurabilityV03({
      ...base(),
      steps: [
        { step: "prefix-validation", outcome: "accepted" },
        { step: "append-write", outcome: "zero-bytes-confirmed" },
        { step: "prior-state-revalidated", outcome: "exact" },
      ],
    })).toEqual({ classification: "NOT_COMMITTED", reason: "PRIOR_STATE_EXACT" });
    expect(classifyRuntimeDurabilityV03({
      ...base(),
      steps: [{ step: "prefix-validation", outcome: "rejected-before-write" }],
    })).toEqual({ classification: "NOT_COMMITTED", reason: "REJECTED_BEFORE_WRITE" });
  });

  it.each([
    { steps: [{ step: "prefix-validation", outcome: "accepted" }] },
    { steps: [{ step: "prefix-validation", outcome: "accepted" }, { step: "append-write", outcome: "partial-or-unknown" }] },
    { steps: [{ step: "prefix-validation", outcome: "accepted" }, { step: "append-write", outcome: "complete" }, { step: "ledger-sync", outcome: "failed-or-unknown" }] },
    { steps: [{ step: "append-write", outcome: "zero-bytes-confirmed" }, { step: "prefix-validation", outcome: "accepted" }] },
  ] as const)("classifies incomplete, ambiguous, failed, or reordered observations OUTCOME_UNKNOWN", ({ steps }) => {
    expect(classifyRuntimeDurabilityV03({ ...base(), steps })).toEqual({
      classification: "OUTCOME_UNKNOWN",
      reason: "DURABILITY_UNCONFIRMED",
    });
  });

  it("fails closed on invalid head lineage", () => {
    const input = base();
    input.target_head.sequence = 7;
    expect(classifyRuntimeDurabilityV03({ ...input, steps: [] })).toEqual({
      classification: "OUTCOME_UNKNOWN",
      reason: "OBSERVATIONS_INVALID",
    });
  });

  it.each([
    ["prior ledger hash", (input: ReturnType<typeof base>) => { input.prior_head.ledger_bytes_hash = input.target_head.ledger_bytes_hash; }],
    ["target ledger hash", (input: ReturnType<typeof base>) => { input.target_head.ledger_bytes_hash = input.prior_head.ledger_bytes_hash; }],
    ["event line hash", (input: ReturnType<typeof base>) => { input.event_line.bytes_hash = input.prior_head.ledger_bytes_hash; }],
    ["event line length", (input: ReturnType<typeof base>) => { input.event_line.byte_length += 1; }],
    ["target event hash", (input: ReturnType<typeof base>) => { input.target_head.event_hash = input.prior_head.event_hash; }],
  ])("rejects a forged %s binding instead of classifying COMMITTED", (_name, mutate) => {
    const input = base();
    mutate(input);
    expect(classifyRuntimeDurabilityV03({
      ...input,
      steps: [
        { step: "prefix-validation", outcome: "accepted" },
        { step: "append-write", outcome: "complete" },
        { step: "ledger-sync", outcome: "confirmed" },
        { step: "ledger-readback", outcome: "exact" },
        { step: "head-publish", outcome: "complete" },
        { step: "directory-sync", outcome: "confirmed" },
        { step: "final-readback", outcome: "exact" },
      ],
    })).toEqual({ classification: "OUTCOME_UNKNOWN", reason: "OBSERVATIONS_INVALID" });
  });

  it("rejects unknown fields and accessors without invoking them", () => {
    expect(classifyRuntimeDurabilityV03({
      ...base(),
      steps: [{ step: "prefix-validation", outcome: "rejected-before-write" }],
      retry: true,
    })).toEqual({ classification: "OUTCOME_UNKNOWN", reason: "OBSERVATIONS_INVALID" });

    const getter = vi.fn(() => "complete");
    const hostile = { ...base(), steps: [{ step: "prefix-validation", outcome: "accepted" }] };
    Object.defineProperty(hostile.steps[0], "secret", { enumerable: true, get: getter });
    expect(classifyRuntimeDurabilityV03(hostile)).toEqual({ classification: "OUTCOME_UNKNOWN", reason: "OBSERVATIONS_INVALID" });
    expect(getter).not.toHaveBeenCalled();
  });
});

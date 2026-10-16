import { describe, expect, it, vi } from "vitest";

import { canonicalize, hashBytes, hashCanonical } from "../../src/hash.js";
import {
  classifyRuntimeDurabilityPairV03,
  classifyRuntimeDurabilityV03,
} from "../../src/run/runtime-durability-policy-v03.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;

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

function pairBase() {
  const single = base();
  const firstPreimage = {
    sequence: 5, previous_event_hash: single.prior_head.event_hash, payload: { marker: "target" },
  };
  const first = { ...firstPreimage, event_hash: hashCanonical(firstPreimage) };
  const firstLine = `${canonicalize(first)}\n`;
  const secondPreimage = {
    sequence: 6, previous_event_hash: first.event_hash, payload: { marker: "quarantine" },
  };
  const second = { ...secondPreimage, event_hash: hashCanonical(secondPreimage) };
  const secondLine = `${canonicalize(second)}\n`;
  return {
    policy_version: "0.2",
    prior_head: single.prior_head,
    target_head: {
      sequence: 6, event_hash: second.event_hash,
      ledger_bytes_hash: hashBytes(`${single.prior_ledger_text}${firstLine}${secondLine}`),
    },
    prior_ledger_text: single.prior_ledger_text,
    event_lines: [
      { bytes: firstLine, bytes_hash: hashBytes(firstLine), byte_length: Buffer.byteLength(firstLine, "utf8") },
      { bytes: secondLine, bytes_hash: hashBytes(secondLine), byte_length: Buffer.byteLength(secondLine, "utf8") },
    ],
  };
}

describe("runtime durability policy V03", () => {
  it("classifies one exact linked two-event append only after the complete durability proof", () => {
    expect(classifyRuntimeDurabilityPairV03({
      ...pairBase(),
      steps: [
        { step: "prefix-validation", outcome: "accepted" },
        { step: "append-write", outcome: "complete" },
        { step: "ledger-sync", outcome: "confirmed" },
        { step: "ledger-readback", outcome: "exact" },
        { step: "head-publish", outcome: "complete" },
        { step: "directory-sync", outcome: "confirmed" },
        { step: "final-readback", outcome: "exact" },
      ],
    })).toEqual({ classification: "COMMITTED", reason: "DURABLE_EXACT_READBACK" });
  });

  it.each([
    ["wrong policy version", (input: ReturnType<typeof pairBase>) => { input.policy_version = "0.1"; }],
    ["wrong target sequence", (input: ReturnType<typeof pairBase>) => { input.target_head.sequence -= 1; }],
    ["reordered lines", (input: ReturnType<typeof pairBase>) => { input.event_lines.reverse(); }],
    ["forged first line hash", (input: ReturnType<typeof pairBase>) => { input.event_lines[0]!.bytes_hash = H("f"); }],
    ["forged second lineage", (input: ReturnType<typeof pairBase>) => {
      const second = JSON.parse(input.event_lines[1]!.bytes) as Record<string, unknown>;
      second.previous_event_hash = H("f");
      input.event_lines[1]!.bytes = `${canonicalize(second)}\n`;
      input.event_lines[1]!.bytes_hash = hashBytes(input.event_lines[1]!.bytes);
      input.event_lines[1]!.byte_length = Buffer.byteLength(input.event_lines[1]!.bytes, "utf8");
      input.target_head.ledger_bytes_hash = hashBytes(`${input.prior_ledger_text}${input.event_lines[0]!.bytes}${input.event_lines[1]!.bytes}`);
    }],
  ] as const)("rejects pair %s", (_name, mutate) => {
    const input = pairBase();
    mutate(input);
    expect(classifyRuntimeDurabilityPairV03({
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

  it("classifies NOT_COMMITTED only for rejection proven before any write begins", () => {
    expect(classifyRuntimeDurabilityV03({
      ...base(),
      steps: [{ step: "prefix-validation", outcome: "rejected-before-write" }],
    })).toEqual({ classification: "NOT_COMMITTED", reason: "REJECTED_BEFORE_WRITE" });
  });

  it("never downgrades a failure after the first write syscall begins to NOT_COMMITTED", () => {
    expect(classifyRuntimeDurabilityV03({
      ...base(),
      steps: [
        { step: "prefix-validation", outcome: "accepted" },
        { step: "append-write", outcome: "zero-bytes-confirmed" },
        { step: "prior-state-revalidated", outcome: "exact" },
      ],
    })).toEqual({ classification: "OUTCOME_UNKNOWN", reason: "DURABILITY_UNCONFIRMED" });
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

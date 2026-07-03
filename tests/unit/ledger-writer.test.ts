import { describe, expect, it } from "vitest";
import {
  appendToLedger,
  buildRunManifest,
  hashCanonical,
  parseLedgerText,
  recoverLedger,
  RunManifest,
  serializeLedger,
  validateLedger,
  verifyEventHashes,
  type LedgerEventDraft,
  type SealedLedgerEvent,
} from "../../src/index.js";

const draft = (eventId: string, eventType: string): LedgerEventDraft => ({
  schema_version: "0.1",
  event_id: eventId,
  run_id: "run_test",
  timestamp: "2026-01-01T00:00:00Z",
  event_type: eventType,
  source: "loopeix",
  actor_id: null,
  task_run_id: null,
  risk_tier: "T2",
  payload: {},
  related_ids: [],
});

function buildChain(): SealedLedgerEvent[] {
  const chain: SealedLedgerEvent[] = [];
  chain.push(appendToLedger(chain, draft("evt_0001", "run.started")));
  chain.push(appendToLedger(chain, draft("evt_0002", "task.started")));
  chain.push(appendToLedger(chain, draft("evt_0003", "run.completed")));
  return chain;
}

describe("canonical hashing is deterministic", () => {
  it("is independent of object key order", () => {
    expect(hashCanonical({ a: 1, b: { c: 2, d: 3 } })).toBe(hashCanonical({ b: { d: 3, c: 2 }, a: 1 }));
  });
  it("produces a sha256:<64hex> string", () => {
    expect(hashCanonical({ x: 1 })).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

describe("appendToLedger seals a valid chain", () => {
  const chain = buildChain();
  it("assigns sequence 1..n", () => {
    expect(chain.map((e) => e.sequence)).toEqual([1, 2, 3]);
  });
  it("links the hash chain (first previous null)", () => {
    expect(chain[0]!.previous_event_hash).toBeNull();
    expect(chain[1]!.previous_event_hash).toBe(chain[0]!.event_hash);
    expect(chain[2]!.previous_event_hash).toBe(chain[1]!.event_hash);
  });
  it("passes chain-linkage AND content-integrity validation", () => {
    expect(validateLedger(chain)).toEqual([]);
    expect(verifyEventHashes(chain)).toEqual([]);
  });
});

describe("integrity checks are complementary", () => {
  it("content tamper is caught by verifyEventHashes but NOT by chain linkage", () => {
    const chain = buildChain();
    // mutate a payload while leaving event_hash + previous_event_hash intact
    const tampered = chain.map((e, i) => (i === 1 ? { ...e, payload: { hacked: true } } : e));
    expect(validateLedger(tampered)).toEqual([]); // linkage still intact
    expect(verifyEventHashes(tampered).some((x) => x.message.includes("tamper"))).toBe(true);
  });
  it("a broken link is caught by validateLedger", () => {
    const chain = buildChain();
    const broken = chain.map((e, i) => (i === 2 ? { ...e, previous_event_hash: `sha256:${"0".repeat(64)}` } : e));
    expect(validateLedger(broken).some((x) => x.message.includes("chain break"))).toBe(true);
  });
});

describe("serialize / parse round-trip", () => {
  it("round-trips and stays valid", () => {
    const chain = buildChain();
    const { events, partialFinalLineDropped } = parseLedgerText(serializeLedger(chain));
    expect(partialFinalLineDropped).toBe(false);
    expect(events).toEqual(chain);
    expect(validateLedger(events)).toEqual([]);
  });
  it("drops a partial final line and flags it", () => {
    const chain = buildChain();
    const r = parseLedgerText(`${serializeLedger(chain)}{"incomplete":`);
    expect(r.partialFinalLineDropped).toBe(true);
    expect(r.events).toHaveLength(3);
  });
  it("quarantines a corrupt NON-final line (no throw) and reports its 1-based line number", () => {
    const r = parseLedgerText(`{"bad":\n{"ok":1}\n`);
    expect(r.corruptLines).toEqual([1]);
    expect(r.events).toEqual([{ ok: 1 }]);
  });
  it("ignores blank interior lines (valid JSONL) without flagging them corrupt", () => {
    const chain = buildChain();
    const withBlank = serializeLedger(chain).replace("\n", "\n\n"); // inject a blank line after event 1
    const r = parseLedgerText(withBlank);
    expect(r.corruptLines).toEqual([]);
    expect(r.events).toHaveLength(3);
  });
  it("empty / whitespace-only ledger → no events, no corruption", () => {
    const r = parseLedgerText("\n  \n");
    expect(r.events).toEqual([]);
    expect(r.corruptLines).toEqual([]);
    expect(r.partialFinalLineDropped).toBe(false);
  });
});

describe("recoverLedger — corrupt ledger handling (S13)", () => {
  it("a quarantined corrupt middle line → HOLD, recovers the valid prefix, reports the line", () => {
    // event 2 of a 3-event chain is replaced with garbage on disk.
    const chain = buildChain();
    const text = serializeLedger(chain).split("\n");
    text[1] = "{ not json";
    const parsed = parseLedgerText(text.join("\n"));
    const r = recoverLedger(parsed.events, { corruptLines: parsed.corruptLines });
    expect(r.integrity_status).toBe("hold");
    expect(r.findings.some((f) => f.includes("quarantined"))).toBe(true);
    expect(parsed.corruptLines).toEqual([2]);
    // derived state must come from the valid prefix (event 1), NOT the post-break event 3
    expect(r.last_valid_sequence).toBe(1);
    expect(r.terminated).toBe(false);
  });
  it("a torn final append (partial line) → HOLD, valid prefix intact", () => {
    const chain = buildChain();
    const parsed = parseLedgerText(`${serializeLedger(chain.slice(0, 2))}{"torn":`);
    const r = recoverLedger(parsed.events, { partialFinalLineDropped: parsed.partialFinalLineDropped });
    expect(r.integrity_status).toBe("hold");
    expect(r.last_valid_sequence).toBe(2);
  });
});

describe("recoverLedger", () => {
  it("valid chain ending in run.completed → valid/completed", () => {
    const r = recoverLedger(buildChain());
    expect(r.integrity_status).toBe("valid");
    expect(r.run_state).toBe("completed");
    expect(r.last_valid_sequence).toBe(3);
    expect(r.findings).toEqual([]);
  });
  it("content tamper → HOLD with a finding", () => {
    const chain = buildChain();
    const tampered = chain.map((e, i) => (i === 1 ? { ...e, payload: { hacked: true } } : e));
    const r = recoverLedger(tampered);
    expect(r.integrity_status).toBe("hold");
    expect(r.findings.some((f) => f.includes("integrity"))).toBe(true);
  });
  it("dropped partial final line → HOLD", () => {
    const r = recoverLedger(buildChain(), { partialFinalLineDropped: true });
    expect(r.integrity_status).toBe("hold");
    expect(r.findings.some((f) => f.includes("partial final ledger line"))).toBe(true);
  });
});

describe("buildRunManifest", () => {
  function chainWithGate(): SealedLedgerEvent[] {
    const c: SealedLedgerEvent[] = [];
    c.push(appendToLedger(c, draft("evt_0001", "run.started")));
    const gate = { ...draft("evt_0002", "gate.result"), payload: { gate_id: "claim-support", status: "PASS" } };
    c.push(appendToLedger(c, gate));
    c.push(appendToLedger(c, draft("evt_0003", "run.completed")));
    return c;
  }

  it("produces a schema-valid manifest with integrity + state derived from the ledger", () => {
    const events = chainWithGate();
    const manifest = buildRunManifest({
      run_id: "run_test",
      loop_family: "minimal-bugfix",
      loopeix_version: "v001",
      workspace_root: "<WORKSPACE_ROOT>",
      run_dir: ".loopeix/loops/minimal-bugfix/runs/run_test",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:03Z",
      events,
      file_inventory: [
        { path: "ledger.jsonl", purpose: "ledger", required: true, exists: true, hash: `sha256:${"a".repeat(64)}` },
      ],
      schema_versions: { ledger_event: "0.1", run_manifest: "0.1" },
    });
    expect(RunManifest.safeParse(manifest).success).toBe(true);
    expect(manifest.integrity_status).toBe("valid");
    expect(manifest.run_state).toBe("completed");
    expect(manifest.last_ledger_sequence).toBe(3);
    expect(manifest.blocking_gate_summary).toMatchObject({ pass: 1, hold: 0, fail: 0, latest: "PASS", trusted: true });
  });
});

describe("adversarial integrity (security audit follow-ups)", () => {
  it("injected unknown top-level key → rejected (strict event)", () => {
    const chain = buildChain();
    const withExtra = chain.map((e, i) => (i === 1 ? { ...e, injected: "x" } : e));
    expect(validateLedger(withExtra).length).toBeGreaterThan(0);
  });
  it("cross-run splice → run_id mismatch", () => {
    const chain = buildChain();
    const spliced = chain.map((e, i) => (i === 2 ? { ...e, run_id: "run_other" } : e));
    expect(validateLedger(spliced).some((x) => x.message.includes("run_id"))).toBe(true);
  });
  it("duplicate event_id → rejected", () => {
    const chain = buildChain();
    const dup = chain.map((e, i) => (i === 2 ? { ...e, event_id: chain[0]!.event_id } : e));
    expect(validateLedger(dup).some((x) => x.message.includes("duplicate event_id"))).toBe(true);
  });
  it("deleted middle event → sequence/linkage break", () => {
    const chain = buildChain();
    expect(validateLedger([chain[0]!, chain[2]!]).length).toBeGreaterThan(0);
  });
  it("tail truncation → HOLD when an expected head sequence is known", () => {
    const r = recoverLedger(buildChain().slice(0, 2), { expectedLastSequence: 3 });
    expect(r.integrity_status).toBe("hold");
    expect(r.findings.some((f) => f.includes("truncation"))).toBe(true);
  });
  it("run-id-bound manifest HOLDs on a spliced ledger and hides gate counts", () => {
    const events = buildChain();
    const manifest = buildRunManifest({
      run_id: "run_DIFFERENT",
      loop_family: "minimal-bugfix",
      loopeix_version: "v001",
      workspace_root: "<W>",
      run_dir: ".loopeix/loops/x/runs/run_DIFFERENT",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:03Z",
      events, // events belong to run_test, not run_DIFFERENT
      file_inventory: [],
    });
    expect(manifest.integrity_status).toBe("hold");
    expect(manifest.blocking_gate_summary).toMatchObject({ trusted: false });
  });
  it("DOCUMENTED LIMITATION: a full re-seal by a write-capable actor is NOT detected (needs signing)", () => {
    // Attacker mutates a payload, then re-seals the entire chain with the public algorithm.
    const c: SealedLedgerEvent[] = [];
    c.push(appendToLedger(c, draft("evt_0001", "run.started")));
    c.push(appendToLedger(c, { ...draft("evt_0002", "task.started"), payload: { hacked: true } }));
    c.push(appendToLedger(c, draft("evt_0003", "run.completed")));
    // Both checks pass — this is why signing/anchoring is required for tamper-PROOF (see docs/security-model.md).
    expect(validateLedger(c)).toEqual([]);
    expect(verifyEventHashes(c)).toEqual([]);
  });
});

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { hashBytes } from "../../src/hash.js";
import { appendToLedger, serializeLedger, type LedgerEventDraft, type SealedLedgerEvent } from "../../src/ledger.js";
import { buildReceipt, verifyReceipt, type BuildReceiptInput } from "../../src/receipt.js";
import { checkReceiptInvariants, computeBriefHash, ReceiptShape } from "../../src/schema/receipt.js";
import { generateSigningKeyPair, verifySignatureBlock } from "../../src/sign.js";

const here = dirname(fileURLToPath(import.meta.url));
const receiptsDir = join(here, "..", "fixtures", "receipts");

const loadText = (name: string): string => readFileSync(join(receiptsDir, name), "utf8");
const failingIds = (text: string, opts?: Parameters<typeof verifyReceipt>[1]): string[] =>
  verifyReceipt(text, opts).checks.filter((c) => !c.ok).map((c) => c.id);

// --- a small in-test run to exercise buildReceipt with an ephemeral key ---

const keys = generateSigningKeyPair();

function seal(steps: readonly { event_type: string; payload: Record<string, unknown> }[]): SealedLedgerEvent[] {
  const ledger: SealedLedgerEvent[] = [];
  for (const s of steps) {
    const draft: LedgerEventDraft = {
      schema_version: "0.1",
      event_id: `evt_${String(ledger.length + 1).padStart(4, "0")}`,
      run_id: "run_build_test",
      timestamp: `2026-07-03T12:00:0${ledger.length}Z`,
      event_type: s.event_type,
      source: "loopeix",
      actor_id: null,
      task_run_id: null,
      risk_tier: "T1",
      payload: s.payload,
      related_ids: [],
    };
    ledger.push(appendToLedger(ledger, draft));
  }
  return ledger;
}

const ledger = seal([
  { event_type: "run.started", payload: {} },
  { event_type: "command", payload: { command: "pnpm test", exit_code: 0 } },
  { event_type: "run.completed", payload: {} },
]);

const buildInput: BuildReceiptInput = {
  run: {
    run_id: "run_build_test",
    loop_family: "minimal-bugfix",
    loopeix_version: "v001",
    engine: "codex_cli",
    sealed_at: "2026-07-03T12:01:00Z",
  },
  brief: {
    task: "fix the bug",
    acceptance: [{ id: "tests-pass", label: "all tests pass", kind: "tests-pass" as const }],
    forbidden: [{ id: "no-test-deletion", label: "deleting tests", kind: "delete_paths" as const, globs: ["tests/**"] }],
    scope: ["src/**"],
  },
  claims: [
    { claim_id: "claim_tests_ran", family: "tests-ran", text: "3/3 tests pass", verdict: "VERIFIED", evidence_ids: ["ev_001"] },
  ],
  brief_clauses: [
    { clause_id: "clause_acceptance", clause_type: "acceptance", text: "all tests pass", verdict: "KEPT", evidence_ids: ["ev_001"] },
  ],
  evidence: [
    { evidence_id: "ev_001", type: "command", sha256: hashBytes("pnpm test exit 0"), capture_level: "full", source: "wrapper" },
  ],
  capture_gaps: [],
  ledger,
};

describe("buildReceipt", () => {
  const receipt = buildReceipt(buildInput, keys.privateKeyPem);

  it("produces a schema-valid, invariant-clean, signature-valid receipt", () => {
    const parsed = ReceiptShape.safeParse(receipt);
    expect(parsed.success).toBe(true);
    expect(checkReceiptInvariants(receipt)).toEqual([]);
    const { signature, ...unsigned } = receipt;
    expect(verifySignatureBlock(unsigned, signature)).toBe(true);
  });

  it("derives run_state and integrity_status from the sealed ledger, and binds exact ledger bytes", () => {
    expect(receipt.run.run_state).toBe("completed");
    expect(receipt.run.integrity_status).toBe("valid");
    expect(receipt.ledger_binding.event_count).toBe(3);
    expect(receipt.ledger_binding.head_event_hash).toBe(ledger.at(-1)!.event_hash);
    expect(receipt.ledger_binding.ledger_sha256).toBe(hashBytes(serializeLedger(ledger)));
  });

  it("embeds a recomputable brief_hash and consistent summary counts", () => {
    const { brief_hash, ...content } = receipt.brief;
    expect(brief_hash).toBe(computeBriefHash(content));
    expect(receipt.summary).toEqual({
      claims: { verified: 1, contradicted: 0, unsupported: 0 },
      clauses: { kept: 1, promise_broken: 0, unevaluated: 0 },
    });
  });

  it("full verification passes, including the deep ledger check", () => {
    const res = verifyReceipt(JSON.stringify(receipt), { ledgerText: serializeLedger(ledger) });
    expect(res.checks.map((c) => c.id)).toEqual([
      "parse", "schema", "invariants", "doctrine", "signature", "ledger_hash", "ledger_head", "ledger_chain",
    ]);
    expect(res.ok).toBe(true);
  });

  it("refuses an empty ledger (nothing to bind to)", () => {
    expect(() => buildReceipt({ ...buildInput, ledger: [] }, keys.privateKeyPem)).toThrow(/empty ledger/);
  });
});

describe("golden receipts verify offline", () => {
  for (const name of ["clean-pass.receipt.json", "snitch.receipt.json"]) {
    it(name, () => {
      const res = verifyReceipt(loadText(name));
      expect(res.checks.filter((c) => !c.ok)).toEqual([]);
      expect(res.ok).toBe(true);
    });
  }
});

describe("tamper variants fail with exactly the expected check ids", () => {
  // Verdict flipped AND summary recomputed: schema, invariants, and doctrine all still
  // pass — the signature is the only line of defence, and it holds.
  it("snitch.tampered-verdict → signature only", () => {
    expect(failingIds(loadText("snitch.tampered-verdict.receipt.json"))).toEqual(["signature"]);
  });

  // Hand-built uncited CONTRADICTED: the structural schema (discriminated union), the
  // invariants (stale summary), the independent doctrine re-check, AND the signature all fail.
  it("snitch.uncited-contradiction → schema, invariants, doctrine, signature", () => {
    expect(failingIds(loadText("snitch.uncited-contradiction.receipt.json"))).toEqual([
      "schema", "invariants", "doctrine", "signature",
    ]);
  });

  it("snitch.bad-signature → signature only", () => {
    expect(failingIds(loadText("snitch.bad-signature.receipt.json"))).toEqual(["signature"]);
  });
});

describe("doctrine property over the whole fixture corpus (claim-families-v1.md §Test obligations)", () => {
  const fixtures = readdirSync(receiptsDir).filter((f) => f.endsWith(".receipt.json")).sort();

  it("the corpus contains fixtures and at least one uncited-condemnation case", () => {
    expect(fixtures.length).toBeGreaterThanOrEqual(5);
    expect(fixtures).toContain("snitch.uncited-contradiction.receipt.json");
  });

  for (const name of fixtures) {
    it(`${name}: no CONTRADICTED/PROMISE_BROKEN without a citable evidence id passes verification`, () => {
      const text = loadText(name);
      const raw = JSON.parse(text) as { claims?: unknown[]; brief_clauses?: unknown[] };
      const uncited = [...(raw.claims ?? []), ...(raw.brief_clauses ?? [])].some((item) => {
        const o = item as { verdict?: unknown; evidence_ids?: unknown };
        if (o.verdict !== "CONTRADICTED" && o.verdict !== "PROMISE_BROKEN") return false;
        return !Array.isArray(o.evidence_ids) || !o.evidence_ids.some((id) => typeof id === "string" && id.trim() !== "");
      });
      const res = verifyReceipt(text);
      if (uncited) {
        expect(res.ok).toBe(false);
        expect(res.checks.find((c) => c.id === "doctrine")?.ok).toBe(false);
      } else {
        expect(res.checks.find((c) => c.id === "doctrine")?.ok).toBe(true);
      }
    });
  }
});

describe("deep ledger check against the committed snitch ledger", () => {
  const receiptText = loadText("snitch.receipt.json");
  const ledgerText = loadText("snitch.ledger.jsonl");

  it("verifies against the matching ledger bytes", () => {
    const res = verifyReceipt(receiptText, { ledgerText });
    expect(res.checks.filter((c) => !c.ok)).toEqual([]);
    expect(res.ok).toBe(true);
  });

  it("a single flipped byte fails ledger_hash (and the content-hash chain)", () => {
    const mutated = ledgerText.replace("pnpm test", "pnpm tset");
    const ids = failingIds(receiptText, { ledgerText: mutated });
    expect(ids).toContain("ledger_hash");
    expect(ids).toContain("ledger_chain");
  });

  it("a dropped MIDDLE event breaks the chain (and hash and count)", () => {
    const lines = ledgerText.split("\n");
    lines.splice(4, 1); // remove event 5 of 20
    const ids = failingIds(receiptText, { ledgerText: lines.join("\n") });
    expect(ids).toEqual(expect.arrayContaining(["ledger_hash", "ledger_head", "ledger_chain"]));
  });

  it("a dropped FINAL event leaves a valid shorter chain but fails hash and head binding", () => {
    const lines = ledgerText.split("\n").filter(Boolean);
    const truncated = `${lines.slice(0, -1).join("\n")}\n`;
    const res = verifyReceipt(receiptText, { ledgerText: truncated });
    const byId = new Map(res.checks.map((c) => [c.id, c.ok]));
    expect(byId.get("ledger_chain")).toBe(true); // the prefix is internally intact...
    expect(byId.get("ledger_hash")).toBe(false); // ...but it is NOT the bound ledger
    expect(byId.get("ledger_head")).toBe(false);
    expect(res.ok).toBe(false);
  });

  it("an unreadable ledger is a FAILURE of the ledger checks, never a skip", () => {
    const ids = failingIds(receiptText, { ledgerError: "ENOENT: no such file" });
    expect(ids).toEqual(["ledger_hash", "ledger_head", "ledger_chain"]);
  });
});

describe("verifyReceipt never throws on hostile input", () => {
  const hostile: [string, string][] = [
    ["not JSON", "this is not json"],
    ["empty string", ""],
    ["JSON array", "[1,2,3]"],
    ["JSON null", "null"],
    ["empty object", "{}"],
    ["huge-number JSON (1e999 → Infinity)", '{"receipt_version":"0.1","x":1e999}'],
    ["wrong shapes everywhere", '{"claims":42,"brief_clauses":{"a":1},"signature":"nope"}'],
  ];
  for (const [name, text] of hostile) {
    it(name, () => {
      const res = verifyReceipt(text, { ledgerText: "also garbage {{{" });
      expect(res.ok).toBe(false);
      for (const c of res.checks) {
        expect(typeof c.detail).toBe("string");
        expect(c.detail.length).toBeGreaterThan(0);
      }
    });
  }

  it("a receipt read error fails the parse check with the reader's detail", () => {
    const res = verifyReceipt("", { receiptError: "EACCES: permission denied" });
    const parse = res.checks.find((c) => c.id === "parse");
    expect(parse?.ok).toBe(false);
    expect(parse?.detail).toContain("EACCES");
    expect(res.ok).toBe(false);
  });
});

import { expect } from "vitest";
import { hashBytes } from "../../src/hash.js";
import { appendToLedger, serializeLedger, type LedgerEventDraft, type SealedLedgerEvent } from "../../src/ledger.js";
import { buildReceipt } from "../../src/receipt.js";
import type { Receipt, ReceiptClaimRecord, ReceiptClauseRecord, ReceiptEvidenceRecord } from "../../src/schema/receipt.js";
import { generateSigningKeyPair } from "../../src/sign.js";

/**
 * Shared helpers for the M3 render tests (render-pr / delta-card / pr-command / snitch-demo).
 *
 * `makeSignedReceipt` builds a REAL receipt over a minimal sealed ledger and signs it with an
 * ephemeral in-process key — so the rendering gate genuinely PASSES and what the injection tests
 * prove is the ESCAPING, not a gate bypass. Evidence entries are derived from the union of cited
 * ids, keeping the receipt invariant-clean by construction.
 */

const keys = generateSigningKeyPair();

function seal(steps: readonly { event_type: string; payload: Record<string, unknown> }[]): SealedLedgerEvent[] {
  const ledger: SealedLedgerEvent[] = [];
  for (const s of steps) {
    const draft: LedgerEventDraft = {
      schema_version: "0.1",
      event_id: `evt_${String(ledger.length + 1).padStart(4, "0")}`,
      run_id: "run_render_test",
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

export interface MakeReceiptOptions {
  task?: string;
  claims?: ReceiptClaimRecord[];
  clauses?: ReceiptClauseRecord[];
  /** Extra/override evidence entries; entries for all cited ids are auto-derived when omitted. */
  evidence?: ReceiptEvidenceRecord[];
  captureGaps?: { engine: string; capability: string; level: string; note: string }[];
}

export function makeSignedReceipt(opts: MakeReceiptOptions = {}): { receipt: Receipt; text: string; ledgerText: string } {
  const claims = opts.claims ?? [
    { claim_id: "claim_tests_ran", family: "tests-ran", text: "3/3 tests pass", verdict: "VERIFIED", evidence_ids: ["ev_001"] },
  ];
  const clauses = opts.clauses ?? [
    { clause_id: "clause_acceptance", clause_type: "acceptance", text: "all tests pass", verdict: "KEPT", evidence_ids: ["ev_001"] },
  ];

  const cited = new Set<string>();
  for (const c of claims) for (const id of c.evidence_ids) cited.add(id);
  for (const c of clauses) for (const id of c.evidence_ids) cited.add(id);
  for (const e of opts.evidence ?? []) cited.delete(e.evidence_id);
  const evidence: ReceiptEvidenceRecord[] = [
    ...(opts.evidence ?? []),
    ...[...cited].map((id): ReceiptEvidenceRecord => ({
      evidence_id: id,
      type: "command",
      sha256: hashBytes(id),
      capture_level: "full",
      source: "wrapper",
    })),
  ];

  const ledger = seal([
    { event_type: "run.started", payload: {} },
    { event_type: "command", payload: { command: "pnpm test", exit_code: 0 } },
    { event_type: "run.completed", payload: {} },
  ]);

  const receipt = buildReceipt(
    {
      run: { run_id: "run_render_test", loop_family: "minimal-bugfix", loopeix_version: "v001", engine: "codex_cli", sealed_at: "2026-07-03T12:01:00Z" },
      brief: {
        task: opts.task ?? "fix the bug",
        acceptance: [{ id: "tests-pass", label: "all tests pass", kind: "tests-pass" }],
        forbidden: [{ id: "no-test-deletion", label: "deleting tests", kind: "delete_paths", globs: ["tests/**"] }],
        scope: ["src/**"],
      },
      claims,
      brief_clauses: clauses,
      evidence,
      capture_gaps: opts.captureGaps ?? [],
      ledger,
    },
    keys.privateKeyPem,
  );
  return { receipt, text: JSON.stringify(receipt), ledgerText: serializeLedger(ledger) };
}

/** The M3 injection corpus (delta-card-and-pr-spec.md §Test obligations). */
export const HOSTILE_STRINGS = [
  "pipe | in | table | cells",
  "`backtick` and fenced ``` block",
  '<img src=x onerror="alert(1)">',
  "<script>alert(1)</script>",
  "cdata escape ]]> here",
  "line one\nline two\r\n# injected heading",
  "emoji 💥🟥✅ payload",
  "[link](https://evil.example) ![img](x.png)",
  `attr breakout " onload="evil()`,
  "entity cut &amp test & raw",
  // Backslash-before-pipe: the GFM class. Old mdEsc (no \ escape) → \\| which GFM
  // treats as literal-backslash + STRUCTURAL pipe; new mdEsc → \\\| (escaped backslash
  // + escaped pipe = inert).  The fixed oracle detects the difference; the old one did not.
  "\\|",
  // Double backslash then pipe: two backslashes (even count) before pipe → structural in
  // GFM if naively escaped.  New mdEsc: \\\\\| → two escaped backslashes + escaped pipe.
  "\\\\|",
  // Lone trailing backslash — tests that the renderer doesn't produce a dangling escape or
  // entity cut at the end of a cell.
  "\\",
] as const;

/**
 * Light XML well-formedness assertion — deliberately NOT a real XML parser.
 * It GUARANTEES: every element tag balances and nests correctly, tag names are sane, raw `&` in
 * text is always a known entity, and no stray markup opens from text content (a hostile string
 * that escaped as raw `<...` would tokenize as a tag and fail the name check or the balance).
 * It does NOT validate: attribute grammar in full, namespaces, DTDs, comments/CDATA (which the
 * renderer never emits), or XML character ranges.
 */
export function assertWellFormedXml(s: string): void {
  const entity = /&(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);/y;
  const stack: string[] = [];
  let i = 0;
  while (i < s.length) {
    const lt = s.indexOf("<", i);
    const text = s.slice(i, lt === -1 ? s.length : lt);
    for (let a = text.indexOf("&"); a !== -1; a = text.indexOf("&", a + 1)) {
      entity.lastIndex = a;
      expect(entity.test(text), `raw '&' without a known entity near: ${text.slice(a, a + 12)}`).toBe(true);
    }
    if (lt === -1) break;
    const gt = s.indexOf(">", lt);
    expect(gt, `unclosed '<' at index ${lt}`).toBeGreaterThan(lt);
    const tag = s.slice(lt + 1, gt);
    if (tag.startsWith("?")) {
      // declaration — allowed
    } else if (tag.startsWith("/")) {
      expect(stack.pop(), `close tag </${tag.slice(1)}> mismatched`).toBe(tag.slice(1).trim());
    } else {
      const name = tag.split(/[\s/]/, 1)[0]!;
      expect(name).toMatch(/^[A-Za-z][A-Za-z0-9:_-]*$/);
      // Attribute values must not contain raw '<' (xmlEsc guarantees); quotes must balance.
      expect((tag.match(/"/g) ?? []).length % 2, `unbalanced quotes in <${name} ...>`).toBe(0);
      if (!tag.endsWith("/")) stack.push(name);
    }
    i = gt + 1;
  }
  expect(stack, "unclosed elements remain").toEqual([]);
}

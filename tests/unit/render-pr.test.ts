import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { compressEvidence, renderPrMarkdown } from "../../src/render/pr.js";
import { HOSTILE_STRINGS, makeSignedReceipt } from "../helpers/render.js";

const here = dirname(fileURLToPath(import.meta.url));
const receipts = join(here, "..", "fixtures", "receipts");
const golden = join(here, "..", "golden", "renders");

const loadReceipt = (name: string): string => readFileSync(join(receipts, name), "utf8");
const loadGolden = (name: string): string => readFileSync(join(golden, name), "utf8");

/** Table lines only (rows + header + separator). */
const tableLines = (md: string): string[] => md.split("\n").filter((l) => l.startsWith("|"));

/**
 * Pipes that delimit table cells — only those preceded by an EVEN number of backslashes
 * (the GFM rule: a character is escaped iff preceded by an ODD number of backslashes;
 * `\\|` has 2 = even backslashes, so the `|` IS structural; `\\\|` has 3 = odd, NOT structural).
 */
const structuralPipes = (line: string): number => {
  let count = 0;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === "|") {
      let bs = 0;
      let j = i - 1;
      while (j >= 0 && line[j] === "\\") { bs++; j--; }
      if (bs % 2 === 0) count++;
    }
  }
  return count;
};

/**
 * True when `text` contains `seq` preceded by an EVEN number of backslashes (GFM-unescaped).
 * A single-backslash lookbehind is insufficient: `\\<img` has the `\` as an escaped backslash,
 * leaving `<img` structurally live.
 */
const hasUnescaped = (text: string, seq: string): boolean => {
  let i = 0;
  while (i < text.length) {
    const at = text.indexOf(seq, i);
    if (at === -1) return false;
    let bs = 0;
    let j = at - 1;
    while (j >= 0 && text[j] === "\\") { bs++; j--; }
    if (bs % 2 === 0) return true;
    i = at + 1;
  }
  return false;
};

describe("renderPrMarkdown — golden Markdown (byte-stable)", () => {
  for (const name of ["snitch", "clean-pass"]) {
    it(`${name} receipt renders byte-identical to tests/golden/renders/${name}.pr.md`, () => {
      const res = renderPrMarkdown(loadReceipt(`${name}.receipt.json`));
      expect(res.ok).toBe(true);
      expect(res.markdown).toBe(loadGolden(`${name}.pr.md`));
    });
  }

  it("is deterministic: rendering the same receipt twice is byte-equal", () => {
    const text = loadReceipt("snitch.receipt.json");
    expect(renderPrMarkdown(text).markdown).toBe(renderPrMarkdown(text).markdown);
  });

  it("deep gate: renders identically when the matching ledger is provided", () => {
    const res = renderPrMarkdown(loadReceipt("snitch.receipt.json"), {
      ledgerText: readFileSync(join(receipts, "snitch.ledger.jsonl"), "utf8"),
    });
    expect(res.ok).toBe(true);
    expect(res.markdown).toBe(loadGolden("snitch.pr.md"));
  });
});

describe("renderPrMarkdown — the rendering gate (spec §1 rule 2)", () => {
  for (const [file, check] of [
    ["snitch.tampered-verdict.receipt.json", "signature"],
    ["snitch.bad-signature.receipt.json", "signature"],
    ["snitch.uncited-contradiction.receipt.json", "doctrine"],
  ] as const) {
    it(`${file} → refused, failure block names '${check}', zero partial output`, () => {
      const res = renderPrMarkdown(loadReceipt(file));
      expect(res.ok).toBe(false);
      expect(res.markdown).toBeUndefined();
      expect(res.model).toBeUndefined();
      expect(res.failure).toContain("NOT verified");
      expect(res.failure).toContain(`\`${check}\``);
      expect(res.failedChecks?.some((c) => c.id === check)).toBe(true);
      expect(res.failure).not.toContain("| Verdict |");
    });
  }

  it("deep gate: a mismatched ledger refuses the render", () => {
    const res = renderPrMarkdown(loadReceipt("snitch.receipt.json"), {
      ledgerText: readFileSync(join(receipts, "clean-pass.ledger.jsonl"), "utf8"),
    });
    expect(res.ok).toBe(false);
    expect(res.failedChecks?.map((c) => c.id)).toContain("ledger_hash");
  });

  it("garbage input → refused via the parse check, never a throw", () => {
    const res = renderPrMarkdown("not json at all {{{");
    expect(res.ok).toBe(false);
    expect(res.failedChecks?.[0]?.id).toBe("parse");
  });
});

describe("renderPrMarkdown — ordering (spec §1 rule 4: the red line is the headline)", () => {
  it("bands: CONTRADICTED/PROMISE_BROKEN first, then UNSUPPORTED/UNEVALUATED, then VERIFIED/KEPT", () => {
    const { text } = makeSignedReceipt({
      claims: [
        { claim_id: "claim_a", family: "tests-ran", text: "claim verified", verdict: "VERIFIED", evidence_ids: ["ev_001"] },
        { claim_id: "claim_b", family: "recognized-assertion", text: "claim contradicted", verdict: "CONTRADICTED", evidence_ids: ["ev_002"] },
        { claim_id: "claim_c", family: "recognized-assertion", text: "claim unsupported", verdict: "UNSUPPORTED", evidence_ids: [] },
      ],
      clauses: [
        { clause_id: "clause_a", clause_type: "acceptance", text: "clause kept", verdict: "KEPT", evidence_ids: ["ev_001"] },
        { clause_id: "clause_b", clause_type: "forbidden", text: "clause broken", verdict: "PROMISE_BROKEN", evidence_ids: ["ev_003"] },
        { clause_id: "clause_c", clause_type: "scope", text: "clause unevaluated", verdict: "UNEVALUATED", evidence_ids: [] },
      ],
    });
    const res = renderPrMarkdown(text);
    expect(res.ok).toBe(true);
    expect(res.model!.rows.map((r) => r.band)).toEqual([0, 0, 1, 1, 2, 2]);
    // Within a band: claims before clauses, receipt order preserved.
    expect(res.model!.rows.map((r) => r.id)).toEqual(["claim_b", "clause_b", "claim_c", "clause_c", "claim_a", "clause_a"]);
    // And in the rendered Markdown the first data row is red.
    const rows = tableLines(res.markdown!).slice(2);
    expect(rows[0]).toContain("🟥");
    expect(rows[0]).toContain("`CONTRADICTED`");
  });

  it("the snitch golden's first data row is the PROMISE BROKEN row", () => {
    const rows = tableLines(loadGolden("snitch.pr.md")).slice(2);
    expect(rows[0]).toContain("🟥 `PROMISE BROKEN`");
  });
});

describe("renderPrMarkdown — evidence column (spec §1 rule 5)", () => {
  it("≤4 ids are listed in full", () => {
    expect(compressEvidence(["ev_001", "ev_002", "ev_003", "ev_004"])).toBe("`ev_001`, `ev_002`, `ev_003`, `ev_004`");
  });

  it("a contiguous run above 4 ids compresses to first…last", () => {
    const ids = Array.from({ length: 28 }, (_, i) => `ev_${String(i + 2).padStart(3, "0")}`);
    expect(compressEvidence(ids)).toBe("`ev_002…ev_029`");
  });

  it("non-contiguous ids above 4 stay listed (compression never fakes a range)", () => {
    expect(compressEvidence(["ev_001", "ev_003", "ev_005", "ev_007", "ev_009"])).toBe(
      "`ev_001`, `ev_003`, `ev_005`, `ev_007`, `ev_009`",
    );
  });

  it("mixed: the contiguous run compresses, stragglers stay listed", () => {
    expect(compressEvidence(["ev_001", "ev_002", "ev_003", "ev_004", "ev_009"])).toBe("`ev_001…ev_004`, `ev_009`");
  });

  it("empty renders — (legal only for non-condemning verdicts; the doctrine guarantees that)", () => {
    expect(compressEvidence([])).toBe("—");
    const { text } = makeSignedReceipt({
      claims: [{ claim_id: "claim_a", family: "tests-ran", text: "tests pass", verdict: "UNSUPPORTED", evidence_ids: [] }],
    });
    const res = renderPrMarkdown(text);
    const row = tableLines(res.markdown!).slice(2).find((l) => l.includes("UNSUPPORTED"));
    expect(row).toContain("| — |");
  });

  it("a real >4-citation receipt renders the compressed range end to end", () => {
    const ids = Array.from({ length: 28 }, (_, i) => `ev_${String(i + 2).padStart(3, "0")}`);
    const { text } = makeSignedReceipt({
      clauses: [{ clause_id: "clause_scope", clause_type: "scope", text: "scope: src/**, tests/**", verdict: "KEPT", evidence_ids: ids }],
    });
    const res = renderPrMarkdown(text);
    expect(res.ok).toBe(true);
    expect(res.markdown).toContain("`ev_002…ev_029`");
  });
});

describe("renderPrMarkdown — injection corpus (spec §1 rule 3): hostile fields stay inert", () => {
  for (const hostile of HOSTILE_STRINGS) {
    it(`hostile ${JSON.stringify(hostile.slice(0, 30))} cannot alter table structure`, () => {
      const { text } = makeSignedReceipt({
        task: hostile,
        claims: [
          { claim_id: "claim_a", family: "tests-ran", text: hostile, verdict: "UNSUPPORTED", evidence_ids: [], reason: hostile },
        ],
        clauses: [
          { clause_id: "clause_a", clause_type: "forbidden", text: hostile, verdict: "PROMISE_BROKEN", evidence_ids: ["ev_009"], reason: hostile },
        ],
        captureGaps: [{ engine: "codex_cli", capability: hostile, level: "partial", note: hostile }],
      });
      const res = renderPrMarkdown(text);
      expect(res.ok).toBe(true);
      const md = res.markdown!;

      // Structure: exactly header + separator + 2 data rows, each with exactly 5 structural pipes.
      const lines = tableLines(md);
      expect(lines).toHaveLength(4);
      for (const line of lines) expect(structuralPipes(line)).toBe(5);

      // No live HTML, images, or links: check with the GFM odd-backslash rule (a single-backslash
      // lookbehind misses \\<img where \\ is an escaped backslash leaving <img live).
      expect(hasUnescaped(md, "<img")).toBe(false);
      expect(hasUnescaped(md, "<script")).toBe(false);
      expect(hasUnescaped(md, "](" )).toBe(false); // [text](url) and ![img](url) both need ]( unescaped
      expect(md).not.toMatch(/```/);
      // No injected heading: every '#' line is the renderer's own single H3.
      expect(md.split("\n").filter((l) => l.startsWith("#"))).toEqual(["### Loopeix Claims Check"]);
    });
  }
});

describe("renderPrMarkdown — header, capture gaps, footer", () => {
  it("carries run metadata, the 12-char brief-hash prefix, the verify one-liner, and the tagline", () => {
    const res = renderPrMarkdown(loadReceipt("snitch.receipt.json"));
    const md = res.markdown!;
    expect(md).toContain("**Run** `run_snitch_01` · engine `codex_cli` · state **completed** · integrity **valid**");
    expect(md).toContain("**Sealed brief** `b376e9a77f9b…` — make the test suite green");
    expect(res.model!.brief.brief_hash_prefix).toBe("b376e9a77f9b…");
    // Codex adapter has 4 partial capabilities (file_changes, tool_approvals, browser_actions, subagent_lifecycle).
    expect(md).toContain("**Capture gaps:** 4 partial (codex_cli file_changes");
    expect(md).toContain("    npx loopeix verify receipt.json");
    expect(md).toContain("<sub>Receipts or it didn't happen. Loopeix records locally; only this signed receipt travels.</sub>");
  });

  it("clean-pass also has 4 partial capture gaps (Codex adapter matrix)", () => {
    const res = renderPrMarkdown(loadReceipt("clean-pass.receipt.json"));
    expect(res.markdown).toContain("**Capture gaps:** 4 partial (codex_cli file_changes");
  });

  it("the model carries counts equal to the receipt summary and rows in render order", () => {
    const res = renderPrMarkdown(loadReceipt("snitch.receipt.json"));
    // Live-pipeline snitch (P1-B): codex engine-stream only → scope+acceptance UNEVALUATED, no KEPT.
    expect(res.model!.counts).toEqual({
      claims: { verified: 0, contradicted: 0, unsupported: 1 },
      clauses: { kept: 0, promise_broken: 1, unevaluated: 2 },
    });
    const bands = res.model!.rows.map((r) => r.band);
    expect([...bands].sort((a, b) => a - b)).toEqual(bands); // non-decreasing = band-ordered
  });
});

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { renderDeltaCard } from "../../src/render/delta-card.js";
import { assertWellFormedXml, HOSTILE_STRINGS, makeSignedReceipt } from "../helpers/render.js";

const here = dirname(fileURLToPath(import.meta.url));
const receipts = join(here, "..", "fixtures", "receipts");
const golden = join(here, "..", "golden", "renders");

const loadReceipt = (name: string): string => readFileSync(join(receipts, name), "utf8");
const loadGolden = (name: string): string => readFileSync(join(golden, name), "utf8");

describe("renderDeltaCard — golden SVG (byte-stable)", () => {
  for (const name of ["snitch", "clean-pass"]) {
    it(`${name} receipt renders byte-identical to tests/golden/renders/${name}.delta-card.svg`, () => {
      const res = renderDeltaCard(loadReceipt(`${name}.receipt.json`));
      expect(res.ok).toBe(true);
      expect(res.svg).toBe(loadGolden(`${name}.delta-card.svg`));
    });
  }

  it("is deterministic: rendering the same receipt twice is byte-equal", () => {
    const text = loadReceipt("snitch.receipt.json");
    expect(renderDeltaCard(text).svg).toBe(renderDeltaCard(text).svg);
  });

  it("goldens are well-formed XML with the spec geometry and style", () => {
    for (const name of ["snitch", "clean-pass"]) {
      const svg = loadGolden(`${name}.delta-card.svg`);
      assertWellFormedXml(svg);
      expect(svg).toContain('viewBox="0 0 1200 630"');
      expect(svg).toContain('fill="#0d1117"');
      expect(svg).toContain('stroke="#30363d"');
      expect(svg).toContain('font-family="ui-monospace, SFMono-Regular, Menlo, monospace"');
      expect(svg).toContain("LOOPEIX CLAIMS CHECK");
      for (const label of ["SEALED", "BROKE", "CLAIMED", "VERDICT"]) expect(svg).toContain(`>${label}</text>`);
      expect(svg).toContain("npx loopeix verify receipt.json");
      expect(svg).toContain("receipts or it didn&apos;t happen.");
    }
  });

  it("static markup only: no scripts, foreignObject, or external references (spec §2 rule 1)", () => {
    for (const name of ["snitch", "clean-pass"]) {
      const svg = loadGolden(`${name}.delta-card.svg`);
      expect(svg).not.toContain("<script");
      expect(svg).not.toContain("foreignObject");
      expect(svg).not.toContain("href");
      expect(svg).not.toContain("url(");
      // The ONLY URL in the file is the SVG namespace declaration itself.
      expect(svg.match(/http/g)).toHaveLength(1);
      expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"');
    }
  });
});

describe("renderDeltaCard — the rendering gate (spec §2 rule 3)", () => {
  for (const [file, check] of [
    ["snitch.tampered-verdict.receipt.json", "signature"],
    ["snitch.bad-signature.receipt.json", "signature"],
    ["snitch.uncited-contradiction.receipt.json", "doctrine"],
  ] as const) {
    it(`${file} → refused, no card, failure names '${check}'`, () => {
      const res = renderDeltaCard(loadReceipt(file));
      expect(res.ok).toBe(false);
      expect(res.svg).toBeUndefined();
      expect(res.failedChecks?.some((c) => c.id === check)).toBe(true);
    });
  }

  it("deep gate: a mismatched ledger refuses the card", () => {
    const res = renderDeltaCard(loadReceipt("snitch.receipt.json"), {
      ledgerText: readFileSync(join(receipts, "clean-pass.ledger.jsonl"), "utf8"),
    });
    expect(res.ok).toBe(false);
    expect(res.svg).toBeUndefined();
  });
});

describe("renderDeltaCard — BROKE row truthfulness (documented spec deviation)", () => {
  it("snitch: the broken forbidden clause renders red with its evidence id", () => {
    const svg = loadGolden("snitch.delta-card.svg");
    // Live-pipeline snitch (P1-B): deletion is ev_0014 (14th evidence item in codex event stream).
    expect(svg).toContain('fill="#f85149">deleting or skipping tests — ev_0014</text>');
  });

  it("every clause KEPT → green 'nothing — all promises kept' (synthetic wrapper-full receipt)", () => {
    // The clean-pass STATIC fixture now has UNEVALUATED clauses (engine-stream replay; no wrapper
    // diff). This test covers the GREEN branch for a genuine full-wrapper all-KEPT receipt.
    const { text } = makeSignedReceipt({
      clauses: [
        { clause_id: "clause_acc", clause_type: "acceptance", text: "all tests pass", verdict: "KEPT", evidence_ids: ["ev_001"] },
        { clause_id: "clause_forb", clause_type: "forbidden", text: "no deletions", verdict: "KEPT", evidence_ids: ["ev_001"] },
        { clause_id: "clause_scope", clause_type: "scope", text: "scope: src/**", verdict: "KEPT", evidence_ids: ["ev_001"] },
      ],
    });
    const svg = renderDeltaCard(text).svg!;
    expect(svg).toContain('fill="#3fb950">nothing — all promises kept</text>');
  });

  it("live-pipeline clean-pass renders NEUTRAL not green (UNEVALUATED clauses, no wrapper diff)", () => {
    const svg = loadGolden("clean-pass.delta-card.svg");
    expect(svg).toContain('fill="#8b949e">no broken promise recorded</text>');
    expect(svg).not.toContain("all promises kept");
  });

  it("no broken clause but UNEVALUATED present → NEUTRAL 'no broken promise recorded', never green", () => {
    const { text } = makeSignedReceipt({
      clauses: [
        { clause_id: "clause_a", clause_type: "acceptance", text: "all tests pass", verdict: "KEPT", evidence_ids: ["ev_001"] },
        { clause_id: "clause_b", clause_type: "forbidden", text: "deleting tests", verdict: "UNEVALUATED", evidence_ids: [] },
      ],
    });
    const svg = renderDeltaCard(text).svg!;
    expect(svg).toContain('fill="#8b949e">no broken promise recorded</text>');
    expect(svg).not.toContain("all promises kept");
  });

  it("no clauses at all → neutral too (a vacuous 'all kept' would be dishonest)", () => {
    const { text } = makeSignedReceipt({ clauses: [] });
    const svg = renderDeltaCard(text).svg!;
    expect(svg).toContain('fill="#8b949e">no broken promise recorded</text>');
  });

  it("several broken clauses → the forbidden one is the headline (severity order)", () => {
    const { text } = makeSignedReceipt({
      clauses: [
        { clause_id: "clause_scope", clause_type: "scope", text: "scope breach", verdict: "PROMISE_BROKEN", evidence_ids: ["ev_002"] },
        { clause_id: "clause_forbidden", clause_type: "forbidden", text: "forbidden action", verdict: "PROMISE_BROKEN", evidence_ids: ["ev_003"] },
      ],
    });
    const svg = renderDeltaCard(text).svg!;
    expect(svg).toContain('fill="#f85149">forbidden action — ev_003</text>');
  });
});

describe("renderDeltaCard — CLAIMED / VERDICT rows", () => {
  it("headline claim = the first tests-ran claim even when it is not first in the list", () => {
    const { text } = makeSignedReceipt({
      claims: [
        { claim_id: "claim_x", family: "recognized-assertion", text: "other claim", verdict: "UNSUPPORTED", evidence_ids: [] },
        { claim_id: "claim_y", family: "tests-ran", text: "12/12 tests pass", verdict: "VERIFIED", evidence_ids: ["ev_001"] },
      ],
    });
    const svg = renderDeltaCard(text).svg!;
    expect(svg).toContain("&quot;12/12 tests pass&quot;");
    expect(svg).toContain('fill="#3fb950">VERIFIED</text>');
  });

  it("no tests-ran claim → the first claim of any family is the headline, coloured by its verdict", () => {
    const { text } = makeSignedReceipt({
      claims: [{ claim_id: "claim_x", family: "recognized-assertion", text: "the build is fine", verdict: "UNSUPPORTED", evidence_ids: [], reason: "unrecognized-assertion" }],
    });
    const svg = renderDeltaCard(text).svg!;
    expect(svg).toContain("&quot;the build is fine&quot;");
    expect(svg).toContain('fill="#d29922">UNSUPPORTED — unrecognized-assertion</text>');
  });

  it("no claims at all → stated neutrally, verdict —", () => {
    const { text } = makeSignedReceipt({ claims: [] });
    const svg = renderDeltaCard(text).svg!;
    expect(svg).toContain(">no agent claims recorded</text>");
    expect(svg).toContain('fill="#8b949e">—</text>');
  });
});

describe("renderDeltaCard — injection corpus (spec §2 rule 2): hostile text stays inert XML", () => {
  for (const hostile of HOSTILE_STRINGS) {
    it(`hostile ${JSON.stringify(hostile.slice(0, 30))} cannot become markup`, () => {
      const { text } = makeSignedReceipt({
        task: hostile,
        claims: [{ claim_id: "claim_a", family: "tests-ran", text: hostile, verdict: "UNSUPPORTED", evidence_ids: [], reason: hostile }],
        clauses: [{ clause_id: "clause_a", clause_type: "forbidden", text: hostile, verdict: "PROMISE_BROKEN", evidence_ids: ["ev_009"], reason: hostile }],
      });
      const res = renderDeltaCard(text);
      expect(res.ok).toBe(true);
      const svg = res.svg!;
      assertWellFormedXml(svg);
      expect(svg).not.toContain("<script");
      expect(svg).not.toContain("<img");
      expect(svg).not.toContain("]]>");
      expect(svg).not.toContain("foreignObject");
      expect(svg).not.toContain("href");
      expect(svg).not.toContain("url(");
      // A hostile URL may survive as INERT escaped text, but never as a reference: no attribute
      // in the whole file may carry one (the only attribute URL is the xmlns declaration).
      for (const attr of svg.matchAll(/="([^"]*)"/g)) {
        if (attr[1]!.includes("http")) expect(attr[1]).toBe("http://www.w3.org/2000/svg");
      }
      // The single-line rule survives newline-bearing input: element count is fixed.
      expect((svg.match(/<text /g) ?? []).length).toBe(13);
    });
  }
});

describe("renderDeltaCard — truncation (single line, documented budgets)", () => {
  it("a 200-char task ellipsizes at the 50-code-point budget and never wraps", () => {
    const long = "a very long task ".repeat(12).trim();
    const { text } = makeSignedReceipt({ task: long });
    const svg = renderDeltaCard(text).svg!;
    const value = /fill="#e6edf3">([^<]*)<\/text>/.exec(svg)?.[1] ?? "";
    expect(Array.from(value)).toHaveLength(50);
    expect(value.endsWith("…")).toBe(true);
    expect(value).not.toContain("\n");
  });

  it("emoji (multi-byte code points) are counted as single characters when truncating", () => {
    const long = "💥".repeat(80);
    const { text } = makeSignedReceipt({ task: long });
    const svg = renderDeltaCard(text).svg!;
    assertWellFormedXml(svg); // no half-cut escape or surrogate-broken entity
    expect(svg).toContain(`${"💥".repeat(49)}…`);
  });
});

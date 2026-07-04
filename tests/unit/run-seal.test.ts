import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CodexAdapter, type GateSpecInput } from "../../src/adapters/index.js";
import { loadBrief } from "../../src/brief.js";
import RunStart from "../../src/commands/run/start.js";
import { buildReceipt, verifyReceipt } from "../../src/receipt.js";
import { extractFinalMessageText, parseJsonlEvents } from "../../src/run/engine.js";
import { assembleRun } from "../../src/run/orchestrate.js";
import { RUN_DIR_FILES } from "../../src/run/run-dir.js";
import type { Receipt } from "../../src/schema/receipt.js";
import { generateSigningKeyPair } from "../../src/sign.js";
import { computeVerdicts } from "../../src/verdicts.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const fixtures = join(here, "..", "fixtures", "run-seal");

const keys = generateSigningKeyPair();
const noT5: GateSpecInput = { id: "no-t5", blocking: true, inputs_required: [], waiver_allowed: false };

/** The REAL pipeline over a captured events file: adapter → assembleRun → verdicts → receipt. */
function sealPipeline(eventsFile: string, briefFile: string, runId: string) {
  const raw = parseJsonlEvents(readFileSync(join(fixtures, eventsFile), "utf8"));
  const adapted = new CodexAdapter().normalize(raw);
  const brief = loadBrief(readFileSync(join(fixtures, briefFile), "utf8"));
  const assembly = assembleRun({
    run_id: runId,
    loop_family: "seal-demo",
    loopeix_version: "v001",
    started_at: "2026-07-03T12:00:00Z",
    engine: "codex_cli",
    events: adapted.events,
    capture_gaps: adapted.capture_gaps,
    gates: [noT5],
    risk_controls: { max_tier_without_approval: "T2", t5_allowed: false },
    brief,
  });
  const engineFinalText = extractFinalMessageText("codex_cli", raw);
  const verdicts = computeVerdicts({
    brief,
    events: adapted.events,
    captureGaps: adapted.capture_gaps,
    ...(engineFinalText !== undefined ? { engineFinalText } : {}),
  });
  const receipt = buildReceipt(
    {
      run: { run_id: runId, loop_family: "seal-demo", loopeix_version: "v001", engine: "codex_cli", sealed_at: "2026-07-03T12:10:00Z" },
      brief,
      claims: verdicts.claims,
      brief_clauses: verdicts.brief_clauses,
      evidence: verdicts.evidence,
      capture_gaps: adapted.capture_gaps.map((g) => ({ engine: "codex_cli", capability: g.capability, level: g.level, note: g.note })),
      ledger: assembly.ledger,
    },
    keys.privateKeyPem,
  );
  return { adapted, brief, assembly, receipt };
}

describe("end-to-end: the Snitch replay (codex capture — PROMISE_BROKEN is honestly emittable)", () => {
  const { adapted, assembly, receipt } = sealPipeline("snitch-events.jsonl", "snitch-brief.yaml", "run_seal_snitch");

  it("normalizes the captured stream with nothing unmapped", () => {
    expect(adapted.unmapped_raw_types).toEqual([]);
  });

  it("brief is sealed as ledger event 1, before run.started, with the receipt's exact brief_hash", () => {
    // F7g: this test guards that `brief.sealed` is always the first ledger event (before
    // `run.started`), ensuring the brief is bound to the run before any engine activity.
    expect(assembly.ledger[0]?.event_type).toBe("brief.sealed");
    expect(assembly.ledger[1]?.event_type).toBe("run.started");
    expect((assembly.ledger[0]?.payload as { brief_hash?: string }).brief_hash).toBe(receipt.brief.brief_hash);
    expect(assembly.integrity.integrity_status).toBe("valid");
  });

  it("records THE deletion at ledger event 17", () => {
    const evt17 = assembly.ledger[16];
    expect(evt17?.event_type).toBe("file_change");
    expect(JSON.stringify(evt17?.payload)).toContain("tests/unit/payments.test.ts");
    expect(JSON.stringify(evt17?.payload)).toContain("delete");
  });

  it("the receipt verifies fully, including the deep ledger check", () => {
    const res = verifyReceipt(JSON.stringify(receipt), { ledgerText: assembly.ledger_text });
    expect(res.checks.filter((c) => !c.ok)).toEqual([]);
    expect(res.ok).toBe(true);
  });

  it("tests-pass is EXACTLY UNSUPPORTED with a suite-mutation reason naming the clause label", () => {
    expect(receipt.claims).toHaveLength(1);
    expect(receipt.claims[0]).toMatchObject({ family: "tests-ran", text: "34/34 tests passing", verdict: "UNSUPPORTED" });
    expect(receipt.claims[0]?.reason).toMatch(/^suite-mutated:/);
    // F7b: the reason names the actual broken clause label.
    expect(receipt.claims[0]?.reason).toContain("forbidden clause 'deleting or skipping tests' broken");
  });

  it("the forbidden clause is PROMISE_BROKEN citing the deletion evidence (ev_0014)", () => {
    const forbidden = receipt.brief_clauses.find((c) => c.clause_id === "clause_no_test_deletion");
    expect(forbidden?.verdict).toBe("PROMISE_BROKEN");
    expect(forbidden?.evidence_ids).toEqual(["ev_0014"]);
    expect(forbidden?.reason).toContain("tests/unit/payments.test.ts");
    const cited = receipt.evidence.find((e) => e.evidence_id === "ev_0014");
    expect(cited).toMatchObject({ type: "file", capture_level: "partial", source: "engine_stream" });
  });

  it("F4: scope is UNEVALUATED (KEPT removed in v1; stream completeness not independently verified)", () => {
    // Under the revised presence/absence doctrine, absence cannot acquit.
    // KEPT requires wrapper-verified completeness (phase two). UNEVALUATED is the honest v1 answer.
    expect(receipt.brief_clauses.find((c) => c.clause_id === "clause_scope")?.verdict).toBe("UNEVALUATED");
    expect(receipt.summary.clauses).toEqual({ kept: 0, promise_broken: 1, unevaluated: 2 });
  });
});

describe("end-to-end: the honest clean replay (F4: containment → UNEVALUATED)", () => {
  const { assembly, receipt } = sealPipeline("clean-events.jsonl", "clean-brief.yaml", "run_seal_clean");

  it("tests-pass is VERIFIED; containment clauses (forbidden, scope) are UNEVALUATED; receipt verifies", () => {
    // F4: KEPT is removed for F2/F3 containment clauses. The acceptance clause remains KEPT
    // (driven by F1 logic, not containment doctrine).
    expect(receipt.claims.map((c) => c.verdict)).toEqual(["VERIFIED"]);
    // [acceptance-KEPT, forbidden-UNEVALUATED, scope-UNEVALUATED]
    expect(receipt.brief_clauses[0]?.clause_type).toBe("acceptance");
    expect(receipt.brief_clauses[0]?.verdict).toBe("KEPT"); // F1 acceptance still KEPT when VERIFIED
    expect(receipt.brief_clauses[1]?.clause_type).toBe("forbidden");
    expect(receipt.brief_clauses[1]?.verdict).toBe("UNEVALUATED");
    expect(receipt.brief_clauses[2]?.clause_type).toBe("scope");
    expect(receipt.brief_clauses[2]?.verdict).toBe("UNEVALUATED");
    expect(receipt.summary).toEqual({
      claims: { verified: 1, contradicted: 0, unsupported: 0 },
      clauses: { kept: 1, promise_broken: 0, unevaluated: 2 },
    });
    const res = verifyReceipt(JSON.stringify(receipt), { ledgerText: assembly.ledger_text });
    expect(res.ok).toBe(true);
  });
});

describe("F5 path-shape equivalence: relative fixture paths ≡ real absolute paths + matching workspaceRoot", () => {
  // Real Codex emits ABSOLUTE file_change paths under the run workspace (live capture
  // 2026-07-04, codex-cli 0.142.3). The committed fixtures keep the canonical post-strip
  // RELATIVE form for replay portability (see tests/fixtures/run-seal/README.md). This test
  // proves the two shapes adjudicate identically: absolutize every path under a synthetic
  // root, pass that root as workspaceRoot, and the verdicts must be byte-equal.
  it("snitch events absolutized under a synthetic root produce identical claims and clause verdicts", () => {
    const ROOT = "/workspace/seal-demo";
    const relText = readFileSync(join(fixtures, "snitch-events.jsonl"), "utf8");
    const absText = relText.replace(/"path":"/g, `"path":"${ROOT}/`);
    const brief = loadBrief(readFileSync(join(fixtures, "snitch-brief.yaml"), "utf8"));

    const relRaw = parseJsonlEvents(relText);
    const absRaw = parseJsonlEvents(absText);
    const rel = new CodexAdapter().normalize(relRaw);
    const abs = new CodexAdapter().normalize(absRaw);
    const engineFinalText = extractFinalMessageText("codex_cli", relRaw);

    const relVerdicts = computeVerdicts({
      brief, events: rel.events, captureGaps: rel.capture_gaps,
      ...(engineFinalText !== undefined ? { engineFinalText } : {}),
    });
    const absVerdicts = computeVerdicts({
      brief, events: abs.events, captureGaps: abs.capture_gaps,
      workspaceRoot: ROOT,
      ...(engineFinalText !== undefined ? { engineFinalText } : {}),
    });

    // Claims and clause records (verdicts, cited evidence ids, reasons) must be identical —
    // reasons cite post-normalization paths, so even the cited paths match exactly.
    expect(absVerdicts.claims).toEqual(relVerdicts.claims);
    expect(absVerdicts.brief_clauses).toEqual(relVerdicts.brief_clauses);
    // Same evidence ids in the same order (sha256 differs: payload bytes carry the raw paths).
    expect(absVerdicts.evidence.map((e) => e.evidence_id)).toEqual(relVerdicts.evidence.map((e) => e.evidence_id));
    // And the flagship verdicts hold in the absolute shape.
    expect(absVerdicts.brief_clauses.find((c) => c.clause_id === "clause_no_test_deletion")?.verdict).toBe("PROMISE_BROKEN");
  });
});

describe("doctrine property over the generated receipts", () => {
  it("no CONTRADICTED/PROMISE_BROKEN without a resolvable evidence id, in either receipt", () => {
    for (const name of [["snitch-events.jsonl", "snitch-brief.yaml"], ["clean-events.jsonl", "clean-brief.yaml"]] as const) {
      const { receipt } = sealPipeline(name[0], name[1], "run_seal_prop");
      const ids = new Set(receipt.evidence.map((e) => e.evidence_id));
      for (const item of [...receipt.claims, ...receipt.brief_clauses]) {
        if (item.verdict !== "CONTRADICTED" && item.verdict !== "PROMISE_BROKEN") continue;
        expect(item.evidence_ids.length).toBeGreaterThan(0);
        for (const id of item.evidence_ids) expect(ids.has(id)).toBe(true);
      }
    }
  });
});

describe("F7f: failed-run receipt — run.failed ledger + receipt.json still written and verifiable", () => {
  it("a run that results in run.failed still produces a verifiable receipt", () => {
    // Simulate an engine failure by constructing an events stream that ends with an error event.
    // The adapter produces an error-bearing ledger; the receipt should still seal + verify.
    const raw = parseJsonlEvents(readFileSync(join(fixtures, "snitch-events.jsonl"), "utf8"));
    const adapted = new CodexAdapter().normalize(raw);
    const brief = loadBrief(readFileSync(join(fixtures, "snitch-brief.yaml"), "utf8"));
    // Inject a run-failed condition by using assembleRun with engine_status fail.
    const assembly = assembleRun({
      run_id: "run_failed_test",
      loop_family: "seal-demo",
      loopeix_version: "v001",
      started_at: "2026-07-03T12:00:00Z",
      engine: "codex_cli",
      events: adapted.events,
      capture_gaps: adapted.capture_gaps,
      gates: [noT5],
      risk_controls: { max_tier_without_approval: "T2", t5_allowed: false },
      brief,
      engine_status: { exit_code: 1, timed_out: false }, // non-zero exit → run.failed
    });
    const verdicts = computeVerdicts({ brief, events: adapted.events, captureGaps: adapted.capture_gaps });
    const receipt = buildReceipt(
      {
        run: { run_id: "run_failed_test", loop_family: "seal-demo", loopeix_version: "v001", engine: "codex_cli", sealed_at: "2026-07-03T12:10:00Z" },
        brief,
        claims: verdicts.claims,
        brief_clauses: verdicts.brief_clauses,
        evidence: verdicts.evidence,
        capture_gaps: adapted.capture_gaps.map((g) => ({ engine: "codex_cli", capability: g.capability, level: g.level, note: g.note })),
        ledger: assembly.ledger,
      },
      keys.privateKeyPem,
    );
    // The run state should be "failed" (not "completed").
    expect(receipt.run.run_state).toBe("failed");
    // The receipt still verifies — a truthful record of a failed run is still a record.
    const res = verifyReceipt(JSON.stringify(receipt), { ledgerText: assembly.ledger_text });
    expect(res.ok).toBe(true);
  });
});

describe("CLI: loopeix run start --events-file --seal (temp workspace)", () => {
  let ws: string;
  let logged: string[];
  let spy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    ws = mkdtempSync(join(tmpdir(), "loopeix-seal-"));
    logged = [];
    spy = vi.spyOn(RunStart.prototype, "log").mockImplementation(function (message?: unknown): void {
      logged.push(String(message ?? ""));
    });
  });
  afterEach(() => {
    spy.mockRestore();
    rmSync(ws, { recursive: true, force: true });
  });

  async function runSealed(): Promise<{ exitCode: number; runDir: string; receipt: Receipt }> {
    const before = process.exitCode;
    process.exitCode = 0;
    try {
      await RunStart.run(
        [
          join(fixtures, "seal-loop.yaml"),
          "--engine", "codex",
          "--events-file", join(fixtures, "snitch-events.jsonl"),
          "--seal", join(fixtures, "snitch-brief.yaml"),
          "--workspace", ws,
        ],
        repoRoot,
      );
      const runsDir = join(ws, ".loopeix", "runs");
      const runDir = join(runsDir, readdirSync(runsDir).sort().at(-1)!);
      const receipt = JSON.parse(readFileSync(join(runDir, RUN_DIR_FILES.receipt), "utf8")) as Receipt;
      return { exitCode: Number(process.exitCode ?? 0), runDir, receipt };
    } finally {
      process.exitCode = before;
    }
  }

  it("writes a verifiable receipt.json, prints verdict summary + verify hint, exit code unchanged (0)", async () => {
    const { exitCode, runDir, receipt } = await runSealed();
    expect(exitCode).toBe(0);

    const res = verifyReceipt(JSON.stringify(receipt), {
      ledgerText: readFileSync(join(runDir, RUN_DIR_FILES.ledger), "utf8"),
    });
    expect(res.ok).toBe(true);

    const out = logged.join("\n");
    expect(out).toContain("Sealed brief verdicts");
    expect(out).toContain("UNSUPPORTED  34/34 tests passing");
    expect(out).toContain("PROMISE_BROKEN  deleting or skipping tests");
    expect(out).toContain(`verify: npx loopeix verify ${runDir}/${RUN_DIR_FILES.receipt}`);
  });

  it("creates the signing key once (0600, git-ignored) and reuses it on the next sealed run", async () => {
    const first = await runSealed();
    const keyPath = join(ws, ".loopeix", "keys", "signing-key.pem");
    expect(existsSync(keyPath)).toBe(true);
    expect(statSync(keyPath).mode & 0o777).toBe(0o600);
    expect(readFileSync(join(ws, ".loopeix", "keys", ".gitignore"), "utf8")).toBe("*\n");
    const announced = logged.join("\n");
    expect(announced).toContain("Created signing key");
    expect(announced).not.toContain("PRIVATE KEY"); // key material never reaches stdout

    logged.length = 0;
    const second = await runSealed();
    expect(logged.join("\n")).not.toContain("Created signing key");
    expect(second.receipt.signature.public_key_spki_b64).toBe(first.receipt.signature.public_key_spki_b64);
  });
});

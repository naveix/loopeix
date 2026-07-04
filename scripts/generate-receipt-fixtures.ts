import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { CodexAdapter } from "../src/adapters/index.js";
import { loadBrief } from "../src/brief.js";
import { serializeLedger } from "../src/ledger.js";
import { buildReceipt, verifyReceipt } from "../src/receipt.js";
import type { Receipt, ReceiptClaimRecord } from "../src/schema/receipt.js";
import { extractFinalMessageText, parseJsonlEvents } from "../src/run/engine.js";
import { assembleRun } from "../src/run/orchestrate.js";
import { generateSigningKeyPair } from "../src/sign.js";
import { computeVerdicts } from "../src/verdicts.js";

/**
 * Generate the golden receipt fixtures (flagship-decision.md M1 + M2), tsx-run like generate-schema.ts.
 *
 * KEY HYGIENE: a fresh ephemeral P-256 keypair is generated IN-PROCESS per run, used to sign the
 * golden receipts, and discarded when the process exits — no private key is ever written to disk
 * or committed. Only the PUBLIC key travels, embedded in each receipt's signature block.
 *
 * DETERMINISM: all content (ids, timestamps, ledgers, hashes, verdicts) is fixed, so the ledger
 * fixtures are byte-identical across runs; ECDSA signing is randomized (see src/sign.ts), so two
 * consecutive runs differ ONLY in each receipt's `signature.public_key_spki_b64` and
 * `signature.signature_b64` fields. Verify with: run twice, diff — nothing else may change.
 *
 * PIPELINE (P1-B): fixtures are now derived from the LIVE pipeline — adapter normalize over the
 * committed run-seal JSONL events → assembleRun (gives the real ledger) → computeVerdicts
 * (admission-based doctrine) → buildReceipt. This ensures ONE snitch truth across M1 verify
 * tests, M3 goldens, and the snitch-demo. Results:
 *  - Containment clauses (acceptance, scope) are UNEVALUATED: the Codex engine-stream cannot
 *    guarantee completeness for negative-certification (no wrapper filesystem diff in v1).
 *  - The forbidden-deletion clause is PROMISE_BROKEN: it is an admission (the engine reported
 *    the file_change delete event) and admission convicts at any capture level.
 *  - The claim text comes from the recognized engine assertion ("34/34 tests passing").
 *  - Evidence IDs use the 4-digit pipeline format (ev_0001, ev_0014, ...).
 *
 * Fixtures written to tests/fixtures/receipts/:
 *  - clean-pass.receipt.json (+ clean-pass.ledger.jsonl) — the honest pass.
 *  - snitch.receipt.json (+ snitch.ledger.jsonl) — THE flagship: forbidden test deletion,
 *    PROMISE_BROKEN cited, tests-ran capped at UNSUPPORTED (suite-mutated).
 *  - snitch.tampered-verdict.receipt.json — PROMISE_BROKEN flipped to KEPT, summary recomputed,
 *    original signature kept: ONLY the signature check can catch it.
 *  - snitch.uncited-contradiction.receipt.json — hand-built CONTRADICTED with no evidence:
 *    schema, invariants, doctrine, AND signature all fail.
 *  - snitch.bad-signature.receipt.json — signature_b64 corrupted: only signature fails.
 */

const here = dirname(fileURLToPath(import.meta.url));
const runSealDir = join(here, "..", "tests", "fixtures", "run-seal");
const outDir = join(here, "..", "tests", "fixtures", "receipts");
mkdirSync(outDir, { recursive: true });

const keyPair = generateSigningKeyPair(); // ephemeral: dies with this process

function writeJson(name: string, value: unknown): void {
  writeFileSync(join(outDir, name), `${JSON.stringify(value, null, 2)}\n`);
  console.log(`wrote ${join(outDir, name)}`);
}

function writeText(name: string, text: string): void {
  writeFileSync(join(outDir, name), text);
  console.log(`wrote ${join(outDir, name)}`);
}

/** Every golden and tamper fixture must behave as documented before it is committed to disk. */
function assertFailingChecks(receipt: unknown, expected: readonly string[], label: string): void {
  const res = verifyReceipt(JSON.stringify(receipt));
  const failing = res.checks.filter((c) => !c.ok).map((c) => c.id);
  if (JSON.stringify(failing) !== JSON.stringify([...expected])) {
    throw new Error(`${label}: expected failing checks [${expected.join(", ")}], got [${failing.join(", ")}]`);
  }
}

// ---------------------------------------------------------------------------
// Load the shared spec, briefs, and adapter once.
// ---------------------------------------------------------------------------

const spec = parseYaml(readFileSync(join(runSealDir, "seal-loop.yaml"), "utf8")) as Record<string, unknown>;
const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

const gates = asArray(spec.gates).map((g) => {
  const gate = g as Record<string, unknown>;
  return {
    id: String(gate.id),
    blocking: gate.blocking === true,
    inputs_required: asArray(gate.inputs_required).map(String),
    waiver_allowed: gate.waiver_allowed === true,
  };
});
const riskControls = spec.risk_controls as { max_tier_without_approval: string; t5_allowed: boolean };
const loopFamily = String(spec.loop_family);
const loopVersion = String(spec.version);

const adapter = new CodexAdapter();

const snitchBrief = loadBrief(readFileSync(join(runSealDir, "snitch-brief.yaml"), "utf8"));
const cleanBrief = loadBrief(readFileSync(join(runSealDir, "clean-brief.yaml"), "utf8"));

const snitchRaw = parseJsonlEvents(readFileSync(join(runSealDir, "snitch-events.jsonl"), "utf8"));
const cleanRaw = parseJsonlEvents(readFileSync(join(runSealDir, "clean-events.jsonl"), "utf8"));

const snitchNorm = adapter.normalize(snitchRaw);
const cleanNorm = adapter.normalize(cleanRaw);

// ---------------------------------------------------------------------------
// Assemble runs (fixed run_id + started_at for byte-stable ledger content).
// ---------------------------------------------------------------------------

const snitchAssembly = assembleRun({
  run_id: "run_snitch_01",
  loop_family: loopFamily,
  loopeix_version: loopVersion,
  started_at: "2026-07-03T11:00:00Z",
  engine: "codex_cli",
  events: snitchNorm.events,
  capture_gaps: snitchNorm.capture_gaps,
  gates,
  risk_controls: riskControls,
  brief: snitchBrief,
});

const cleanAssembly = assembleRun({
  run_id: "run_clean_pass_01",
  loop_family: loopFamily,
  loopeix_version: loopVersion,
  started_at: "2026-07-03T10:00:00Z",
  engine: "codex_cli",
  events: cleanNorm.events,
  capture_gaps: cleanNorm.capture_gaps,
  gates,
  risk_controls: riskControls,
  brief: cleanBrief,
});

// ---------------------------------------------------------------------------
// Compute verdicts via the doctrine engine (P1-B: one snitch truth).
// ---------------------------------------------------------------------------

const snitchVerdicts = computeVerdicts({
  brief: snitchBrief,
  events: snitchNorm.events,
  captureGaps: snitchNorm.capture_gaps,
  engineFinalText: extractFinalMessageText("codex_cli", snitchRaw),
});

const cleanVerdicts = computeVerdicts({
  brief: cleanBrief,
  events: cleanNorm.events,
  captureGaps: cleanNorm.capture_gaps,
  engineFinalText: extractFinalMessageText("codex_cli", cleanRaw),
});

// Capture gaps in receipt: all adapter gaps annotated with the engine id.
type CapGap = { engine: "codex_cli"; capability: (typeof snitchNorm.capture_gaps)[number]["capability"]; level: string; note: string };
const snitchGaps: CapGap[] = snitchNorm.capture_gaps.map((g) => ({ engine: "codex_cli", capability: g.capability, level: g.level, note: g.note }));
const cleanGaps: CapGap[] = cleanNorm.capture_gaps.map((g) => ({ engine: "codex_cli", capability: g.capability, level: g.level, note: g.note }));

// ---------------------------------------------------------------------------
// Build and sign receipts.
// ---------------------------------------------------------------------------

const snitch = buildReceipt(
  {
    run: {
      run_id: "run_snitch_01",
      loop_family: loopFamily,
      loopeix_version: loopVersion,
      engine: "codex_cli",
      sealed_at: "2026-07-03T11:05:00Z",
    },
    brief: snitchBrief,
    claims: snitchVerdicts.claims,
    brief_clauses: snitchVerdicts.brief_clauses,
    evidence: snitchVerdicts.evidence,
    capture_gaps: snitchGaps,
    ledger: snitchAssembly.ledger,
  },
  keyPair.privateKeyPem,
);

const cleanPass = buildReceipt(
  {
    run: {
      run_id: "run_clean_pass_01",
      loop_family: loopFamily,
      loopeix_version: loopVersion,
      engine: "codex_cli",
      sealed_at: "2026-07-03T10:05:00Z",
    },
    brief: cleanBrief,
    claims: cleanVerdicts.claims,
    brief_clauses: cleanVerdicts.brief_clauses,
    evidence: cleanVerdicts.evidence,
    capture_gaps: cleanGaps,
    ledger: cleanAssembly.ledger,
  },
  keyPair.privateKeyPem,
);

// ---------------------------------------------------------------------------
// Tamper variants — derived from the SIGNED snitch receipt, so each carries the
// original (now stale) signature.
// ---------------------------------------------------------------------------

// Verdict flip with the summary recomputed to stay consistent: schema, invariants,
// and doctrine all still pass — ONLY the signature can catch this tamper.
const tamperedVerdict = structuredClone(snitch) as Receipt;
const flipped = tamperedVerdict.brief_clauses.find((c) => c.verdict === "PROMISE_BROKEN");
if (!flipped) throw new Error("snitch receipt drifted: no PROMISE_BROKEN clause to flip");
(flipped as { verdict: string }).verdict = "KEPT";
tamperedVerdict.summary.clauses.promise_broken -= 1;
tamperedVerdict.summary.clauses.kept += 1;

// A hostile hand-built uncited condemnation, with summary and signature left stale:
// schema (doctrine is structural), invariants, doctrine, and signature ALL fail.
const uncited = structuredClone(snitch) as Receipt;
uncited.claims.push({
  claim_id: "claim_hostile_01",
  family: "recognized-assertion",
  text: "the agent's 34/34 report is false",
  verdict: "CONTRADICTED",
  evidence_ids: [],
} as unknown as ReceiptClaimRecord);

// Corrupted signature bytes (still valid base64): only the signature check fails.
const badSignature = structuredClone(snitch) as Receipt;
badSignature.signature.signature_b64 = `${badSignature.signature.signature_b64.startsWith("A") ? "B" : "A"}${badSignature.signature.signature_b64.slice(1)}`;

// ---------------------------------------------------------------------------
// Self-check every fixture against its documented verification outcome, then write.
// ---------------------------------------------------------------------------

assertFailingChecks(cleanPass, [], "clean-pass");
assertFailingChecks(snitch, [], "snitch");
assertFailingChecks(tamperedVerdict, ["signature"], "snitch.tampered-verdict");
assertFailingChecks(uncited, ["schema", "invariants", "doctrine", "signature"], "snitch.uncited-contradiction");
assertFailingChecks(badSignature, ["signature"], "snitch.bad-signature");

writeJson("clean-pass.receipt.json", cleanPass);
writeText("clean-pass.ledger.jsonl", serializeLedger(cleanAssembly.ledger));
writeJson("snitch.receipt.json", snitch);
writeText("snitch.ledger.jsonl", serializeLedger(snitchAssembly.ledger));
writeJson("snitch.tampered-verdict.receipt.json", tamperedVerdict);
writeJson("snitch.uncited-contradiction.receipt.json", uncited);
writeJson("snitch.bad-signature.receipt.json", badSignature);

// Summary for quick inspection.
console.log("\nVerdicts summary:");
console.log("snitch claims:", snitch.claims.map((c) => `${c.verdict} ${c.text}`).join(", "));
console.log("snitch clauses:", snitch.brief_clauses.map((c) => `${c.verdict} [${c.clause_type}]`).join(", "));
console.log("snitch summary:", JSON.stringify(snitch.summary));
console.log("clean claims:", cleanPass.claims.map((c) => `${c.verdict} ${c.text}`).join(", "));
console.log("clean clauses:", cleanPass.brief_clauses.map((c) => `${c.verdict} [${c.clause_type}]`).join(", "));
console.log("clean summary:", JSON.stringify(cleanPass.summary));

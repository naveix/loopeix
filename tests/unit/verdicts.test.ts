import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ClaudeAdapter, CodexAdapter, type CaptureGap, type NormalizedEvent } from "../../src/adapters/index.js";
import { extractEvidence } from "../../src/run/orchestrate.js";
import { BriefShape, type Brief } from "../../src/schema/brief.js";
import { computeVerdicts, isTestRunnerCommand, type VerdictOutput } from "../../src/verdicts.js";

// Real declared capture-gap sets — the exact inputs the CLI pipeline feeds the engine.
// NB: after the M2 adversarial fix-pass, Codex file_changes is PARTIAL (engine self-report).
const codexGaps: CaptureGap[] = new CodexAdapter().normalize([]).capture_gaps; // command FULL, file PARTIAL
const claudeGaps: CaptureGap[] = new ClaudeAdapter().normalize([]).capture_gaps; // command PARTIAL, file PARTIAL

const cmd = (command: string, exit_code: number): NormalizedEvent => ({
  source: "codex_cli",
  kind: "command",
  raw_type: "item.completed:command_execution",
  payload: { item_type: "command_execution", command, exit_code, status: exit_code === 0 ? "completed" : "failed" },
});
const change = (path: string, kind?: string): NormalizedEvent => ({
  source: "codex_cli",
  kind: "file_change",
  raw_type: "item.completed:file_change",
  payload: { item_type: "file_change", status: "completed", changes: [{ path, ...(kind !== undefined ? { kind } : {}) }] },
});
// A Claude-style inferred command event: no command text (partial capture).
const claudeCmd = (): NormalizedEvent => ({
  source: "claude_code_cli",
  kind: "command",
  raw_type: "assistant.tool_use",
  payload: { tool: "Bash" },
});

const makeBrief = (over: Record<string, unknown> = {}): Brief =>
  BriefShape.parse({
    brief_version: "0.1",
    task: "make the test suite green",
    acceptance: [{ id: "tests-pass", label: "all tests pass", kind: "tests-pass" }],
    forbidden: [{ id: "no-test-deletion", label: "deleting or skipping tests", kind: "delete_paths", globs: ["tests/**"] }],
    scope: ["src/**", "tests/**"],
    ...over,
  });

const clauseById = (out: VerdictOutput, id: string) => out.brief_clauses.find((c) => c.clause_id === id);

// ─────────────────────────────────────────────────────────────────────────────
// F2 (adversarial fix): program-position runner recognizer corpus
// ─────────────────────────────────────────────────────────────────────────────

describe("test-runner recognizer — program-position corpus (F2 fix)", () => {
  it("recognizes documented runners at program position", () => {
    const SHOULD_RECOGNIZE = [
      "pnpm test",
      "npm run test",
      "npm test",
      "yarn test",
      "bun test",
      "deno test",
      "npx vitest run",
      "vitest",
      "vitest run",
      "npx jest --ci",
      "jest --coverage",
      "pytest -q",
      "mocha",
      "go test ./...",
      "cargo test --workspace",
      "pnpm exec vitest",
      "node --test",
      "node --experimental-vm-modules --test",
      "./node_modules/.bin/vitest",
      "NODE_ENV=test pnpm test",
      "CI=1 TERM=dumb npx vitest run",
      // Note: "npx pnpm-dlx vitest" is intentionally excluded — pnpm-dlx is not a real binary;
      // the correct form is "pnpm dlx vitest" and nested-proxy detection is out of scope for v1.
    ];
    for (const c of SHOULD_RECOGNIZE) {
      expect(isTestRunnerCommand(c), `should recognize: ${c}`).toBe(true);
    }
  });

  it("alias corpus: truthful runner aliases must NOT be recognized (miss → UNSUPPORTED, not CONTRADICTED)", () => {
    // These runners are VALID test runners that our allowlist does not cover.
    // A missed runner → UNSUPPORTED (no CONTRADICTED). This is intentional and safe.
    const ALIASES = [
      "make test",
      "./scripts/test.sh",
      "bash run_tests.sh",
      "sh -c 'pytest'", // compound shell — tokenizer sees `sh` not `pytest`
    ];
    for (const c of ALIASES) {
      expect(isTestRunnerCommand(c), `alias should NOT be recognized: ${c}`).toBe(false);
    }
  });

  it("substring corpus: commands with runner names in args/filenames must NOT be recognized", () => {
    const SUBSTRING_CASES = [
      "sed -i 's/a/b/' vitest.config.ts",    // sed is the program; vitest.config.ts is an arg
      "cat vitest.config.ts",                  // cat is the program
      "rm tests/jest.config.js",              // rm is the program
      "git commit -m 'cargo test now passes'", // git is the program; message has cargo test
      "echo 'pnpm test'",                      // echo is the program
      "grep vitest package.json",              // grep is the program
      "cp jest.config.js jest.config.bak",     // cp is the program
      "mv mocha.opts .mocharc.js",             // mv is the program
      "less vitest.config.ts",                 // less is the program
      "pnpm testx",                            // pnpm with `testx` subcommand, not `test`
      "cargo build",                           // cargo without `test`
      "go build",                              // go without `test`
      "attest something",                      // looks like a runner suffix; it's not
      "git status",
      "ls -la",
      "echo test",                             // `test` appears but not as a runner subcommand
    ];
    for (const c of SUBSTRING_CASES) {
      expect(isTestRunnerCommand(c), `should NOT recognize: ${c}`).toBe(false);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// F1: tests-ran adjudication
// ─────────────────────────────────────────────────────────────────────────────

describe("F1 tests-ran — honest pass / honest violation", () => {
  it("green runner + full command capture + no mutation → claim VERIFIED, acceptance KEPT, runner cited", () => {
    const out = computeVerdicts({ brief: makeBrief(), events: [cmd("pnpm test", 0)], captureGaps: codexGaps });
    expect(out.claims).toHaveLength(1);
    expect(out.claims[0]).toMatchObject({ family: "tests-ran", verdict: "VERIFIED", evidence_ids: ["ev_0001"] });
    expect(clauseById(out, "clause_tests_pass")?.verdict).toBe("KEPT");
  });

  it("failing runner + full-pass assertion → CONTRADICTED citing the runner command evidence id + exit code (never command text)", () => {
    const out = computeVerdicts({
      brief: makeBrief(),
      events: [cmd("pnpm test", 1)],
      captureGaps: codexGaps,
      engineFinalText: "Done — 12/12 tests passing",
    });
    expect(out.claims[0]).toMatchObject({ verdict: "CONTRADICTED", evidence_ids: ["ev_0001"] });
    expect(out.claims[0]?.reason).toContain("exited 1");
    expect(out.claims[0]?.reason).toContain("ev_0001");
    // F6: raw command text must NOT appear in the reason (could carry inline secrets).
    expect(out.claims[0]?.reason).not.toContain("pnpm test");
    expect(clauseById(out, "clause_tests_pass")?.verdict).toBe("PROMISE_BROKEN");
  });

  it("failing runner WITHOUT any success assertion → UNSUPPORTED, never CONTRADICTED", () => {
    const out = computeVerdicts({ brief: makeBrief(), events: [cmd("pnpm test", 1)], captureGaps: codexGaps });
    expect(out.claims[0]?.verdict).toBe("UNSUPPORTED");
  });

  it("F1 (absence rule): success asserted with ZERO recognized runners → UNSUPPORTED, never CONTRADICTED", () => {
    // Doctrine rule: absence of a recognized runner execution is NOT a contradiction.
    // `make test` (or any aliased runner) runs tests truthfully, but the allowlist misses it —
    // UNSUPPORTED is the honest answer; CONTRADICTED would be a false condemnation.
    const out = computeVerdicts({
      brief: makeBrief(),
      events: [cmd("ls -la", 0)],
      captureGaps: codexGaps,
      engineFinalText: "All done, 8/8 tests passed",
    });
    expect(out.claims[0]?.verdict).toBe("UNSUPPORTED");
    expect(out.claims[0]?.reason).toContain("no recognized test-runner execution");
    // Evidence ids may be empty (no runner evidence to cite).
    const ids = new Set(out.evidence.map((e) => e.evidence_id));
    for (const id of out.claims[0]!.evidence_ids) expect(ids.has(id), id).toBe(true);
  });

  it("F1 alias: make test claims all-pass + no recognized runner → UNSUPPORTED (truthful-pass-with-alias never CONTRADICTED)", () => {
    // The classic alias problem: a green make test run that our allowlist misses.
    // Must produce UNSUPPORTED, not CONTRADICTED.
    const out = computeVerdicts({
      brief: makeBrief(),
      events: [cmd("make test", 0)],
      captureGaps: codexGaps,
      engineFinalText: "34/34 tests passing",
    });
    expect(out.claims[0]?.verdict).toBe("UNSUPPORTED");
    expect(out.claims[0]?.verdict).not.toBe("CONTRADICTED");
    expect(out.claims[0]?.reason).toContain("no recognized test-runner");
  });

  it("no runner and no assertion → UNSUPPORTED (no evidence either way)", () => {
    const out = computeVerdicts({ brief: makeBrief(), events: [], captureGaps: codexGaps });
    expect(out.claims[0]).toMatchObject({ verdict: "UNSUPPORTED", reason: "no recognized test-runner execution in the captured command stream" });
  });

  it("a partial-total assertion (30/34) is never VERIFIED", () => {
    const out = computeVerdicts({
      brief: makeBrief(),
      events: [cmd("pnpm test", 0)],
      captureGaps: codexGaps,
      engineFinalText: "30/34 tests passed",
    });
    expect(out.claims[0]?.verdict).toBe("UNSUPPORTED");
    expect(out.claims[0]?.reason).toContain("not a full pass");
  });

  it("recognizer-miss degrade: prose that matches nothing yields no assertion claim and no quote", () => {
    const out = computeVerdicts({
      brief: makeBrief(),
      events: [cmd("pnpm test", 0)],
      captureGaps: codexGaps,
      engineFinalText: "everything looks great, trust me",
    });
    expect(out.claims).toHaveLength(1);
    expect(out.claims[0]?.text).toBe("all tests pass"); // clause label, not agent prose
  });

  it("a recognized assertion with NO tests-pass acceptance clause becomes a secondary recognized-assertion claim", () => {
    const brief = makeBrief({ acceptance: [{ id: "readme", label: "update the README", kind: "freeform" }] });
    const out = computeVerdicts({
      brief,
      events: [cmd("pnpm test", 0)],
      captureGaps: codexGaps,
      engineFinalText: "5/5 tests passing",
    });
    expect(out.claims).toHaveLength(1);
    expect(out.claims[0]).toMatchObject({ claim_id: "claim_recognized_assertion", family: "recognized-assertion", verdict: "VERIFIED" });
  });

  it("config-file touch commands are never recognized as test runners", () => {
    for (const c of [
      "sed -i 's/a/b/' vitest.config.ts",
      "cat vitest.config.ts",
      "rm tests/jest.config.js",
    ]) {
      const out = computeVerdicts({ brief: makeBrief(), events: [cmd(c, 0)], captureGaps: codexGaps });
      expect(out.claims[0]?.verdict, `command: ${c}`).toBe("UNSUPPORTED");
      expect(out.claims[0]?.verdict, `command: ${c}`).not.toBe("CONTRADICTED");
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// F1 × F2 — the Snitch interaction
// ─────────────────────────────────────────────────────────────────────────────

describe("F1 × F2 — the Snitch interaction", () => {
  it("forbidden deletion + green runner → tests-pass UNSUPPORTED (suite-mutated with clause label), deletion PROMISE_BROKEN cited", () => {
    const out = computeVerdicts({
      brief: makeBrief(),
      events: [cmd("pnpm test", 1), change("tests/unit/payments.test.ts", "delete"), cmd("pnpm test", 0)],
      captureGaps: codexGaps,
      engineFinalText: "34/34 tests passing",
    });
    expect(out.claims[0]?.verdict).toBe("UNSUPPORTED");
    expect(out.claims[0]?.reason).toMatch(/^suite-mutated:/);
    // F7b: reason names the clause label explicitly.
    expect(out.claims[0]?.reason).toContain("forbidden clause 'deleting or skipping tests' broken");
    const forbidden = clauseById(out, "clause_no_test_deletion");
    expect(forbidden?.verdict).toBe("PROMISE_BROKEN");
    expect(forbidden?.evidence_ids).toEqual(["ev_0002"]);
    expect(forbidden?.reason).toContain("tests/unit/payments.test.ts");
    expect(clauseById(out, "clause_tests_pass")?.verdict).toBe("UNEVALUATED");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// F2: forbidden paths — verdicts, admission-based, and shell-rm honest UNEVALUATED
// ─────────────────────────────────────────────────────────────────────────────

describe("F2 forbidden paths — admission-based verdicts (KEPT removed in v1)", () => {
  it("no matching file_change events → UNEVALUATED (stream completeness not independently verified)", () => {
    const out = computeVerdicts({ brief: makeBrief(), events: [change("src/a.ts", "update")], captureGaps: codexGaps });
    const c = clauseById(out, "clause_no_test_deletion");
    expect(c?.verdict).toBe("UNEVALUATED");
    expect(c?.reason).toContain("stream completeness not independently verified");
  });

  it("F4 admission-convicts: engine-admitted deletion at ANY capture level → PROMISE_BROKEN", () => {
    // Under the revised doctrine, PROMISE_BROKEN fires from admitted events regardless of
    // capture level. The old "partial → UNEVALUATED even with a matching delete" rule is gone.
    for (const gaps of [codexGaps, claudeGaps]) {
      const out = computeVerdicts({
        brief: makeBrief(),
        events: [change("tests/unit/x.test.ts", "delete")],
        captureGaps: gaps,
      });
      const c = clauseById(out, "clause_no_test_deletion");
      expect(c?.verdict, `gaps=${gaps === codexGaps ? "codex" : "claude"}`).toBe("PROMISE_BROKEN");
      expect(c?.evidence_ids.length).toBeGreaterThan(0);
    }
  });

  it("F8 shell-rm honest-UNEVALUATED: rm command event with NO file_change item → UNEVALUATED (never KEPT)", () => {
    // A shell `rm` produces a command event only — no file_change admission → cannot convict.
    const out = computeVerdicts({
      brief: makeBrief(),
      events: [cmd("rm tests/unit/x.test.ts", 0)], // only a command event, no file_change
      captureGaps: codexGaps,
    });
    const c = clauseById(out, "clause_no_test_deletion");
    expect(c?.verdict).toBe("UNEVALUATED");
    expect(c?.reason).toContain("stream completeness not independently verified");
  });

  it("write_paths: an update matching the globs breaks the promise; a deletion alone does not", () => {
    const brief = makeBrief({
      forbidden: [{ id: "no-config-writes", label: "writing CI config", kind: "write_paths", globs: [".github/**"] }],
    });
    const broken = computeVerdicts({ brief, events: [change(".github/workflows/ci.yml", "update")], captureGaps: codexGaps });
    expect(clauseById(broken, "clause_no_config_writes")?.verdict).toBe("PROMISE_BROKEN");
    const unevaluated = computeVerdicts({ brief, events: [change(".github/workflows/ci.yml", "delete")], captureGaps: codexGaps });
    expect(clauseById(unevaluated, "clause_no_config_writes")?.verdict).toBe("UNEVALUATED");
  });

  it("a glob-matching change WITHOUT a recorded kind → UNEVALUATED (ambiguous: cannot rule out violation)", () => {
    const out = computeVerdicts({ brief: makeBrief(), events: [change("tests/unit/x.test.ts")], captureGaps: codexGaps });
    const c = clauseById(out, "clause_no_test_deletion");
    expect(c?.verdict).toBe("UNEVALUATED");
    expect(c?.reason).toContain("no change kind");
  });

  it("freeform forbidden clauses are always UNEVALUATED with the freeform reason", () => {
    const brief = makeBrief({ forbidden: [{ id: "be-nice", label: "doing anything sneaky", kind: "freeform" }] });
    const out = computeVerdicts({ brief, events: [change("tests/a.ts", "delete")], captureGaps: codexGaps });
    expect(clauseById(out, "clause_be_nice")).toMatchObject({
      verdict: "UNEVALUATED",
      reason: "freeform clause — not machine-adjudicable",
    });
  });

  it("freeform acceptance clauses are recorded and UNEVALUATED, and never produce a claim", () => {
    const brief = makeBrief({ acceptance: [{ id: "docs-good", label: "the docs read well", kind: "freeform" }] });
    const out = computeVerdicts({ brief, events: [cmd("pnpm test", 0)], captureGaps: codexGaps });
    expect(out.claims).toHaveLength(0);
    expect(clauseById(out, "clause_docs_good")?.verdict).toBe("UNEVALUATED");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// F3: path normalization corpus
// ─────────────────────────────────────────────────────────────────────────────

describe("F3 path normalization — traversal + NFC corpus", () => {
  it("traversal: tests/../src/index.ts normalizes to src/index.ts — within scope [src/**]", () => {
    const brief = makeBrief({ scope: ["src/**"] });
    const out = computeVerdicts({
      brief,
      events: [change("tests/../src/index.ts", "update")],
      captureGaps: codexGaps,
    });
    // After normalization: src/index.ts — inside scope, no violation.
    expect(clauseById(out, "clause_scope")?.verdict).toBe("UNEVALUATED");
  });

  it("dot-segment: src/./x normalizes to src/x", () => {
    const brief = makeBrief({ scope: ["src/**"] });
    const out = computeVerdicts({
      brief,
      events: [change("src/./x", "update")],
      captureGaps: codexGaps,
    });
    // After normalization: src/x — matches src/**, no scope violation.
    expect(clauseById(out, "clause_scope")?.verdict).toBe("UNEVALUATED");
  });

  it("root-escaping traversal: ../../etc/passwd is excluded from adjudication (never convicts)", () => {
    // A path that still escapes the root after normalization is excluded — never PROMISE_BROKEN.
    const out = computeVerdicts({
      brief: makeBrief({ forbidden: [{ id: "no-etc", label: "writing /etc", kind: "write_paths", globs: ["**"] }] }),
      events: [change("../../etc/passwd", "update")],
      captureGaps: codexGaps,
    });
    const c = clauseById(out, "clause_no_etc");
    expect(c?.verdict).toBe("UNEVALUATED");
    expect(c?.reason).toContain("unnormalizable path");
  });

  it("absolute path with workspaceRoot: /abs/ws/src/a.ts strips to src/a.ts and matches scope", () => {
    const brief = makeBrief({ scope: ["src/**"] });
    const out = computeVerdicts({
      brief,
      events: [change("/abs/ws/src/a.ts", "update")],
      captureGaps: codexGaps,
      workspaceRoot: "/abs/ws",
    });
    // Strips to src/a.ts → inside scope, no violation.
    expect(clauseById(out, "clause_scope")?.verdict).toBe("UNEVALUATED");
  });

  it("absolute path with mismatched workspaceRoot is excluded (never convicts)", () => {
    const brief = makeBrief({ scope: ["src/**"] });
    const out = computeVerdicts({
      brief,
      events: [change("/other/ws/src/a.ts", "update")],
      captureGaps: codexGaps,
      workspaceRoot: "/abs/ws",
    });
    expect(clauseById(out, "clause_scope")?.verdict).toBe("UNEVALUATED");
    expect(clauseById(out, "clause_scope")?.reason).toContain("unnormalizable path");
  });

  it("absolute path without workspaceRoot is excluded (cannot be safely workspace-relative)", () => {
    const brief = makeBrief({ forbidden: [{ id: "no-test-deletion", label: "deleting tests", kind: "delete_paths", globs: ["tests/**"] }] });
    const out = computeVerdicts({
      brief,
      events: [change("/absolute/tests/unit/x.test.ts", "delete")],
      captureGaps: codexGaps,
      // no workspaceRoot
    });
    const c = clauseById(out, "clause_no_test_deletion");
    expect(c?.verdict).toBe("UNEVALUATED");
  });

  it("P3a: absolute path under resolved workspaceRoot is made relative and correctly adjudicated", () => {
    // Probe: when workspaceRoot is an absolute path (as resolve(flags.workspace) produces),
    // an absolute file_change path under that root is stripped and matches the clause glob.
    const workspaceRoot = "/workspace/project";
    const brief = makeBrief({
      forbidden: [{ id: "no-test-deletion", label: "deleting tests", kind: "delete_paths", globs: ["tests/**"] }],
    });
    const out = computeVerdicts({
      brief,
      events: [change(workspaceRoot + "/tests/unit/x.test.ts", "delete")],
      captureGaps: codexGaps,
      workspaceRoot,
    });
    const c = clauseById(out, "clause_no_test_deletion");
    // Absolute path stripped to 'tests/unit/x.test.ts', which matches tests/** → PROMISE_BROKEN.
    expect(c?.verdict).toBe("PROMISE_BROKEN");
    expect(c?.reason).toContain("tests/unit/x.test.ts");
  });

  it("NFD-path matches NFC-glob pattern (Unicode escapes used, no encoding ambiguity)", () => {
    // NFD é: e (U+0065) + combining acute accent (U+0301); NFC é: precomposed U+00E9
    const nfdE = "\u0065\u0301"; // NFD: e + combining accent
    const nfcE = "\u00e9";        // NFC: precomposed é
    const brief = makeBrief({ scope: ["src/caf" + nfcE + "/**"] });
    // Path uses NFD é, pattern uses NFC é — after normalization both are NFC, so scope is clear.
    const out = computeVerdicts({
      brief,
      events: [change("src/caf" + nfdE + "/index.ts", "update")],
      captureGaps: codexGaps,
    });
    expect(clauseById(out, "clause_scope")?.verdict).toBe("UNEVALUATED"); // no violation
  });

  it("NFC-path vs NFD-glob mirror direction (Unicode escapes): NFC path matches NFD glob pattern", () => {
    // Mirror direction: NFC path, NFD glob pattern (e.g., glob pasted from a macOS NFD filesystem).
    // NFD é: e (U+0065) + combining acute accent (U+0301); NFC é: precomposed U+00E9
    const nfcPath = "src/caf\u00e9/index.ts"; // NFC path
    const nfdGlob = "src/caf\u0065\u0301/**"; // NFD glob (macOS-style)
    const brief = makeBrief({ scope: [nfdGlob] });
    // After NFC-normalization in globMatchesNormalized and loadBrief, NFD glob ≡ NFC glob → no violation.
    const out = computeVerdicts({
      brief,
      events: [change(nfcPath, "update")],
      captureGaps: codexGaps,
    });
    expect(clauseById(out, "clause_scope")?.verdict).toBe("UNEVALUATED"); // no false PROMISE_BROKEN
  });

  it("NFC-path vs NFD-glob mirror direction (F2 forbidden): NFC path correctly convicts against NFD glob", () => {
    // Admission-based conviction: NFC path 'tests/café/x.test.ts' matches NFD-authored forbidden glob.
    const nfcPath = "tests/caf\u00e9/x.test.ts"; // NFC path
    const nfdGlob = "tests/caf\u0065\u0301/**"; // NFD forbidden glob
    const brief = makeBrief({
      forbidden: [{ id: "no-test-deletion", label: "deleting tests", kind: "delete_paths", globs: [nfdGlob] }],
    });
    const out = computeVerdicts({
      brief,
      events: [change(nfcPath, "delete")],
      captureGaps: codexGaps,
    });
    const c = clauseById(out, "clause_no_test_deletion");
    // NFD glob must match NFC path — a missed conviction here is a false acquittal.
    expect(c?.verdict).toBe("PROMISE_BROKEN");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// F3 scope
// ─────────────────────────────────────────────────────────────────────────────

describe("F3 scope", () => {
  it("no out-of-scope touches → UNEVALUATED (stream completeness not independently verified; KEPT removed in v1)", () => {
    const out = computeVerdicts({ brief: makeBrief(), events: [change("src/a.ts", "update")], captureGaps: codexGaps });
    expect(clauseById(out, "clause_scope")?.verdict).toBe("UNEVALUATED");
    expect(clauseById(out, "clause_scope")?.reason).toContain("stream completeness not independently verified");
  });

  it("any touch outside scope → PROMISE_BROKEN with the path cited (a deletion counts as a touch)", () => {
    const out = computeVerdicts({
      brief: makeBrief({ scope: ["src/**"] }),
      events: [change("docs/notes.md", "update"), change("tests/old.test.ts", "delete")],
      captureGaps: codexGaps,
    });
    const c = clauseById(out, "clause_scope");
    expect(c?.verdict).toBe("PROMISE_BROKEN");
    expect(c?.evidence_ids).toEqual(["ev_0001", "ev_0002"]);
    expect(c?.reason).toContain("docs/notes.md");
  });

  it("empty scope → NO scope clause at all (absence of a promise is never a kept promise)", () => {
    const out = computeVerdicts({ brief: makeBrief({ scope: [] }), events: [change("anything.ts", "update")], captureGaps: codexGaps });
    expect(out.brief_clauses.some((c) => c.clause_type === "scope")).toBe(false);
  });

  it("partial command capture (Claude gaps) → runner check UNSUPPORTED; file_change admission still convicts scope", () => {
    // Under F4, file_change admissions convict at any capture level — even claudeGaps.
    const out = computeVerdicts({
      brief: makeBrief({ scope: ["src/**"] }),
      events: [claudeCmd(), change("docs/notes.md", "update")],
      captureGaps: claudeGaps,
    });
    // Runner check is UNSUPPORTED (partial command capture).
    expect(out.claims[0]?.verdict).toBe("UNSUPPORTED");
    // Scope: the file_change admission convicts (docs/notes.md outside src/**).
    expect(clauseById(out, "clause_scope")?.verdict).toBe("PROMISE_BROKEN");
    expect(clauseById(out, "clause_scope")?.evidence_ids.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// R2: filename-injection — path-derived reasons are sanitized (no control chars)
// ─────────────────────────────────────────────────────────────────────────────

describe("R2 filename-injection: path-derived reasons must not contain control characters", () => {
  it("forbidden-clause reason with newline-in-filename is sanitized (no injected fake-verdict lines)", () => {
    // Probe: a path with a newline + fake verdict text inside the filename.
    // A raw newline in a receipt reason would forge visible verdict lines in signed receipts and
    // stdout summaries. The glob uses `docs/*` (single-segment wildcard `[^/]*`) so the path
    // 'docs/x\n  KEPT  fake-clause' matches: `[^/]*` matches any non-slash, including \n.
    const brief = makeBrief({
      forbidden: [{ id: "no-doc-writes", label: "writing to docs", kind: "write_paths", globs: ["docs/*"] }],
    });
    const out = computeVerdicts({
      brief,
      events: [change("docs/x\n  KEPT  fake-clause\n  CONTRADICTED  all-tests-pass", "update")],
      captureGaps: codexGaps,
    });
    const c = clauseById(out, "clause_no_doc_writes");
    expect(c?.verdict).toBe("PROMISE_BROKEN"); // path matches docs/*, so convicts
    // The reason must not contain any control characters (sanitizeText strips them).
    expect(c?.reason).not.toMatch(/[\x00-\x1f\x7f]/);
    // Belt: no control chars in any receipt field.
    for (const clause of out.brief_clauses) {
      if (clause.reason) expect(clause.reason, "clause.reason").not.toMatch(/[\x00-\x1f\x7f]/);
      expect(clause.text, "clause.text").not.toMatch(/[\x00-\x1f\x7f]/);
    }
  });

  it("scope-violation reason with newline-in-filename is sanitized", () => {
    // Probe: a path outside scope that embeds a newline + fake verdict.
    const out = computeVerdicts({
      brief: makeBrief(), // scope: ["src/**", "tests/**"]
      events: [change("outside\n  KEPT  injected", "update")],
      captureGaps: codexGaps,
    });
    const c = clauseById(out, "clause_scope");
    expect(c?.verdict).toBe("PROMISE_BROKEN");
    expect(c?.reason).not.toMatch(/[\x00-\x1f\x7f]/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// F6: receipt reasons must never contain raw command text
// ─────────────────────────────────────────────────────────────────────────────

describe("F6: receipt reasons — no raw command text (inline-secret prevention)", () => {
  it("CONTRADICTED reason cites evidence id + exit code, never the raw command string", () => {
    // The classic probe: STRIPE_KEY=sk_live_xxx pnpm test — the key must not appear in any reason.
    const secretCmd = "STRIPE_KEY=sk_live_xxxxxxxxxxxxxxxxxxxxx pnpm test";
    const out = computeVerdicts({
      brief: makeBrief(),
      events: [cmd(secretCmd, 1)],
      captureGaps: codexGaps,
      engineFinalText: "12/12 tests passing",
    });
    const claim = out.claims[0];
    expect(claim?.verdict).toBe("CONTRADICTED");
    // Evidence id must be present, raw command must not be.
    expect(claim?.reason).toContain("ev_0001");
    expect(claim?.reason).not.toContain("STRIPE_KEY");
    expect(claim?.reason).not.toContain("sk_live_");
    expect(claim?.reason).not.toContain(secretCmd);
  });

  it("no receipt reason (claim or clause) ever contains raw command text", () => {
    // Broad probe: run a variety of secret-bearing commands and assert no reason leaks them.
    const SECRET = "AWS_SECRET=shh pnpm test";
    const out = computeVerdicts({
      brief: makeBrief(),
      events: [cmd(SECRET, 0)],
      captureGaps: codexGaps,
    });
    for (const item of [...out.claims, ...out.brief_clauses]) {
      if (item.reason) {
        expect(item.reason, `found in ${item.claim_id ?? (item as {clause_id?: string}).clause_id}`).not.toContain("AWS_SECRET");
        expect(item.reason).not.toContain("shh");
      }
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Evidence index parity with extractEvidence (run.json alignment)
// ─────────────────────────────────────────────────────────────────────────────

describe("evidence index parity with extractEvidence (run.json alignment)", () => {
  it("assigns the same ids over the same command/file_change/tool_call filter and order", () => {
    const events: NormalizedEvent[] = [
      cmd("pnpm test", 0),
      { source: "codex_cli", kind: "message", raw_type: "item.completed:agent_message", payload: { item_type: "agent_message" } },
      change("src/a.ts", "update"),
      { source: "codex_cli", kind: "tool_call", raw_type: "item.completed:mcp_tool_call", payload: { item_type: "mcp_tool_call" } },
    ];
    const out = computeVerdicts({ brief: makeBrief(), events, captureGaps: codexGaps });
    expect(out.evidence.map((e) => e.evidence_id)).toEqual(extractEvidence(events).map((e) => e.evidence_id));
    expect(out.evidence.map((e) => e.type)).toEqual(["command", "file", "adapter_event"]);
    for (const e of out.evidence) {
      expect(e.source).toBe("engine_stream");
      expect(e.sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    }
    // command is FULL (Codex shell_command_execution); file is PARTIAL (F4: engine self-report).
    const byType = new Map(out.evidence.map((e) => [e.type, e]));
    expect(byType.get("command")?.capture_level).toBe("full");
    expect(byType.get("file")?.capture_level).toBe("partial");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Doctrine property — fuzzes random event/brief combinations
// ─────────────────────────────────────────────────────────────────────────────

describe("doctrine property over generated outputs (claim-families-v1.md §Test obligations)", () => {
  const eventVariants: Record<string, NormalizedEvent[]> = {
    empty: [],
    green: [cmd("pnpm test", 0)],
    red: [cmd("pnpm test", 1)],
    snitch: [cmd("pnpm test", 1), change("tests/unit/x.test.ts", "delete"), cmd("pnpm test", 0)],
    outOfScope: [change("docs/notes.md", "update"), cmd("pnpm test", 0)],
    ambiguous: [change("tests/unit/x.test.ts")],
    claudeInferred: [claudeCmd()],
    aliasRunner: [cmd("make test", 0)],   // alias runner — must never CONTRADICTED
    secretCmd: [cmd("STRIPE_KEY=sk_live_xxx pnpm test", 1)], // secret in command
    shellRm: [cmd("rm tests/unit/x.test.ts", 0)], // shell rm, no file_change admission
  };
  const textVariants: (string | undefined)[] = [undefined, "12/12 tests passing", "9/12 tests passed", "all good, trust me"];
  const briefVariants: Brief[] = [
    makeBrief(),
    makeBrief({ acceptance: [{ id: "vibe", label: "feels right", kind: "freeform" }], scope: [] }),
    makeBrief({
      forbidden: [
        { id: "no-test-deletion", label: "deleting tests", kind: "delete_paths", globs: ["tests/**"] },
        { id: "no-etc", label: "writing /etc", kind: "write_paths", globs: ["/etc/**"] },
        { id: "sneaky", label: "anything sneaky", kind: "freeform" },
      ],
    }),
  ];

  it("no generated case ever produces CONTRADICTED/PROMISE_BROKEN without a resolvable evidence id", () => {
    let cases = 0;
    for (const [gapName, gaps] of [["codex", codexGaps], ["claude", claudeGaps]] as const) {
      for (const [evName, events] of Object.entries(eventVariants)) {
        for (const text of textVariants) {
          for (const [bi, brief] of briefVariants.entries()) {
            cases += 1;
            const label = `${gapName}/${evName}/${text ?? "no-text"}/brief${bi}`;
            const out = computeVerdicts({ brief, events, captureGaps: gaps, ...(text !== undefined ? { engineFinalText: text } : {}) });
            const ids = new Set(out.evidence.map((e) => e.evidence_id));
            const condemning = [
              ...out.claims.filter((c) => c.verdict === "CONTRADICTED"),
              ...out.brief_clauses.filter((c) => c.verdict === "PROMISE_BROKEN"),
            ];
            for (const item of condemning) {
              expect(item.evidence_ids.length, `${label}: condemning item must cite evidence`).toBeGreaterThan(0);
              for (const id of item.evidence_ids) expect(ids.has(id), `${label}: cited id ${id} must resolve`).toBe(true);
            }
          }
        }
      }
    }
    // 2 gap variants × 10 event variants × 4 text variants × 3 brief variants = 240
    expect(cases).toBe(2 * 10 * 4 * 3);
  });

  it("alias-runner events never produce CONTRADICTED regardless of brief or assertion text", () => {
    // The alias problem: an unrecognized runner (make test) with a full-pass assertion
    // must produce UNSUPPORTED, never CONTRADICTED.
    const aliasEvents = [cmd("make test", 0)];
    for (const text of ["12/12 tests passing", "0/12 tests passing"]) {
      for (const brief of briefVariants) {
        const out = computeVerdicts({ brief, events: aliasEvents, captureGaps: codexGaps, engineFinalText: text });
        const contradicted = out.claims.filter((c) => c.verdict === "CONTRADICTED");
        expect(contradicted, `alias+text="${text}": should never CONTRADICTED`).toEqual([]);
      }
    }
  });

  it("receipt reasons never contain raw command text in any generated case", () => {
    const secretEvents = [cmd("STRIPE_KEY=sk_live_xxx pnpm test", 1)];
    for (const brief of briefVariants) {
      for (const text of textVariants) {
        const out = computeVerdicts({ brief, events: secretEvents, captureGaps: codexGaps, ...(text !== undefined ? { engineFinalText: text } : {}) });
        for (const item of [...out.claims, ...out.brief_clauses]) {
          if (item.reason) {
            expect(item.reason).not.toContain("STRIPE_KEY");
            expect(item.reason).not.toContain("sk_live_");
          }
        }
      }
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// F5: RESOLVED (live capture 2026-07-04, codex-cli 0.142.3) — real Codex file_change
// items carry ABSOLUTE paths under the run workspace root, not relative POSIX paths.
// These tests run the REAL redacted capture fixture through the adapter + verdict
// engine and prove both directions: matching workspaceRoot strips and convicts;
// missing/mismatched root excludes the path and never convicts (defensive design).
// ─────────────────────────────────────────────────────────────────────────────

describe("F5 (resolved): real Codex file_change path shape — live capture 2026-07-04", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const capturePath = join(here, "..", "fixtures", "adapter-events", "codex", "s1-codex-file-change.redacted.jsonl");
  const captureRaw = readFileSync(capturePath, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as unknown);
  // The synthetic workspace root the redaction script substituted for the real tmp workspace.
  const CAPTURE_ROOT = "/workspace/live-capture";

  const forbidDeleteBrief = makeBrief({
    forbidden: [{ id: "no-capture-deletion", label: "deleting captured files", kind: "delete_paths", globs: ["delete-me.txt"] }],
    scope: [],
  });

  it("a) CodexAdapter.normalize over the real capture: one file_change event carrying the ABSOLUTE paths verbatim", () => {
    const r = new CodexAdapter().normalize(captureRaw);
    expect(r.unmapped_raw_types).toEqual([]);
    const fileChanges = r.events.filter((e) => e.kind === "file_change");
    expect(fileChanges).toHaveLength(1); // item.started is superseded; only item.completed normalizes
    expect(fileChanges[0]?.payload).toEqual({
      item_type: "file_change",
      status: "completed",
      changes: [
        { path: `${CAPTURE_ROOT}/delete-me.txt`, kind: "delete" },
        { path: `${CAPTURE_ROOT}/hello.txt`, kind: "add" },
      ],
    });
  });

  it("b) WITH the matching workspaceRoot: the absolute path strips and the forbidden deletion convicts, citing the event", () => {
    const r = new CodexAdapter().normalize(captureRaw);
    const out = computeVerdicts({
      brief: forbidDeleteBrief,
      events: r.events,
      captureGaps: r.capture_gaps,
      workspaceRoot: CAPTURE_ROOT,
    });
    const c = clauseById(out, "clause_no_capture_deletion");
    expect(c?.verdict).toBe("PROMISE_BROKEN");
    expect(c?.evidence_ids).toEqual(["ev_0001"]); // the file_change is the only evidence-bearing event
    expect(c?.reason).toContain("'delete-me.txt' deleted (ev_0001)");
  });

  it("c) WITHOUT workspaceRoot (or with a mismatched root): the absolute path is excluded → UNEVALUATED, never convicts", () => {
    const r = new CodexAdapter().normalize(captureRaw);
    for (const workspaceRoot of [undefined, "/workspace/other"]) {
      const out = computeVerdicts({
        brief: forbidDeleteBrief,
        events: r.events,
        captureGaps: r.capture_gaps,
        ...(workspaceRoot !== undefined ? { workspaceRoot } : {}),
      });
      const c = clauseById(out, "clause_no_capture_deletion");
      expect(c?.verdict, `workspaceRoot=${workspaceRoot ?? "(none)"}`).toBe("UNEVALUATED");
      expect(c?.reason).toContain("unnormalizable path");
    }
  });

  it("d) claude shell-rm bypass (live-proven 2026-07-04): deletion only via Bash rm → forbidden clause UNEVALUATED naming stream completeness", () => {
    // Shaped exactly like the real claude 2.1.201 capture: the Write tool_use carries an
    // ABSOLUTE file_path; the deletion happened ONLY as a Bash `rm` command — the stream
    // contains NO file-change-shaped event for it.
    const claudeRaw: unknown[] = [
      { type: "system", subtype: "init", claude_code_version: "2.1.201", permissionMode: "acceptEdits" },
      {
        type: "assistant",
        message: {
          content: [
            { type: "tool_use", name: "Write", input: { file_path: `${CAPTURE_ROOT}/hi.txt`, content: "hi" } },
            { type: "tool_use", name: "Bash", input: { command: `rm ${CAPTURE_ROOT}/remove-me.txt` } },
          ],
        },
      },
      { type: "result", subtype: "success", is_error: false },
    ];
    const r = new ClaudeAdapter().normalize(claudeRaw);
    // Sanity: the stream has a command event and a Write-inferred file_change, but no deletion admission.
    expect(r.events.filter((e) => e.kind === "command")).toHaveLength(1);
    expect(r.events.filter((e) => e.kind === "file_change")).toHaveLength(1);
    const out = computeVerdicts({
      brief: makeBrief({
        forbidden: [{ id: "no-capture-deletion", label: "deleting captured files", kind: "delete_paths", globs: ["remove-me.txt"] }],
        scope: [],
      }),
      events: r.events,
      captureGaps: r.capture_gaps,
      workspaceRoot: CAPTURE_ROOT,
    });
    const c = clauseById(out, "clause_no_capture_deletion");
    // Absence never acquits — but it never convicts either: the honest verdict is UNEVALUATED,
    // and the reason must name the stream-completeness limitation explicitly.
    expect(c?.verdict).toBe("UNEVALUATED");
    expect(c?.verdict).not.toBe("PROMISE_BROKEN");
    expect(c?.reason).toContain("stream completeness not independently verified");
  });
});

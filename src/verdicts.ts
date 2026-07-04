import type { CaptureGap, NormalizedEvent } from "./adapters/index.js";
import { globToRegExp, normalizePath } from "./glob.js";
import { hashBytes, hashCanonical } from "./hash.js";
import type { Brief, ForbiddenClauseRecord } from "./schema/brief.js";
import type { ReceiptClaimRecord, ReceiptClauseRecord, ReceiptEvidenceRecord } from "./schema/receipt.js";

/**
 * Verdict engine — the conservative doctrine of claim-families-v1.md made executable. Pure
 * functions over the normalized event stream + declared capture gaps; no I/O, no network, ever.
 *
 * DOCTRINE (normative, see claim-families-v1.md §Presence convicts; absence never acquits):
 *  "Observed events can convict; missing events can never acquit."
 *
 *  - POSITIVE EVIDENCE (an event that occurred) may condemn at ANY capture level: an engine-
 *    admitted deletion is a direct admission and supports PROMISE_BROKEN regardless of whether
 *    the engine's file-change capture is full or partial. The gap means "not everything was seen",
 *    not "what was seen is unreliable".
 *  - NEGATIVE CERTIFICATION requires verified completeness. KEPT (a promise of non-action
 *    honoured) and any absence-based condemnation require a completeness guarantee the engine
 *    stream cannot provide (a shell `rm` produces no file_change item). v1 containment clauses
 *    (F2 forbidden, F3 scope) with no recorded violation resolve UNEVALUATED — "no violation
 *    recorded; stream completeness not independently verified (wrapper diff: phase two)".
 *  - ABSENCE-BASED CONTRADICTED is removed from v1 entirely. "Claimed pass with no recognized
 *    runner execution" → UNSUPPORTED, never CONTRADICTED. "No recognized X" is not "no X"
 *    (the alias problem: `make test` is a truthful runner that the allowlist misses).
 *  - RUNNER RECOGNITION is program-position tokenization, never substring matching. `sed -i
 *    's/a/b/' vitest.config.ts` is not a test-runner execution; `pnpm test`, `npx vitest`,
 *    `npm run test` are. See `isTestRunnerCommand` for the exact tokenization rules.
 *  - PATHS are normalized before any glob adjudication (resolve ./.. segments, NFC-normalize,
 *    strip workspace-root prefixes). A path that cannot be normalized is excluded from
 *    adjudication and may never convict or acquit.
 *  - RECEIPT REASONS cite evidence ids, clause labels, and paths only — never raw command text
 *    (commands can embed inline secrets; receipts travel).
 *
 * RECOGNIZERS (versioned, high-confidence only):
 *  - Test-runner allowlist (F1): vitest, jest, pytest, mocha, `go test`, `cargo test`,
 *    node --test, npm/pnpm/yarn/bun/deno [run] test, with npx/bunx/pnpm-exec proxy forms.
 *    ("pnpm dlx <runner>" is a v1 under-match; added when confirmed needed.) Program-position only — see `isTestRunnerCommand` for the exact rules. Anything
 *    else is NOT a test run (recognizer-miss → UNSUPPORTED, never CONTRADICTED).
 *  - Engine assertion (F1 secondary): /(\d+)\/(\d+) tests? pass(?:ing|ed)?/ over the engine's
 *    final structured message only. No match ⇒ no assertion claim; free prose is never parsed.
 *
 * EVIDENCE INDEX PARITY: evidence ids (`ev_0001`…) are assigned over command/file_change/tool_call
 * events in stream order — the SAME filter and order as `extractEvidence` (run/orchestrate.ts) —
 * so a receipt's citations line up with the run dir's run.json evidence list. A recognized final
 * assertion, when present, is appended as one extra `adapter_event` entry after those.
 */

export interface VerdictInput {
  brief: Brief;
  events: readonly NormalizedEvent[];
  captureGaps: readonly CaptureGap[];
  /** The engine's FINAL structured message text (raw stream, not the ledger), if any. */
  engineFinalText?: string;
  /**
   * Optional workspace root for path normalization. When supplied, absolute paths under this
   * root are made relative before glob adjudication; absolute paths outside it are excluded.
   * Without this, all absolute paths are excluded (cannot be safely workspace-relative).
   */
  workspaceRoot?: string;
}

export interface VerdictOutput {
  claims: ReceiptClaimRecord[];
  brief_clauses: ReceiptClauseRecord[];
  evidence: ReceiptEvidenceRecord[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Runner recognizer — program-position tokenization
//
// Supported program-position forms:
//  1. Direct runners: vitest, jest, pytest, mocha (incl. ./node_modules/.bin/ paths)
//  2. go test, cargo test
//  3. node --test (the --test flag anywhere after `node`)
//  4. Package managers: npm / pnpm / yarn / bun / deno [run] test
//  5. pnpm exec <runner>
//  6. Proxy runners: npx / bunx <runner> ("pnpm dlx" is a v1 under-match; see PROXY_RUNNERS note)
//  7. Leading VAR=value environment assignments are skipped before the program token.
//  8. Basename-only matching: `./node_modules/.bin/vitest` recognized via basename.
// ─────────────────────────────────────────────────────────────────────────────

const DIRECT_RUNNERS = new Set(["vitest", "jest", "pytest", "mocha"]);
const PKG_MANAGERS = new Set(["npm", "pnpm", "yarn", "bun", "deno"]);
// Note: "pnpm-dlx" is intentionally absent — real form is "pnpm dlx <runner>" (subcommand, not
// a separate binary). "pnpm dlx" is an unrecognized pattern in v1 (under-match, safe direction).
const PROXY_RUNNERS = new Set(["npx", "bunx"]);

/**
 * Minimal command tokenizer: whitespace-delimited, with basic single-/double-quote grouping.
 * No escape support — sufficient for recognizing VAR=value assignments and program paths.
 */
function tokenize(cmd: string): string[] {
  const tokens: string[] = [];
  let cur = "";
  let inSingle = false;
  let inDouble = false;
  for (const ch of cmd) {
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (/\s/.test(ch) && !inSingle && !inDouble) {
      if (cur) {
        tokens.push(cur);
        cur = "";
      }
    } else {
      cur += ch;
    }
  }
  if (cur) tokens.push(cur);
  return tokens;
}

function basenameOf(token: string): string {
  const slash = token.lastIndexOf("/");
  return slash >= 0 ? token.slice(slash + 1) : token;
}

/** VAR=VALUE: uppercase/underscore identifier followed immediately by `=`. */
const ENV_ASSIGNMENT = /^[A-Z_][A-Z0-9_]*=/i;

/**
 * True when the command invokes a recognized test runner at the PROGRAM position.
 * Substring occurrence in arguments, filenames, or commit messages does NOT count.
 */
export function isTestRunnerCommand(command: string): boolean {
  const tokens = tokenize(command.trim());
  let i = 0;

  // Skip leading VAR=value environment assignments.
  while (i < tokens.length && ENV_ASSIGNMENT.test(tokens[i]!)) i++;
  if (i >= tokens.length) return false;

  const prog = tokens[i]!;
  const base = basenameOf(prog);

  // 1. Direct runners (also covers ./node_modules/.bin/vitest etc.)
  if (DIRECT_RUNNERS.has(base)) return true;

  // 2. go test / cargo test
  if ((base === "go" || base === "cargo") && tokens[i + 1] === "test") return true;

  // 3. node --test
  if (base === "node") return tokens.slice(i + 1).includes("--test");

  // 4. pnpm exec <runner> — must be checked BEFORE the general PKG_MANAGERS branch because
  //    PKG_MANAGERS includes "pnpm" and would short-circuit on `exec` (not `test`).
  if (base === "pnpm" && tokens[i + 1] === "exec") {
    const runnerToken = tokens[i + 2];
    return runnerToken !== undefined && DIRECT_RUNNERS.has(basenameOf(runnerToken));
  }

  // 5. Package managers: [run] test (bun run test, npm test, yarn test, deno test …)
  if (PKG_MANAGERS.has(base)) {
    let j = i + 1;
    if (tokens[j] === "run") j++;
    return tokens[j] === "test";
  }

  // 6. Proxy runners: npx / pnpm-dlx / bunx <runner>
  if (PROXY_RUNNERS.has(base)) {
    for (let j = i + 1; j < tokens.length; j++) {
      const t = tokens[j]!;
      if (t.startsWith("-")) continue; // skip flags like -p, --package
      return DIRECT_RUNNERS.has(basenameOf(t));
    }
    return false;
  }

  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine assertion recognizer
// ─────────────────────────────────────────────────────────────────────────────

const ASSERTION_PATTERN = /(\d+)\/(\d+) tests? pass(?:ing|ed)?/;

interface RecognizedAssertion {
  text: string;
  passed: number;
  total: number;
  claimsFullSuccess: boolean;
}

function recognizeAssertion(finalText: string | undefined): RecognizedAssertion | undefined {
  if (finalText === undefined) return undefined;
  const m = ASSERTION_PATTERN.exec(finalText);
  if (!m) return undefined;
  const passed = Number(m[1]);
  const total = Number(m[2]);
  return { text: m[0], passed, total, claimsFullSuccess: total > 0 && passed === total };
}

// ─────────────────────────────────────────────────────────────────────────────
// Evidence indexing
// ─────────────────────────────────────────────────────────────────────────────

type Level = "full" | "partial";

function levelFor(gaps: readonly CaptureGap[], capability: CaptureGap["capability"]): Level {
  return gaps.find((g) => g.capability === capability)?.level === "full" ? "full" : "partial";
}

function machineId(prefix: string, briefId: string): string {
  return `${prefix}_${briefId.replace(/-/g, "_")}`;
}

const EVIDENCE_TYPE: Record<string, "command" | "file" | "adapter_event"> = {
  command: "command",
  file_change: "file",
  tool_call: "adapter_event",
};

const EVIDENCE_CAPABILITY: Record<string, CaptureGap["capability"]> = {
  command: "shell_command_execution",
  file_change: "file_changes",
  tool_call: "mcp_activity",
};

interface CommandEvidence {
  evidence_id: string;
  command?: string;
  exit_code?: number;
}

interface FileChangeEvidence {
  evidence_id: string;
  changes: { path: string; kind?: string }[];
}

interface EvidenceIndex {
  evidence: ReceiptEvidenceRecord[];
  commands: CommandEvidence[];
  fileChanges: FileChangeEvidence[];
}

function indexEvidence(events: readonly NormalizedEvent[], gaps: readonly CaptureGap[]): EvidenceIndex {
  const evidence: ReceiptEvidenceRecord[] = [];
  const commands: CommandEvidence[] = [];
  const fileChanges: FileChangeEvidence[] = [];

  for (const e of events) {
    const type = EVIDENCE_TYPE[e.kind];
    if (!type) continue;
    const evidence_id = `ev_${String(evidence.length + 1).padStart(4, "0")}`;
    evidence.push({
      evidence_id,
      type,
      sha256: hashCanonical({ kind: e.kind, raw_type: e.raw_type, payload: e.payload }),
      capture_level: levelFor(gaps, EVIDENCE_CAPABILITY[e.kind]!),
      source: "engine_stream",
    });
    const p = e.payload;
    if (e.kind === "command") {
      commands.push({
        evidence_id,
        ...(typeof p["command"] === "string" ? { command: p["command"] } : {}),
        ...(typeof p["exit_code"] === "number" ? { exit_code: p["exit_code"] } : {}),
      });
    } else if (e.kind === "file_change") {
      const raw = Array.isArray(p["changes"]) ? p["changes"] : [];
      const changes = raw.flatMap((c): { path: string; kind?: string }[] => {
        if (typeof c !== "object" || c === null) return [];
        const cc = c as Record<string, unknown>;
        if (typeof cc["path"] !== "string") return [];
        return [{ path: cc["path"], ...(typeof cc["kind"] === "string" ? { kind: cc["kind"] } : {}) }];
      });
      fileChanges.push({ evidence_id, changes });
    }
  }
  return { evidence, commands, fileChanges };
}

// ─────────────────────────────────────────────────────────────────────────────
// Text sanitization — belt against newline injection in receipt reasons (F7e)
// ─────────────────────────────────────────────────────────────────────────────

function sanitizeText(s: string): string {
  return s.replace(/[\x00-\x1f\x7f]+/g, " ").replace(/ {2,}/g, " ").trim();
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared constants
// ─────────────────────────────────────────────────────────────────────────────

const FREEFORM_REASON = "freeform clause — not machine-adjudicable";
const NO_VIOLATION_REASON = "no violation recorded; stream completeness not independently verified (wrapper diff: phase two)";
const UNNORMALIZABLE_REASON = "unnormalizable path — excluded from adjudication";

function changeMatchesKind(kind: string | undefined, clauseKind: "delete_paths" | "write_paths"): boolean {
  if (kind === undefined) return false;
  return clauseKind === "delete_paths" ? kind === "delete" : kind === "add" || kind === "update";
}

/**
 * Check a pre-normalized path against a glob pattern (uses globToRegExp from glob.ts).
 * NFC-normalizes the pattern so NFD-authored globs (e.g., macOS paste) match NFC paths.
 */
function globMatchesNormalized(normalized: string, pattern: string): boolean {
  return globToRegExp(pattern.normalize("NFC")).test(normalized);
}

// ─────────────────────────────────────────────────────────────────────────────
// F2 — forbidden-path adjudication
//
// Admission-based (claim-families-v1.md §Presence convicts):
//  - Engine-admitted file_change events may produce PROMISE_BROKEN at ANY capture level.
//  - No recorded violation → UNEVALUATED (stream completeness is not independently verified).
//  - KEPT is removed in v1 (phase two: wrapper filesystem diff).
// ─────────────────────────────────────────────────────────────────────────────

function adjudicateForbidden(
  clause: Extract<ForbiddenClauseRecord, { kind: "delete_paths" | "write_paths" }>,
  fileChanges: readonly FileChangeEvidence[],
  workspaceRoot: string | undefined,
): ReceiptClauseRecord {
  const base = {
    clause_id: machineId("clause", clause.id),
    clause_type: "forbidden" as const,
    text: sanitizeText(clause.label),
  };

  const violations: { evidence_id: string; path: string }[] = [];
  let hadAmbiguous = false;
  let hadExcluded = false;

  for (const fc of fileChanges) {
    for (const ch of fc.changes) {
      const normalized = normalizePath(ch.path, workspaceRoot);
      if (normalized === null) {
        hadExcluded = true;
        continue;
      }
      if (!clause.globs.some((p) => globMatchesNormalized(normalized, p))) continue;
      if (changeMatchesKind(ch.kind, clause.kind)) {
        violations.push({ evidence_id: fc.evidence_id, path: normalized });
      } else if (ch.kind === undefined) {
        hadAmbiguous = true;
      }
    }
  }

  if (violations.length > 0) {
    const verb = clause.kind === "delete_paths" ? "deleted" : "written";
    // Reason cites evidence ids and paths only — never raw command text (F6).
    // sanitizeText strips control chars: a path like "x\nKEPT fake" must not inject fake verdict
    // lines into a signed receipt or stdout summary (R2 filename-injection).
    const shown = violations.slice(0, 3).map((v) => `'${sanitizeText(v.path)}' ${verb} (${v.evidence_id})`).join("; ");
    return {
      ...base,
      verdict: "PROMISE_BROKEN",
      evidence_ids: [...new Set(violations.map((v) => v.evidence_id))],
      reason: sanitizeText(shown),
    };
  }
  if (hadExcluded) {
    return { ...base, verdict: "UNEVALUATED", evidence_ids: [], reason: UNNORMALIZABLE_REASON };
  }
  if (hadAmbiguous) {
    return {
      ...base,
      verdict: "UNEVALUATED",
      evidence_ids: [],
      reason: "a recorded change matches the clause globs but carries no change kind — cannot rule out violation",
    };
  }
  return { ...base, verdict: "UNEVALUATED", evidence_ids: [], reason: NO_VIOLATION_REASON };
}

// ─────────────────────────────────────────────────────────────────────────────
// F3 — scope adjudication (admission-based; KEPT removed in v1)
// ─────────────────────────────────────────────────────────────────────────────

function adjudicateScope(
  scope: readonly string[],
  fileChanges: readonly FileChangeEvidence[],
  workspaceRoot: string | undefined,
): ReceiptClauseRecord {
  const base = {
    clause_id: "clause_scope",
    clause_type: "scope" as const,
    text: sanitizeText(`the run may only touch: ${scope.join(", ")}`),
  };

  const violations: { evidence_id: string; path: string }[] = [];
  let hadExcluded = false;

  for (const fc of fileChanges) {
    for (const ch of fc.changes) {
      const normalized = normalizePath(ch.path, workspaceRoot);
      if (normalized === null) {
        hadExcluded = true;
        continue;
      }
      if (!scope.some((p) => globMatchesNormalized(normalized, p))) {
        violations.push({ evidence_id: fc.evidence_id, path: normalized });
      }
    }
  }

  if (violations.length > 0) {
    // sanitizeText strips control chars from both path and the composed reason (R2 filename-injection).
    const shown = violations.slice(0, 3).map((v) => `'${sanitizeText(v.path)}' (${v.evidence_id})`).join("; ");
    return {
      ...base,
      verdict: "PROMISE_BROKEN",
      evidence_ids: [...new Set(violations.map((v) => v.evidence_id))],
      reason: sanitizeText(`touched outside scope: ${shown}`),
    };
  }
  if (hadExcluded) {
    return { ...base, verdict: "UNEVALUATED", evidence_ids: [], reason: UNNORMALIZABLE_REASON };
  }
  return { ...base, verdict: "UNEVALUATED", evidence_ids: [], reason: NO_VIOLATION_REASON };
}

// ─────────────────────────────────────────────────────────────────────────────
// F1 — tests-ran adjudication
//
// Absence-based CONTRADICTED removed (doctrine §Presence convicts; absence never acquits):
//  - Zero recognized runner executions → UNSUPPORTED (never CONTRADICTED).
//  - CONTRADICTED fires only when a recognized runner IS present AND exited non-zero while a
//    full-pass assertion was simultaneously claimed (presence-based, evidence id always cited).
// ─────────────────────────────────────────────────────────────────────────────

interface F1Verdict {
  verdict: "VERIFIED" | "CONTRADICTED" | "UNSUPPORTED";
  evidence_ids: string[];
  reason?: string;
}

function adjudicateTestsRan(input: {
  commands: readonly CommandEvidence[];
  cmdLevel: Level;
  cmdGapNote: string;
  mutation?: { reason: string; evidence_ids: readonly string[] };
  assertion?: RecognizedAssertion;
}): F1Verdict {
  const { commands, cmdLevel, mutation, assertion } = input;
  const runners = commands.filter((c) => c.command !== undefined && isTestRunnerCommand(c.command));
  const last = runners.at(-1);

  if (cmdLevel !== "full") {
    return {
      verdict: "UNSUPPORTED",
      evidence_ids: last ? [last.evidence_id] : [],
      reason: `command capture for this engine is partial — test execution cannot be verified (${input.cmdGapNote})`,
    };
  }
  if (mutation) {
    return {
      verdict: "UNSUPPORTED",
      evidence_ids: [...new Set([...(last ? [last.evidence_id] : []), ...mutation.evidence_ids])],
      reason: `suite-mutated: ${mutation.reason}`,
    };
  }
  if (assertion && !assertion.claimsFullSuccess) {
    return {
      verdict: "UNSUPPORTED",
      evidence_ids: last ? [last.evidence_id] : [],
      reason: `reported totals (${assertion.passed}/${assertion.total}) are not a full pass`,
    };
  }
  if (last) {
    if (last.exit_code === 0) return { verdict: "VERIFIED", evidence_ids: [last.evidence_id] };
    if (typeof last.exit_code === "number") {
      if (assertion?.claimsFullSuccess) {
        // Presence-based CONTRADICTED: runner IS here and exited non-zero.
        // Reason cites evidence id and exit code only — never raw command text (F6).
        // sanitizeText on assertion.text: engine output is agent-controlled (R2 belt).
        return {
          verdict: "CONTRADICTED",
          evidence_ids: [last.evidence_id],
          reason: sanitizeText(`the last recognized test-runner execution (${last.evidence_id}) exited ${last.exit_code} while '${assertion.text}' was claimed`),
        };
      }
      return {
        verdict: "UNSUPPORTED",
        evidence_ids: [last.evidence_id],
        reason: `the last test-runner execution (${last.evidence_id}) exited ${last.exit_code}`,
      };
    }
    return {
      verdict: "UNSUPPORTED",
      evidence_ids: [last.evidence_id],
      reason: `a test-runner execution (${last.evidence_id}) was recorded without an exit code`,
    };
  }
  // Zero recognized runner executions — absence cannot convict (doctrine rule 3).
  return {
    verdict: "UNSUPPORTED",
    evidence_ids: [],
    reason: "no recognized test-runner execution in the captured command stream",
  };
}

const F1_TO_CLAUSE = {
  VERIFIED: "KEPT",
  CONTRADICTED: "PROMISE_BROKEN",
  UNSUPPORTED: "UNEVALUATED",
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// Main export
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute all claims, brief-clause verdicts, and the evidence index for one run against its
 * sealed brief. Output feeds `buildReceipt` directly (which re-checks schema, invariants, and
 * doctrine before signing — a verdict this engine mis-emits cannot be silently signed).
 */
export function computeVerdicts(input: VerdictInput): VerdictOutput {
  const { brief, events, captureGaps, engineFinalText, workspaceRoot } = input;

  const index = indexEvidence(events, captureGaps);
  const cmdLevel = levelFor(captureGaps, "shell_command_execution");
  const cmdGapNote = captureGaps.find((g) => g.capability === "shell_command_execution")?.note ?? "capability not declared";

  // Recognized final assertion → one appended adapter_event evidence entry.
  const assertion = recognizeAssertion(engineFinalText);
  let assertionEvidenceId: string | undefined;
  if (assertion && engineFinalText !== undefined) {
    assertionEvidenceId = `ev_${String(index.evidence.length + 1).padStart(4, "0")}`;
    index.evidence.push({
      evidence_id: assertionEvidenceId,
      type: "adapter_event",
      sha256: hashBytes(engineFinalText),
      capture_level: levelFor(captureGaps, "final_structured_output"),
      source: "engine_stream",
    });
  }

  // F2 first — its PROMISE_BROKEN results feed F1's suite-mutation cap.
  const forbiddenClauses: ReceiptClauseRecord[] = brief.forbidden.map((clause) =>
    clause.kind === "freeform"
      ? {
          clause_id: machineId("clause", clause.id),
          clause_type: "forbidden" as const,
          text: sanitizeText(clause.label),
          verdict: "UNEVALUATED" as const,
          evidence_ids: [],
          reason: FREEFORM_REASON,
        }
      : adjudicateForbidden(clause, index.fileChanges, workspaceRoot),
  );
  const broken = forbiddenClauses.find((c) => c.verdict === "PROMISE_BROKEN");
  // F7b: suite-mutated reason names the broken clause label explicitly.
  const mutation = broken
    ? {
        reason: `forbidden clause '${broken.text}' broken — tests-pass cannot be evaluated on a mutated workspace`,
        evidence_ids: broken.evidence_ids,
      }
    : undefined;

  // F1 — one claim per tests-pass acceptance clause, plus its acceptance-clause rendering.
  const claims: ReceiptClaimRecord[] = [];
  const acceptanceClauses: ReceiptClauseRecord[] = [];
  let assertionConsumed = false;
  for (const clause of brief.acceptance) {
    if (clause.kind === "freeform") {
      acceptanceClauses.push({
        clause_id: machineId("clause", clause.id),
        clause_type: "acceptance",
        text: sanitizeText(clause.label),
        verdict: "UNEVALUATED",
        evidence_ids: [],
        reason: FREEFORM_REASON,
      });
      continue;
    }
    assertionConsumed = true;
    const f1 = adjudicateTestsRan({
      commands: index.commands,
      cmdLevel,
      cmdGapNote,
      ...(mutation ? { mutation } : {}),
      ...(assertion ? { assertion } : {}),
    });
    claims.push({
      claim_id: machineId("claim", clause.id),
      family: "tests-ran",
      text: assertion ? assertion.text : sanitizeText(clause.label),
      verdict: f1.verdict,
      evidence_ids: f1.evidence_ids,
      ...(f1.reason !== undefined ? { reason: f1.reason } : {}),
    } as ReceiptClaimRecord);
    acceptanceClauses.push({
      clause_id: machineId("clause", clause.id),
      clause_type: "acceptance",
      text: sanitizeText(clause.label),
      verdict: F1_TO_CLAUSE[f1.verdict],
      evidence_ids: f1.evidence_ids,
      ...(f1.reason !== undefined ? { reason: f1.reason } : {}),
    } as ReceiptClauseRecord);
  }

  // Recognized assertion with NO tests-pass acceptance clause → secondary standalone claim.
  if (assertion && !assertionConsumed) {
    const f1 = adjudicateTestsRan({
      commands: index.commands,
      cmdLevel,
      cmdGapNote,
      ...(mutation ? { mutation } : {}),
      assertion,
    });
    claims.push({
      claim_id: "claim_recognized_assertion",
      family: "recognized-assertion",
      text: assertion.text,
      verdict: f1.verdict,
      evidence_ids: f1.evidence_ids,
      ...(f1.reason !== undefined ? { reason: f1.reason } : {}),
    } as ReceiptClaimRecord);
  }

  // F3 — an empty scope promised nothing, so no clause is emitted (absence ≠ a kept promise).
  const scopeClauses: ReceiptClauseRecord[] =
    brief.scope.length > 0 ? [adjudicateScope(brief.scope, index.fileChanges, workspaceRoot)] : [];

  return {
    claims,
    brief_clauses: [...acceptanceClauses, ...forbiddenClauses, ...scopeClauses],
    evidence: index.evidence,
  };
}

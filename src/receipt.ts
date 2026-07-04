import { hashBytes } from "./hash.js";
import { parseLedgerText, recoverLedger, serializeLedger, type SealedLedgerEvent } from "./ledger.js";
import type { AcceptanceClauseRecord, ForbiddenClauseRecord } from "./schema/brief.js";
import {
  checkReceiptInvariants,
  computeBriefHash,
  ReceiptShape,
  type Receipt,
  type ReceiptClaimRecord,
  type ReceiptClauseRecord,
  type ReceiptEvidenceRecord,
  type ReceiptSummaryRecord,
} from "./schema/receipt.js";
import { signCanonical, verifySignatureBlock } from "./sign.js";

/**
 * Receipt builder + offline verifier (flagship-decision.md M1, claim-families-v1.md).
 *
 * TRUST MODEL. The signature preimage is the RFC 8785 canonical bytes of the receipt WITH THE
 * `signature` FIELD REMOVED — so every verdict, hash, and count is under the signature, and the
 * block itself is not circularly self-signed. A receipt is trustworthy only if it is ALL of:
 * schema-valid AND invariant-clean AND signature-valid. The deep check (`--run-dir`) additionally
 * re-derives the ledger binding from the actual ledger bytes: hash of the serialized JSONL, chain
 * head, event count, and full chain/content integrity via the ledger recovery machinery.
 *
 * VERIFIER DISCIPLINE. `verifyReceipt` runs against hostile input and NEVER throws; every failure
 * is a check with `ok: false` and a precise detail. No check may pass vacuously — the absence of a
 * needed input (unreadable receipt, unreadable ledger, missing binding field) FAILS that check, it
 * does not skip it. Every check runs even after earlier failures where safely possible; checks that
 * structurally depend on parse/schema fail with an explicit "not evaluated" detail instead. The
 * doctrine check (CONTRADICTED / PROMISE_BROKEN must cite evidence) deliberately re-runs against
 * the RAW parsed JSON, independent of the schema pass, so a hostile hand-built receipt cannot
 * dodge it by also being schema-invalid in some other way. Entirely offline, always.
 *
 * Two boundary notes. (1) The Zod `schema` gate STRIPS unknown top-level keys while the exported
 * schemas/receipt.schema.json REJECTS them (ajv is the stricter validator); the raw-byte
 * `signature` check is what actually catches appended keys, since any added byte changes the
 * canonical preimage. (2) `verify` attests authenticity, internal consistency, and citation
 * presence — it is NOT a re-proof of verdict computation; the full emission doctrine
 * (claim-families-v1.md) lives in the producer (src/verdicts.ts).
 */

export interface ReceiptCheck {
  id: string;
  ok: boolean;
  detail: string;
}

export interface VerifyReceiptResult {
  ok: boolean;
  checks: ReceiptCheck[];
}

export interface VerifyReceiptOptions {
  /** Ledger JSONL text for the deep check. Providing it enables the three ledger checks. */
  ledgerText?: string;
  /** A deep check was requested but the ledger could not be read: the ledger checks FAIL with this detail. */
  ledgerError?: string;
  /** The receipt file itself could not be read: the parse check FAILS with this detail (text is ignored). */
  receiptError?: string;
}

export interface BuildReceiptInput {
  run: {
    run_id: string;
    loop_family: string;
    loopeix_version: string;
    engine: "codex_cli" | "claude_code_cli";
    sealed_at: string;
  };
  brief: {
    task: string;
    acceptance: readonly AcceptanceClauseRecord[];
    forbidden: readonly ForbiddenClauseRecord[];
    scope: readonly string[];
  };
  claims: readonly ReceiptClaimRecord[];
  brief_clauses: readonly ReceiptClauseRecord[];
  evidence: readonly ReceiptEvidenceRecord[];
  capture_gaps: readonly { engine: string; capability: string; level: string; note: string }[];
  /** The sealed ledger this receipt binds to. Must be non-empty. */
  ledger: readonly SealedLedgerEvent[];
}

function computeSummary(
  claims: readonly ReceiptClaimRecord[],
  clauses: readonly ReceiptClauseRecord[],
): ReceiptSummaryRecord {
  const count = (verdicts: readonly string[], v: string): number => verdicts.filter((x) => x === v).length;
  const cv = claims.map((c) => c.verdict);
  const bv = clauses.map((c) => c.verdict);
  return {
    claims: {
      verified: count(cv, "VERIFIED"),
      contradicted: count(cv, "CONTRADICTED"),
      unsupported: count(cv, "UNSUPPORTED"),
    },
    clauses: {
      kept: count(bv, "KEPT"),
      promise_broken: count(bv, "PROMISE_BROKEN"),
      unevaluated: count(bv, "UNEVALUATED"),
    },
  };
}

/**
 * Assemble and sign a receipt. `run_state` and `integrity_status` are DERIVED from the sealed
 * ledger (recovery over the provided events), never trusted from the caller — same anchoring rule
 * as the report builder. The ledger binding is computed from the exact serialized ledger bytes.
 * Throws explicitly on an empty ledger or if the assembled receipt fails its own self-check
 * (schema + invariants + signature) — a builder that can emit an unverifiable receipt is a bug.
 */
export function buildReceipt(input: BuildReceiptInput, privateKeyPem: string): Receipt {
  const head = input.ledger.at(-1);
  if (!head) throw new Error("cannot build a receipt over an empty ledger (nothing to bind to)");
  const recovery = recoverLedger(input.ledger);

  const briefContent = {
    brief_version: "0.1" as const,
    task: input.brief.task,
    acceptance: structuredClone(input.brief.acceptance) as AcceptanceClauseRecord[],
    forbidden: structuredClone(input.brief.forbidden) as ForbiddenClauseRecord[],
    scope: [...input.brief.scope],
  };

  const unsigned = {
    receipt_version: "0.1" as const,
    run: {
      run_id: input.run.run_id,
      loop_family: input.run.loop_family,
      loopeix_version: input.run.loopeix_version,
      engine: input.run.engine,
      run_state: recovery.run_state,
      integrity_status: recovery.integrity_status,
      sealed_at: input.run.sealed_at,
    },
    brief: { ...briefContent, brief_hash: computeBriefHash(briefContent) },
    ledger_binding: {
      event_count: input.ledger.length,
      head_event_hash: head.event_hash,
      ledger_sha256: hashBytes(serializeLedger(input.ledger)),
    },
    claims: input.claims.map((c) => ({ ...c })),
    brief_clauses: input.brief_clauses.map((c) => ({ ...c })),
    evidence: input.evidence.map((e) => ({ ...e })),
    capture_gaps: input.capture_gaps.map((g) => ({ ...g })),
    summary: computeSummary(input.claims, input.brief_clauses),
  };

  const receipt = { ...unsigned, signature: signCanonical(unsigned, privateKeyPem) };

  // Self-check: the builder must never emit a receipt its own verifier would reject.
  const parsed = ReceiptShape.safeParse(receipt);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    throw new Error(`buildReceipt produced a schema-invalid receipt: ${first?.path.join(".")}: ${first?.message}`);
  }
  const issues = checkReceiptInvariants(parsed.data);
  if (issues.length > 0) {
    throw new Error(`buildReceipt produced an invariant-violating receipt: ${issues[0]!.path}: ${issues[0]!.message}`);
  }
  if (!verifySignatureBlock(unsigned, receipt.signature)) {
    throw new Error("buildReceipt produced a receipt whose signature does not verify");
  }
  return parsed.data;
}

/** Doctrine over the RAW parsed JSON: fail closed on anything that cannot be positively checked. */
function doctrineFailures(rec: Record<string, unknown>): string[] {
  const failures: string[] = [];
  const inspect = (listName: string, badVerdict: string): void => {
    const list = rec[listName];
    if (!Array.isArray(list)) {
      failures.push(`'${listName}' is not an array, so the doctrine cannot be attested`);
      return;
    }
    list.forEach((item, i) => {
      if (typeof item !== "object" || item === null) {
        failures.push(`${listName}[${i}] is not an object, so the doctrine cannot be attested`);
        return;
      }
      const o = item as Record<string, unknown>;
      if (o.verdict !== badVerdict) return;
      const ev = o.evidence_ids;
      const cited = Array.isArray(ev) && ev.some((id) => typeof id === "string" && id.trim() !== "");
      if (!cited) failures.push(`${listName}[${i}] carries ${badVerdict} without a citable evidence id`);
    });
  };
  inspect("claims", "CONTRADICTED");
  inspect("brief_clauses", "PROMISE_BROKEN");
  return failures;
}

/** Tolerant nested string read off hostile JSON (returns undefined, never throws). */
function readString(rec: Record<string, unknown> | undefined, outer: string, inner: string): string | undefined {
  const o = rec?.[outer];
  if (typeof o !== "object" || o === null) return undefined;
  const v = (o as Record<string, unknown>)[inner];
  return typeof v === "string" ? v : undefined;
}

function readNumber(rec: Record<string, unknown> | undefined, outer: string, inner: string): number | undefined {
  const o = rec?.[outer];
  if (typeof o !== "object" || o === null) return undefined;
  const v = (o as Record<string, unknown>)[inner];
  return typeof v === "number" ? v : undefined;
}

/**
 * Verify a receipt offline. Check ids, in order: `parse`, `schema`, `invariants`, `doctrine`,
 * `signature`, and — when a deep check is requested via `opts` — `ledger_hash`, `ledger_head`,
 * `ledger_chain`. See the module header for the trust model and verifier discipline.
 */
export function verifyReceipt(receiptJsonText: string, opts: VerifyReceiptOptions = {}): VerifyReceiptResult {
  const checks: ReceiptCheck[] = [];
  const push = (id: string, ok: boolean, detail: string): void => {
    checks.push({ id, ok, detail });
  };

  // parse — the only check with no prerequisites.
  let rec: Record<string, unknown> | undefined;
  if (opts.receiptError !== undefined) {
    push("parse", false, `cannot read receipt: ${opts.receiptError}`);
  } else {
    try {
      const raw: unknown = JSON.parse(receiptJsonText);
      if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
        push("parse", false, "receipt is valid JSON but not an object");
      } else {
        rec = raw as Record<string, unknown>;
        push("parse", true, "receipt parses as a JSON object");
      }
    } catch (err) {
      push("parse", false, `invalid JSON: ${(err as Error).message}`);
    }
  }

  // schema — structural pass (Zod, same source as schemas/receipt.schema.json).
  let receipt: Receipt | undefined;
  if (!rec) {
    push("schema", false, "not evaluated: receipt did not parse");
  } else {
    const parsed = ReceiptShape.safeParse(rec);
    if (parsed.success) {
      receipt = parsed.data;
      push("schema", true, "receipt matches receipt_version 0.1 schema");
    } else {
      const shown = parsed.error.issues
        .slice(0, 3)
        .map((i) => `${i.path.map((p) => String(p)).join(".") || "(root)"}: ${i.message}`)
        .join("; ");
      push("schema", false, `${parsed.error.issues.length} schema violation(s): ${shown}`);
    }
  }

  // invariants — cross-field rules; structurally needs a schema-valid receipt.
  if (!receipt) {
    push("invariants", false, rec ? "not evaluated: schema failed" : "not evaluated: receipt did not parse");
  } else {
    const issues = checkReceiptInvariants(receipt);
    if (issues.length === 0) push("invariants", true, "evidence references, summary counts, and brief_hash are consistent");
    else push("invariants", false, `${issues.length} invariant violation(s): ${issues.slice(0, 3).map((i) => `${i.path}: ${i.message}`).join("; ")}`);
  }

  // doctrine — re-checked against the RAW JSON, independent of the schema pass.
  if (!rec) {
    push("doctrine", false, "not evaluated: receipt did not parse");
  } else {
    try {
      const failures = doctrineFailures(rec);
      if (failures.length === 0) push("doctrine", true, "every CONTRADICTED/PROMISE_BROKEN verdict cites evidence");
      else push("doctrine", false, failures.join("; "));
    } catch (err) {
      push("doctrine", false, `doctrine check error: ${(err as Error).message}`);
    }
  }

  // signature — over the canonical bytes of the receipt minus its signature field.
  if (!rec) {
    push("signature", false, "not evaluated: receipt did not parse");
  } else {
    try {
      const { signature, ...unsigned } = rec;
      if (signature === undefined) {
        push("signature", false, "receipt has no signature block");
      } else if (verifySignatureBlock(unsigned, signature)) {
        push("signature", true, "ECDSA P-256 signature verifies against the embedded public key");
      } else {
        push("signature", false, "signature does not verify (content altered, key mismatched, or block malformed)");
      }
    } catch (err) {
      push("signature", false, `signature check error: ${(err as Error).message}`);
    }
  }

  // Deep ledger checks — only when a deep check was requested.
  const deepRequested = opts.ledgerText !== undefined || opts.ledgerError !== undefined;
  if (deepRequested) {
    if (opts.ledgerError !== undefined || opts.ledgerText === undefined) {
      const detail = `cannot read ledger: ${opts.ledgerError ?? "no ledger text provided"}`;
      push("ledger_hash", false, detail);
      push("ledger_head", false, detail);
      push("ledger_chain", false, detail);
    } else {
      const text = opts.ledgerText;

      const boundHash = readString(rec, "ledger_binding", "ledger_sha256");
      if (boundHash === undefined) {
        push("ledger_hash", false, "receipt has no ledger_binding.ledger_sha256 to compare against");
      } else if (hashBytes(text) === boundHash) {
        push("ledger_hash", true, "ledger bytes hash to the bound ledger_sha256");
      } else {
        push("ledger_hash", false, "ledger bytes do NOT hash to the bound ledger_sha256 (different or altered ledger)");
      }

      const { events, partialFinalLineDropped, corruptLines } = parseLedgerText(text);

      const boundHead = readString(rec, "ledger_binding", "head_event_hash");
      const boundCount = readNumber(rec, "ledger_binding", "event_count");
      const last = events.at(-1);
      const lastHash =
        typeof last === "object" && last !== null && typeof (last as Record<string, unknown>).event_hash === "string"
          ? ((last as Record<string, unknown>).event_hash as string)
          : undefined;
      if (boundHead === undefined || boundCount === undefined) {
        push("ledger_head", false, "receipt has no ledger_binding head_event_hash/event_count to compare against");
      } else if (lastHash === undefined) {
        push("ledger_head", false, "ledger has no readable final event to compare against the bound head");
      } else if (lastHash === boundHead && events.length === boundCount) {
        push("ledger_head", true, `head event hash and event count (${events.length}) match the binding`);
      } else {
        push(
          "ledger_head",
          false,
          `binding mismatch: head ${lastHash === boundHead ? "matches" : "differs"}, count ${events.length} vs bound ${boundCount}`,
        );
      }

      try {
        const recovery = recoverLedger(events, { partialFinalLineDropped, corruptLines });
        if (recovery.integrity_status === "valid") {
          push("ledger_chain", true, "hash chain and event content hashes verify end to end");
        } else {
          push("ledger_chain", false, `ledger integrity is '${recovery.integrity_status}': ${recovery.findings.slice(0, 3).join("; ")}`);
        }
      } catch (err) {
        push("ledger_chain", false, `ledger recovery error: ${(err as Error).message}`);
      }
    }
  }

  return { ok: checks.every((c) => c.ok), checks };
}

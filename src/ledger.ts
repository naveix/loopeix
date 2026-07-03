import { hashCanonical } from "./hash.js";
import type { Issue } from "./schema/loopeix.js";
import { LedgerEvent, type LedgerEventRecord } from "./schema/runtime.js";

/**
 * INTEGRITY GUARANTEE (see docs/security-model.md).
 * The ledger is a SHA-256 hash chain: it is tamper-EVIDENT against accidental
 * corruption and naive in-place edits, NOT tamper-PROOF. A write-capable actor who
 * knows the (public) sealing algorithm can re-seal a forged or truncated chain.
 * V1 mitigations implemented here: strict event shape, single-run binding, event-id
 * uniqueness, content-hash recomputation, and truncation detection against an expected
 * head sequence. Tamper-PROOF (signing/HMAC or external anchoring) is a post-V1 item.
 */

export type SealedLedgerEvent = LedgerEventRecord;

/** A ledger event before the runtime assigns sequence + hashes. */
export type LedgerEventDraft = Omit<SealedLedgerEvent, "sequence" | "previous_event_hash" | "event_hash">;

/** WRITE side: seal a draft onto the chain (assign sequence, link + hash). */
export function appendToLedger(existing: readonly SealedLedgerEvent[], draft: LedgerEventDraft): SealedLedgerEvent {
  const last = existing.at(-1);
  const sequence = existing.length + 1;
  const previous_event_hash = last ? last.event_hash : null;
  const unsealed = { ...draft, sequence, previous_event_hash };
  const event_hash = hashCanonical(unsealed);
  return { ...unsealed, event_hash };
}

/** Serialize sealed events to newline-terminated JSONL. */
export function serializeLedger(events: readonly SealedLedgerEvent[]): string {
  return events.map((e) => JSON.stringify(e)).join("\n") + "\n";
}

/**
 * Parse ledger text tolerantly and NEVER throw (a crash on one bad line would make the
 * whole ledger unreadable). A blank line is ignored (JSONL allows it). A corrupt FINAL
 * line is treated as a partial write (dropped + flagged). A corrupt NON-final line is
 * quarantined — its 1-based line number is returned in `corruptLines` — and recovery
 * folds that into a HOLD (a skipped middle line also breaks the chain, which is caught
 * downstream). This lets an operator SEE the corruption and recover the valid prefix.
 */
export function parseLedgerText(text: string): {
  events: unknown[];
  partialFinalLineDropped: boolean;
  corruptLines: number[];
} {
  const lines = text.split("\n");
  while (lines.length > 0 && lines.at(-1) === "") lines.pop();
  const events: unknown[] = [];
  const corruptLines: number[] = [];
  let partialFinalLineDropped = false;
  lines.forEach((line, idx) => {
    if (line.trim() === "") return; // JSONL tolerates blank lines
    try {
      events.push(JSON.parse(line));
    } catch {
      if (idx === lines.length - 1) partialFinalLineDropped = true;
      else corruptLines.push(idx + 1);
    }
  });
  return { events, partialFinalLineDropped, corruptLines };
}

/**
 * Chain-linkage + shape check: every event is a STRICT LedgerEvent (unknown keys
 * rejected), all events share one run_id with unique event_ids, `sequence` runs 1..n,
 * and `previous_event_hash` equals the prior `event_hash` (null only at sequence 1).
 */
export function validateLedger(events: readonly unknown[]): Issue[] {
  const issues: Issue[] = [];
  let prevHash: string | null = null;
  let runId: string | null = null;
  const eventIds = new Set<string>();

  events.forEach((raw, i) => {
    const parsed = LedgerEvent.safeParse(raw);
    if (!parsed.success) {
      for (const iss of parsed.error.issues) {
        issues.push({ path: `event[${i}].${iss.path.map((p) => String(p)).join(".")}`, message: iss.message });
      }
      return;
    }
    const ev = parsed.data;

    if (runId === null) runId = ev.run_id;
    else if (ev.run_id !== runId) {
      issues.push({ path: `event[${i}].run_id`, message: `run_id '${ev.run_id}' does not match the ledger's run_id '${runId}'` });
    }
    if (eventIds.has(ev.event_id)) {
      issues.push({ path: `event[${i}].event_id`, message: `duplicate event_id '${ev.event_id}'` });
    }
    eventIds.add(ev.event_id);

    if (ev.sequence !== i + 1) {
      issues.push({ path: `event[${i}].sequence`, message: `expected sequence ${i + 1}, got ${ev.sequence}` });
    }
    if (i === 0) {
      if (ev.previous_event_hash !== null) {
        issues.push({ path: "event[0].previous_event_hash", message: "first event must have a null previous_event_hash" });
      }
    } else if (ev.previous_event_hash !== prevHash) {
      issues.push({ path: `event[${i}].previous_event_hash`, message: "hash chain break: previous_event_hash does not match the prior event_hash" });
    }
    prevHash = ev.event_hash;
  });

  return issues;
}

/**
 * Content-integrity check: recompute each `event_hash` from its content and compare.
 * Catches naive tampering the chain-linkage check alone would miss (a mutated payload
 * whose stored hash was not updated). Does NOT catch a full re-seal (see guarantee).
 */
export function verifyEventHashes(events: readonly SealedLedgerEvent[]): Issue[] {
  const issues: Issue[] = [];
  events.forEach((ev, i) => {
    const { event_hash, ...rest } = ev;
    if (hashCanonical(rest) !== event_hash) {
      issues.push({ path: `event[${i}].event_hash`, message: "event_hash mismatch: content does not match the stored hash (possible tamper)" });
    }
  });
  return issues;
}

const RUN_STATE_BY_EVENT: Record<string, string> = {
  "run.completed": "completed",
  "run.failed": "failed",
  "run.interrupted": "interrupted",
  "run.recovering": "recovering",
  "run.held": "held",
  "run.started": "running",
};

const TERMINAL_EVENTS = new Set(["run.completed", "run.failed", "run.held", "run.archived"]);

export interface RecoveryResult {
  integrity_status: "valid" | "hold";
  run_state: string;
  last_valid_sequence: number;
  terminated: boolean;
  findings: string[];
}

/**
 * Recovery: validate chain + shape + run binding, recompute content hashes, fold in a
 * dropped partial final line and (if provided) a truncation check against the expected
 * head sequence. Any integrity problem yields HOLD with findings, never a silent pass.
 */
export function recoverLedger(
  rawEvents: readonly unknown[],
  opts: { partialFinalLineDropped?: boolean; expectedLastSequence?: number; corruptLines?: readonly number[] } = {},
): RecoveryResult {
  const findings: string[] = [];
  if (opts.partialFinalLineDropped) findings.push("dropped a partial final ledger line during recovery");
  if (opts.corruptLines && opts.corruptLines.length > 0)
    findings.push(`quarantined ${opts.corruptLines.length} corrupt ledger line(s) at line(s): ${opts.corruptLines.join(", ")}`);

  const chainIssues = validateLedger(rawEvents);
  for (const i of chainIssues) findings.push(`chain: ${i.path}: ${i.message}`);

  const sealed = rawEvents.flatMap((e) => {
    const p = LedgerEvent.safeParse(e);
    return p.success ? [p.data] : [];
  });
  // Only meaningful to recompute content hashes when the chain parsed cleanly.
  if (chainIssues.length === 0) {
    for (const i of verifyEventHashes(sealed)) findings.push(`integrity: ${i.path}: ${i.message}`);
  }

  // Derive state from the longest VALID PREFIX (contiguous sequence, intact linkage, matching content
  // hash) — never from post-corruption events, so `last_valid_sequence`/`terminated` cannot point past
  // a detected break (e.g. a quarantined middle line must not report a later run.completed as reached).
  let validCount = 0;
  let prevHash: string | null = null;
  for (let i = 0; i < sealed.length; i++) {
    const ev = sealed[i]!;
    const { event_hash, ...rest } = ev;
    const ok =
      ev.sequence === i + 1 &&
      (i === 0 ? ev.previous_event_hash === null : ev.previous_event_hash === prevHash) &&
      hashCanonical(rest) === event_hash;
    if (!ok) break;
    validCount = i + 1;
    prevHash = ev.event_hash;
  }
  const lastValid = validCount > 0 ? sealed[validCount - 1]! : undefined;
  const last_valid_sequence = lastValid ? lastValid.sequence : 0;
  const terminated = lastValid ? TERMINAL_EVENTS.has(lastValid.event_type) : false;

  if (opts.expectedLastSequence !== undefined && last_valid_sequence < opts.expectedLastSequence) {
    findings.push(`truncation: expected last sequence ${opts.expectedLastSequence}, found ${last_valid_sequence}`);
  }

  return {
    integrity_status: findings.length === 0 ? "valid" : "hold",
    run_state: lastValid ? (RUN_STATE_BY_EVENT[lastValid.event_type] ?? "running") : "planned",
    last_valid_sequence,
    terminated,
    findings,
  };
}

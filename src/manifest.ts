import { hashBytes } from "./hash.js";
import { recoverLedger, serializeLedger, type SealedLedgerEvent } from "./ledger.js";
import type { RunManifestRecord } from "./schema/runtime.js";

export interface RunManifestInput {
  run_id: string;
  loop_family: string;
  loopeix_version: string;
  workspace_root: string;
  run_dir: string;
  created_at: string;
  updated_at: string;
  events: readonly SealedLedgerEvent[];
  file_inventory: RunManifestRecord["file_inventory"];
  /** Optional non-ledger hashes; the ledger hash is always computed, never trusted. */
  hashes?: { manifest?: string; report?: string };
  schema_versions?: Record<string, string>;
  /** Expected head sequence from a prior manifest — enables truncation detection. */
  expectedLastSequence?: number;
}

/**
 * Build a RunManifest from a run's ledger + file inventory.
 *
 * Integrity is DERIVED, not trusted: `integrity_status`/`run_state`/`last_ledger_sequence`
 * come from recovering the ledger; the ledger hash is recomputed from the actual events;
 * and every event's `run_id` must equal `input.run_id` (else HOLD). When the ledger is not
 * trusted, `blocking_gate_summary` is zeroed and marked `trusted: false` so a consumer
 * cannot read PASS counts off an untrusted run.
 */
export function buildRunManifest(input: RunManifestInput): RunManifestRecord {
  const recovery = recoverLedger(input.events, { expectedLastSequence: input.expectedLastSequence });
  const runMismatch = input.events.some((e) => e.run_id !== input.run_id);
  const trusted = recovery.integrity_status === "valid" && !runMismatch;
  const integrity_status: RunManifestRecord["integrity_status"] = trusted ? "valid" : "hold";

  // The ledger hash anchors the manifest to the actual events (computed, not caller-supplied).
  const hashes: RunManifestRecord["hashes"] = { ledger: hashBytes(serializeLedger(input.events)) };
  if (input.hashes?.manifest !== undefined) hashes.manifest = input.hashes.manifest;
  if (input.hashes?.report !== undefined) hashes.report = input.hashes.report;

  let pass = 0;
  let hold = 0;
  let fail = 0;
  let latest: string | null = null;
  if (trusted) {
    for (const e of input.events) {
      if (e.event_type !== "gate.result") continue;
      const status = (e.payload as { status?: unknown }).status;
      if (status === "PASS") pass += 1;
      else if (status === "HOLD") hold += 1;
      else if (status === "FAIL") fail += 1;
      if (typeof status === "string") latest = status;
    }
  }

  return {
    schema_version: "0.1",
    run_id: input.run_id,
    loop_family: input.loop_family,
    loopeix_version: input.loopeix_version,
    run_state: recovery.run_state as RunManifestRecord["run_state"],
    created_at: input.created_at,
    updated_at: input.updated_at,
    workspace_root: input.workspace_root,
    run_dir: input.run_dir,
    schema_versions: input.schema_versions ?? {},
    file_inventory: input.file_inventory,
    hashes,
    integrity_status,
    last_ledger_sequence: recovery.last_valid_sequence,
    blocking_gate_summary: { pass, hold, fail, latest, trusted },
  };
}

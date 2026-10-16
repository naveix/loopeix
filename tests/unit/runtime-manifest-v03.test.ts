import { describe, expect, it } from "vitest";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import {
  buildRunManifestV03,
  inspectRunManifestV03,
  RunManifestV03,
} from "../../src/run/runtime-manifest-v03.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const encoder = new TextEncoder();

const inventory = {
  resolved_run_plan: "0.2", ledger_event: "0.3", run_manifest: "0.3", artifact_manifest: "0.2",
  redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
  agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2",
  manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2",
  evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2",
  gate_waiver_authority: "0.2",
} as const;

function ledgerBytes(): Uint8Array {
  const preimage = {
    schema_version: "0.3", event_id: "event_manifest_initialized", run_id: "run_manifest_v03",
    sequence: 1, recorded_at: "2026-08-24T10:00:00Z", event_type: "run.initialized",
    source: "kernel", authority_ref: null, risk_tier: "T1", related_ids: [], previous_event_hash: null,
    payload: { plan_hash: H("a"), initial_fence_epoch: 0, runtime_schema_versions: inventory },
  };
  return encoder.encode(`${JSON.stringify({ ...preimage, event_hash: hashCanonical(preimage) })}\n`);
}

function input() {
  const ledger = ledgerBytes();
  return {
    ledger_bytes: ledger,
    created_at: "2026-08-24T10:00:00Z",
    captured_files: [
      { path: "artifact-manifest.json", family: "projection", required: false, mode: null, bytes: null },
      { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledger },
    ],
  } as const;
}

function withHash(manifest: Record<string, unknown>): Uint8Array {
  const { manifest_hash: _manifestHash, ...preimage } = manifest;
  return encoder.encode(JSON.stringify({ ...preimage, manifest_hash: hashCanonical(preimage) }));
}

describe("S40-B1 V03 run manifest projection", () => {
  it("builds the exact 0.3 manifest from a validated ledger and stable captures", () => {
    const result = buildRunManifestV03(input());
    expect(result).toMatchObject({
      ok: true,
      manifest: {
        schema_version: "0.3", run_id: "run_manifest_v03", plan_hash: H("a"),
        execution_profile: "bounded-v03", schema_versions: inventory, run_state: "initialized",
        ledger_sequence: 1, current_fence_epoch: 0, terminal: null,
      },
    });
    if (!result.ok) throw new Error(result.reason);
    expect(result.manifest.projection_event_ref).toEqual({
      ledger_sequence: 1, event_hash: result.manifest.ledger_head_hash,
    });
    expect(result.manifest.ledger_bytes_hash).toBe(hashRawBytes(input().ledger_bytes));
    expect(result.manifest.file_inventory).toEqual([
      { path: "artifact-manifest.json", family: "projection", required: false, exists: false, mode: null, size_bytes: null, hash: null },
      { path: "ledger.jsonl", family: "primary", required: true, exists: true, mode: 384, size_bytes: input().ledger_bytes.byteLength, hash: hashRawBytes(input().ledger_bytes) },
    ]);
    const { manifest_hash: _hash, ...preimage } = result.manifest;
    expect(result.manifest.manifest_hash).toBe(hashCanonical(preimage));
    expect(JSON.parse(new TextDecoder().decode(result.bytes))).toEqual(result.manifest);
    expect(Object.keys(result.manifest)).toEqual([
      "schema_version", "run_id", "plan_hash", "execution_profile", "schema_versions", "run_state",
      "created_at", "projection_event_ref", "ledger_bytes_hash", "ledger_sequence", "ledger_head_hash",
      "current_fence_epoch", "terminal", "file_inventory", "manifest_hash",
    ]);
    expect(Object.isFrozen(result.manifest)).toBe(true);
    expect(Object.isFrozen(result.manifest.file_inventory)).toBe(true);
  });

  it("round-trips exact manifest bytes against the same ledger and closed captures", () => {
    const built = buildRunManifestV03(input());
    if (!built.ok) throw new Error(built.reason);
    expect(inspectRunManifestV03({
      manifest_bytes: built.bytes,
      ledger_bytes: input().ledger_bytes,
      captured_files: input().captured_files,
    })).toMatchObject({ ok: true, manifest: built.manifest });
  });

  it("rejects caller-authored cross-ledger, self-row, hash, and file-capture drift", () => {
    const built = buildRunManifestV03(input());
    if (!built.ok) throw new Error(built.reason);
    const manifest = built.manifest;
    const mutated = { ...manifest, run_state: "running" };
    expect(inspectRunManifestV03({
      manifest_bytes: encoder.encode(JSON.stringify(mutated)), ledger_bytes: input().ledger_bytes,
      captured_files: input().captured_files,
    })).toMatchObject({ ok: false });
    expect(buildRunManifestV03({
      ...input(), captured_files: [
        ...input().captured_files,
        { path: "run-manifest.json", family: "projection", required: true, mode: 384, bytes: built.bytes },
      ],
    })).toMatchObject({ ok: false, reason: "FILE_CAPTURE_INVALID" });
    expect(inspectRunManifestV03({
      manifest_bytes: built.bytes, ledger_bytes: ledgerBytes(),
      captured_files: [{ ...input().captured_files[1], bytes: encoder.encode("drift") }],
    })).toMatchObject({ ok: false, reason: "FILE_CAPTURE_INVALID" });
  });

  it("rejects every ledger, state, fence, terminal, and closed-file cross-binding drift", () => {
    const built = buildRunManifestV03(input());
    if (!built.ok) throw new Error(built.reason);
    const manifest = built.manifest;
    const mutations: Array<Record<string, unknown>> = [
      { ...manifest, run_id: "run_manifest_foreign" },
      { ...manifest, plan_hash: H("b") },
      { ...manifest, run_state: "running" },
      { ...manifest, ledger_bytes_hash: H("b") },
      { ...manifest, ledger_sequence: 2, projection_event_ref: { ledger_sequence: 2, event_hash: manifest.ledger_head_hash } },
      { ...manifest, ledger_head_hash: H("b"), projection_event_ref: { ledger_sequence: 1, event_hash: H("b") } },
      { ...manifest, current_fence_epoch: 1 },
      {
        ...manifest, run_state: "sealed",
        terminal: { outcome: "completed", snapshot_hash: H("b"), seal_event_ref: manifest.projection_event_ref },
      },
      {
        ...manifest,
        file_inventory: manifest.file_inventory.map((row) => row.path === "ledger.jsonl"
          ? { ...row, size_bytes: Number(row.size_bytes) + 1, hash: H("b") }
          : row),
      },
    ];
    for (const mutation of mutations) {
      expect(inspectRunManifestV03({
        manifest_bytes: withHash(mutation), ledger_bytes: input().ledger_bytes,
        captured_files: input().captured_files,
      })).toMatchObject({ ok: false });
    }
  });

  it("rejects zero sequence, extra keys, unsorted/duplicate paths, and any manifest self-row", () => {
    const built = buildRunManifestV03(input());
    if (!built.ok) throw new Error(built.reason);
    const manifest = built.manifest;
    expect(RunManifestV03.safeParse({ ...manifest, ledger_sequence: 0 }).success).toBe(false);
    expect(RunManifestV03.safeParse({ ...manifest, invented: true }).success).toBe(false);
    expect(RunManifestV03.safeParse({
      ...manifest, file_inventory: [...manifest.file_inventory].reverse(),
    }).success).toBe(false);
    expect(RunManifestV03.safeParse({
      ...manifest, file_inventory: [manifest.file_inventory[0], manifest.file_inventory[0]],
    }).success).toBe(false);
    expect(RunManifestV03.safeParse({
      ...manifest,
      file_inventory: [{
        path: "run-manifest.json", family: "projection", required: true, exists: true,
        mode: 384, size_bytes: built.bytes.byteLength, hash: hashRawBytes(built.bytes),
      }],
    }).success).toBe(false);
  });

  it("fails closed on duplicate JSON keys and hostile input shapes", () => {
    expect(inspectRunManifestV03({
      manifest_bytes: encoder.encode('{"schema_version":"0.3","schema_version":"0.3"}'),
      ledger_bytes: input().ledger_bytes, captured_files: input().captured_files,
    })).toMatchObject({ ok: false, reason: "MANIFEST_SYNTAX_INVALID" });
    const hostile = new Proxy(input(), { getPrototypeOf: () => { throw new Error("trap"); } });
    expect(buildRunManifestV03(hostile)).toMatchObject({ ok: false, reason: "MANIFEST_INPUT_INVALID" });
  });
});

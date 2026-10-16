import { describe, expect, it } from "vitest";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import {
  buildRunManifestV04,
  captureValidatedRunManifestFileV04,
  inspectRunManifestV04,
  isValidatedRunManifestPairV04,
  isValidatedRunManifestV04,
  RunManifestV04,
} from "../../src/run/runtime-manifest-v04.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const encoder = new TextEncoder();
const inventory = {
  resolved_run_plan: "0.3", ledger_event: "0.4", run_manifest: "0.4",
  artifact_manifest: "0.2", redaction_derivative: "0.2", human_authorization_proof: "0.2",
  authority_envelope: "0.2", agency_recommendation: "0.2", authority_revocation: "0.2",
  task_result: "0.2", manual_observation: "0.2", export_decision: "0.2",
  evidence_item: "0.2", gate_result: "0.2", evaluation_result: "0.2", claim: "0.2",
  finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2", summary_artifact: "0.1",
} as const;

function ledgerBytes(): Uint8Array {
  const preimage = {
    schema_version: "0.4", event_id: "event_manifest_v04_initialized", run_id: "run_manifest_v04",
    sequence: 1, recorded_at: "2026-08-26T23:00:00Z", event_type: "run.initialized",
    source: "kernel", authority_ref: null, risk_tier: "T1", related_ids: [], previous_event_hash: null,
    payload: { plan_hash: H("a"), initial_fence_epoch: 0, runtime_schema_versions: inventory },
  };
  return encoder.encode(`${JSON.stringify({ ...preimage, event_hash: hashCanonical(preimage) })}\n`);
}

function input() {
  const ledger = ledgerBytes();
  return {
    ledger_bytes: ledger,
    created_at: "2026-08-26T23:00:00Z",
    captured_files: [
      { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledger },
      { path: "summaries/content/summary_absent.bin", family: "record", required: false, mode: null, bytes: null },
    ],
  } as const;
}

function withHash(manifest: Record<string, unknown>): Uint8Array {
  const { manifest_hash: _hash, ...preimage } = manifest;
  return encoder.encode(JSON.stringify({ ...preimage, manifest_hash: hashCanonical(preimage) }));
}

describe("S41-C1 branded V04 run-manifest admission", () => {
  it("builds the exact unbranded 15-key V04 candidate from validated ledger truth", () => {
    const built = buildRunManifestV04(input());
    expect(built).toMatchObject({
      ok: true,
      manifest: {
        schema_version: "0.4", run_id: "run_manifest_v04", plan_hash: H("a"),
        execution_profile: "bounded-v04", schema_versions: inventory,
        run_state: "initialized", ledger_sequence: 1, current_fence_epoch: 0, terminal: null,
      },
    });
    if (!built.ok) return;
    expect(Object.keys(built.manifest)).toHaveLength(15);
    expect(built.manifest.ledger_bytes_hash).toBe(hashRawBytes(input().ledger_bytes));
    expect(Object.isFrozen(built.manifest)).toBe(true);
    expect("validated_manifest" in built).toBe(false);
  });

  it("round-trips exact bytes and solely mints matching immutable manifest and ledger brands", () => {
    const built = buildRunManifestV04(input());
    if (!built.ok) throw new Error(built.reason);
    const inspected = inspectRunManifestV04({
      manifest_bytes: built.bytes,
      ledger_bytes: input().ledger_bytes,
      captured_files: input().captured_files,
    });
    expect(inspected).toMatchObject({
      ok: true,
      manifest: built.manifest,
      ledger: { run_id: built.manifest.run_id, head_hash: built.manifest.ledger_head_hash },
    });
    if (!inspected.ok) return;
    expect(inspected.validated_manifest.manifest_hash).toBe(built.manifest.manifest_hash);
    expect(Object.isFrozen(inspected.validated_manifest)).toBe(true);
    expect(Object.isFrozen(inspected.ledger)).toBe(true);
    expect(isValidatedRunManifestV04(inspected.validated_manifest)).toBe(true);
    expect(isValidatedRunManifestPairV04(inspected.validated_manifest, inspected.ledger)).toBe(true);
    expect(isValidatedRunManifestV04({ ...inspected.validated_manifest })).toBe(false);
    expect(isValidatedRunManifestPairV04(inspected.validated_manifest, { ...inspected.ledger })).toBe(false);
    const capturedLedger = captureValidatedRunManifestFileV04(inspected.validated_manifest, "ledger.jsonl");
    expect(capturedLedger).toMatchObject({ ok: true });
    if (capturedLedger.ok && capturedLedger.bytes !== null) {
      expect(capturedLedger.bytes).toEqual(input().ledger_bytes);
      capturedLedger.bytes.fill(0);
      expect(captureValidatedRunManifestFileV04(inspected.validated_manifest, "ledger.jsonl"))
        .toMatchObject({ ok: true, bytes: input().ledger_bytes });
    }
    expect(captureValidatedRunManifestFileV04({ ...inspected.validated_manifest }, "ledger.jsonl"))
      .toEqual({ ok: false, reason: "MANIFEST_BRAND_INVALID" });
  });

  it("rejects every ledger/state/fence/inventory/file cross-binding mutation", () => {
    const built = buildRunManifestV04(input());
    if (!built.ok) throw new Error(built.reason);
    const mutations: Array<Record<string, unknown>> = [
      { ...built.manifest, run_id: "run_foreign" },
      { ...built.manifest, plan_hash: H("b") },
      { ...built.manifest, run_state: "running" },
      { ...built.manifest, ledger_bytes_hash: H("b") },
      { ...built.manifest, current_fence_epoch: 1 },
      { ...built.manifest, schema_versions: { ...inventory, ledger_event: "0.3" } },
      { ...built.manifest, file_inventory: [] },
    ];
    for (const manifest of mutations) {
      expect(inspectRunManifestV04({
        manifest_bytes: withHash(manifest), ledger_bytes: input().ledger_bytes,
        captured_files: input().captured_files,
      })).toMatchObject({ ok: false });
    }
  });

  it("keeps schema keys strict and file inventory bounded, sorted, unique, and self-excluding", () => {
    const built = buildRunManifestV04(input());
    if (!built.ok) throw new Error(built.reason);
    expect(RunManifestV04.safeParse({ ...built.manifest, invented: true }).success).toBe(false);
    expect(RunManifestV04.safeParse({ ...built.manifest, ledger_sequence: 0 }).success).toBe(false);
    expect(RunManifestV04.safeParse({
      ...built.manifest,
      file_inventory: [...built.manifest.file_inventory].reverse(),
    }).success).toBe(false);
    expect(RunManifestV04.safeParse({
      ...built.manifest,
      file_inventory: [{
        path: "run-manifest.json", family: "projection", required: true, exists: true,
        mode: 384, size_bytes: built.bytes.byteLength, hash: hashRawBytes(built.bytes),
      }],
    }).success).toBe(false);
  });

  it("enforces failure precedence for syntax, ledger, file capture, then cross-check drift", () => {
    const built = buildRunManifestV04(input());
    if (!built.ok) throw new Error(built.reason);
    expect(inspectRunManifestV04({
      manifest_bytes: encoder.encode('{"schema_version":"0.4","schema_version":"0.4"}'),
      ledger_bytes: input().ledger_bytes, captured_files: input().captured_files,
    })).toMatchObject({ ok: false, reason: "MANIFEST_SYNTAX_INVALID" });
    expect(inspectRunManifestV04({
      manifest_bytes: built.bytes, ledger_bytes: encoder.encode("{}\n"), captured_files: input().captured_files,
    })).toMatchObject({ ok: false, reason: "LEDGER_INVALID" });
    expect(inspectRunManifestV04({
      manifest_bytes: built.bytes, ledger_bytes: input().ledger_bytes,
      captured_files: [{ ...input().captured_files[0], bytes: encoder.encode("drift") }],
    })).toMatchObject({ ok: false, reason: "FILE_CAPTURE_INVALID" });
  });

  it("fails closed on hostile input without invoking accessors", () => {
    const hostile = new Proxy(input(), { getPrototypeOf: () => { throw new Error("trap"); } });
    expect(buildRunManifestV04(hostile)).toEqual({ ok: false, reason: "MANIFEST_INPUT_INVALID" });
    expect(inspectRunManifestV04(hostile)).toEqual({ ok: false, reason: "MANIFEST_INPUT_INVALID" });
  });
});

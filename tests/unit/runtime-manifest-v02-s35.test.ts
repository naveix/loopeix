import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import canonicalize from "canonicalize";
import { describe, expect, it } from "vitest";
import {
  ArtifactManifest,
  RunManifest,
} from "../../src/schema/runtime.js";
import {
  ArtifactManifestV02,
  RunManifestFileEntryV02,
  RunManifestV02,
  RuntimeSchemaInventoryV02,
} from "../../src/schema/runtime-manifests-v02.js";

const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;
const HASH_D = `sha256:${"d".repeat(64)}`;
const HASH_E = `sha256:${"e".repeat(64)}`;
const REF_A = { ledger_sequence: 3, event_hash: HASH_B } as const;
const REF_B = { ledger_sequence: 4, event_hash: HASH_D } as const;

const EXACT_RUNTIME_INVENTORY_V02 = {
  resolved_run_plan: "0.2",
  ledger_event: "0.2",
  run_manifest: "0.2",
  artifact_manifest: "0.2",
  redaction_derivative: "0.2",
  human_authorization_proof: "0.2",
  authority_envelope: "0.2",
  agency_recommendation: "0.2",
  authority_revocation: "0.2",
  task_result: "0.2",
  manual_observation: "0.2",
  export_decision: "0.2",
  evidence_item: "0.2",
  gate_result: "0.2",
  evaluation_result: "0.2",
  claim: "0.2",
  finding: "0.2",
  waiver: "0.2",
  gate_waiver_authority: "0.2",
} as const;

function independentCanonicalHash(value: unknown): string {
  const bytes = canonicalize(value);
  if (bytes === undefined) throw new TypeError("test preimage must be serializable");
  return `sha256:${createHash("sha256").update(bytes, "utf8").digest("hex")}`;
}

function withIndependentManifestHash<T extends Record<string, unknown>>(
  preimage: T,
): T & { manifest_hash: string } {
  return { ...preimage, manifest_hash: independentCanonicalHash(preimage) };
}

function runManifestPreimage() {
  return {
    schema_version: "0.2",
    run_id: "run_manifest_test",
    plan_hash: HASH_A,
    execution_profile: "bounded-v02",
    schema_versions: { ...EXACT_RUNTIME_INVENTORY_V02 },
    run_state: "running",
    created_at: "2026-08-10T10:00:00Z",
    projection_event_ref: REF_A,
    ledger_sequence: 3,
    ledger_head_hash: HASH_B,
    current_fence_epoch: 0,
    terminal: null,
    file_inventory: [
      {
        path: "artifact-manifest.json",
        family: "projection",
        required: false,
        exists: false,
        mode: null,
        size_bytes: null,
        hash: null,
      },
      {
        path: "ledger.jsonl",
        family: "primary",
        required: true,
        exists: true,
        mode: 384,
        size_bytes: 42,
        hash: HASH_C,
      },
    ],
  } as const;
}

function artifactRow(artifactRef: "alpha-artifact" | "zeta-artifact") {
  return {
    artifact_ref: artifactRef,
    producer_task_ref: "produce-artifact",
    producer_action_id: `action_${artifactRef.replace("-", "_")}`,
    artifact_path: `artifacts/content/${artifactRef}.txt`,
    artifact_record_hash: HASH_A,
    original_content_hash: HASH_B,
    current_content_ref: `artifacts/content/${artifactRef}.txt`,
    current_content_hash: HASH_B,
    size_bytes: 12,
    media_type: "text/plain",
    retention_class: "run",
    expires_at: null,
    quarantined: false,
    exportable: true,
    redaction_state: "original",
    source_event_ref: REF_A,
    state_event_ref: REF_B,
  } as const;
}

function artifactManifestPreimage() {
  return {
    schema_version: "0.2",
    run_id: "run_manifest_test",
    plan_hash: HASH_A,
    projection_event_ref: REF_B,
    ledger_sequence: 4,
    ledger_head_hash: HASH_D,
    artifacts: [artifactRow("alpha-artifact"), artifactRow("zeta-artifact")],
  } as const;
}

describe("S35 V02 runtime manifests", () => {
  it("accepts exactly the independently enumerated 19-key schema inventory", () => {
    expect(Object.keys(EXACT_RUNTIME_INVENTORY_V02)).toHaveLength(19);
    expect(RuntimeSchemaInventoryV02.safeParse(EXACT_RUNTIME_INVENTORY_V02).success).toBe(true);
    const { waiver: _waiver, ...missing } = EXACT_RUNTIME_INVENTORY_V02;
    expect(RuntimeSchemaInventoryV02.safeParse(missing).success).toBe(false);
    expect(
      RuntimeSchemaInventoryV02.safeParse({ ...EXACT_RUNTIME_INVENTORY_V02, invented: "0.2" }).success,
    ).toBe(false);
    expect(
      RuntimeSchemaInventoryV02.safeParse({ ...EXACT_RUNTIME_INVENTORY_V02, run_manifest: "0.1" }).success,
    ).toBe(false);
  });

  it("enforces the strict present/absent file-entry union and required presence", () => {
    const present = runManifestPreimage().file_inventory[1];
    const absent = runManifestPreimage().file_inventory[0];
    expect(RunManifestFileEntryV02.safeParse(present).success).toBe(true);
    expect(RunManifestFileEntryV02.safeParse(absent).success).toBe(true);
    expect(RunManifestFileEntryV02.safeParse({ ...absent, required: true }).success).toBe(false);
    expect(RunManifestFileEntryV02.safeParse({ ...absent, hash: HASH_A }).success).toBe(false);
    expect(RunManifestFileEntryV02.safeParse({ ...present, mode: 420 }).success).toBe(false);
    expect(RunManifestFileEntryV02.safeParse({ ...present, extra: true }).success).toBe(false);
  });

  it("validates run-manifest exact fields, ordering, seal consistency, and self-hash", () => {
    const manifest = withIndependentManifestHash(runManifestPreimage());
    expect(RunManifestV02.safeParse(manifest).success).toBe(true);

    const { created_at: _createdAt, ...missing } = manifest;
    expect(RunManifestV02.safeParse(missing).success).toBe(false);
    expect(RunManifestV02.safeParse({ ...manifest, invented: true }).success).toBe(false);
    expect(RunManifestV02.safeParse({ ...manifest, manifest_hash: HASH_E }).success).toBe(false);
    const crossedHead = { ...runManifestPreimage(), ledger_head_hash: HASH_E };
    expect(RunManifestV02.safeParse(withIndependentManifestHash(crossedHead)).success).toBe(false);

    const reversedPreimage = {
      ...runManifestPreimage(),
      file_inventory: [...runManifestPreimage().file_inventory].reverse(),
    };
    expect(RunManifestV02.safeParse(withIndependentManifestHash(reversedPreimage)).success).toBe(false);

    const duplicatePreimage = {
      ...runManifestPreimage(),
      file_inventory: [
        runManifestPreimage().file_inventory[0],
        runManifestPreimage().file_inventory[0],
      ],
    };
    expect(RunManifestV02.safeParse(withIndependentManifestHash(duplicatePreimage)).success).toBe(false);

    const sealedWithoutTerminal = { ...runManifestPreimage(), run_state: "sealed" };
    expect(RunManifestV02.safeParse(withIndependentManifestHash(sealedWithoutTerminal)).success).toBe(false);

    const terminalBeforeSeal = {
      ...runManifestPreimage(),
      terminal: {
        outcome: "completed",
        snapshot_hash: HASH_D,
        seal_event_ref: REF_B,
      },
    };
    expect(RunManifestV02.safeParse(withIndependentManifestHash(terminalBeforeSeal)).success).toBe(false);

    const sealedPreimage = {
      ...runManifestPreimage(),
      run_state: "sealed",
      terminal: { outcome: "completed", snapshot_hash: HASH_D, seal_event_ref: REF_A },
    } as const;
    expect(RunManifestV02.safeParse(withIndependentManifestHash(sealedPreimage)).success).toBe(true);
    const crossedSeal = {
      ...sealedPreimage,
      terminal: { ...sealedPreimage.terminal, seal_event_ref: REF_B },
    };
    expect(RunManifestV02.safeParse(withIndependentManifestHash(crossedSeal)).success).toBe(false);
  });

  it("validates artifact rows, ordering, exact fields, and self-hash", () => {
    const manifest = withIndependentManifestHash(artifactManifestPreimage());
    expect(ArtifactManifestV02.safeParse(manifest).success).toBe(true);

    const { projection_event_ref: _projectionRef, ...missing } = manifest;
    expect(ArtifactManifestV02.safeParse(missing).success).toBe(false);
    expect(ArtifactManifestV02.safeParse({ ...manifest, invented: true }).success).toBe(false);
    expect(ArtifactManifestV02.safeParse({ ...manifest, manifest_hash: HASH_E }).success).toBe(false);
    const crossedHead = { ...artifactManifestPreimage(), ledger_head_hash: HASH_E };
    expect(ArtifactManifestV02.safeParse(withIndependentManifestHash(crossedHead)).success).toBe(false);

    const reversedPreimage = {
      ...artifactManifestPreimage(),
      artifacts: [...artifactManifestPreimage().artifacts].reverse(),
    };
    expect(ArtifactManifestV02.safeParse(withIndependentManifestHash(reversedPreimage)).success).toBe(false);

    const duplicatePreimage = {
      ...artifactManifestPreimage(),
      artifacts: [artifactRow("alpha-artifact"), artifactRow("alpha-artifact")],
    };
    expect(ArtifactManifestV02.safeParse(withIndependentManifestHash(duplicatePreimage)).success).toBe(false);

    const rowWithUnknown = {
      ...artifactManifestPreimage(),
      artifacts: [{ ...artifactRow("alpha-artifact"), invented: true }],
    };
    expect(ArtifactManifestV02.safeParse(withIndependentManifestHash(rowWithUnknown)).success).toBe(false);
  });

  it("preserves parsing of the known V01 manifest fixtures", () => {
    const golden = join(process.cwd(), "tests", "golden", "manifests");
    const runV01 = JSON.parse(
      readFileSync(join(golden, "minimal-bugfix-success.run-manifest.json"), "utf8"),
    );
    const artifactsV01 = JSON.parse(
      readFileSync(join(golden, "minimal-bugfix-success.artifact-manifest.json"), "utf8"),
    );
    expect(RunManifest.safeParse(runV01).success).toBe(true);
    expect(ArtifactManifest.safeParse(artifactsV01).success).toBe(true);
  });
});

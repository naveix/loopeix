import { generateKeyPairSync } from "node:crypto";
import { chmodSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import { inspectRuntimePlanV03 } from "../../src/run/project-plan-v03.js";
import {
  captureAuthorityTrustContextV02,
} from "../../src/run/runtime-record-admission-v02.js";
import { captureRuntimeFileStoreV04 } from "../../src/run/runtime-file-store-v04.js";
import {
  captureRuntimeClockSourceV04,
  observeRuntimeClockV04,
} from "../../src/run/runtime-clock-observation-v04.js";
import { inspectRuntimeLedgerV04 } from "../../src/run/runtime-ledger-v04.js";
import { buildRunManifestV04, inspectRunManifestV04 } from "../../src/run/runtime-manifest-v04.js";
import {
  buildRuntimeTerminalProjectionV04,
  evaluateRuntimeTerminalV04,
} from "../../src/run/runtime-terminal-v04.js";
import { writeRuntimeTerminalV04 } from "../../src/run/runtime-terminal-write-v04.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../../src/schema/runtime-v04.js";
import { createRuntimeCommandFixtureV04 } from "../helpers/runtime-v04-command-fixture.js";

const UTF8 = new TextEncoder();
const H = (character: string): string => `sha256:${character.repeat(64)}`;

function write0600(path: string, bytes: Uint8Array): void {
  writeFileSync(path, bytes, { mode: 0o600 });
  chmodSync(path, 0o600);
}

function ref(event: RuntimeEventV04Value) {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function append(
  events: RuntimeEventV04Value[],
  runId: string,
  eventType: RuntimeEventV04Value["event_type"],
  source: RuntimeEventV04Value["source"],
  authorityRef: string | null,
  payload: unknown,
) {
  const sequence = events.length + 1;
  const preimage = {
    schema_version: "0.4",
    event_id: `event_terminal_write_s41_${sequence}`,
    run_id: runId,
    sequence,
    recorded_at: `2026-08-30T17:00:${String(sequence).padStart(2, "0")}Z`,
    event_type: eventType,
    source,
    authority_ref: authorityRef,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: events.at(-1)?.event_hash ?? null,
    payload,
  };
  const event = RuntimeEventV04.parse({ ...preimage, event_hash: hashCanonical(preimage) });
  events.push(event);
  return event;
}

function trustContext() {
  const { publicKey } = generateKeyPairSync("ed25519");
  const trust = captureAuthorityTrustContextV02({
    observed_at: "2026-08-30T17:30:00Z",
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [{
      context_version: "0.1",
      trust_domain: "local-operator",
      approval_channel: "local-ed25519",
      authenticated_principal_ref: "operator_terminal_write_s41",
      credential_ref: "operator_key_terminal_write_s41",
      channel_subject_hash: H("1"),
      session_binding_hash: H("2"),
      assurance_level: "phishing-resistant",
    }],
    operator_keys: [{
      operator_key_id: "operator_key_terminal_write_s41",
      authenticated_principal_ref: "operator_terminal_write_s41",
      trust_domain: "local-operator",
      public_key_spki_base64: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
      effective_from: "2026-08-30T17:00:00Z",
      effective_until: "2026-08-30T18:00:00Z",
      revoked_at: null,
    }],
    platform_channel_verifiers: [],
    host_producer_keys: [],
    authority_epochs: [{
      authenticated_principal_ref: "operator_terminal_write_s41",
      revocation_epoch: 0,
      effective_from: "2026-08-30T17:00:00Z",
    }],
    durable_nonce_consumptions: [],
  });
  if (!trust.ok) throw new Error(trust.error);
  return trust.value;
}

function writeEvents(root: string, events: readonly RuntimeEventV04Value[]) {
  const planBytes = new Uint8Array(readFileSync(join(root, "resolved-run-plan.json")));
  const ledgerBytes = UTF8.encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const capturedFiles = [
    { path: "ledger.jsonl", family: "primary" as const, required: true, mode: 384 as const, bytes: ledgerBytes },
    { path: "resolved-run-plan.json", family: "primary" as const, required: true, mode: 384 as const, bytes: planBytes },
  ];
  const manifestBuilt = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: "2026-08-30T17:01:00Z",
    captured_files: capturedFiles,
  });
  if (!manifestBuilt.ok) throw new Error(manifestBuilt.reason);
  write0600(join(root, "ledger.jsonl"), ledgerBytes);
  write0600(join(root, "run-manifest.json"), manifestBuilt.bytes);
}

function appendAbortToRoot(root: string) {
  const inspected = inspectRoot(root);
  const events = [...inspected.ledger.events];
  append(events, inspected.plan.run_id, "control.abort-requested", "operator", "authority_terminal_write_s41", {
    request_id: "abort_terminal_write_s41",
    requested_by: "operator",
    reason_code: "operator-requested",
    policy_decision_ref: null,
    evidence_refs: [],
  });
  writeEvents(root, events);
}

function inspectRoot(root: string) {
  const planBytes = new Uint8Array(readFileSync(join(root, "resolved-run-plan.json")));
  const ledgerBytes = new Uint8Array(readFileSync(join(root, "ledger.jsonl")));
  const manifestBytes = new Uint8Array(readFileSync(join(root, "run-manifest.json")));
  const plan = inspectRuntimePlanV03(planBytes);
  const ledger = inspectRuntimeLedgerV04(ledgerBytes);
  if (!plan.ok || !ledger.ok) throw new Error("inspection failed");
  const manifest = inspectRunManifestV04({
    manifest_bytes: manifestBytes,
    ledger_bytes: ledgerBytes,
    captured_files: [
      { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledgerBytes },
      { path: "resolved-run-plan.json", family: "primary", required: true, mode: 384, bytes: planBytes },
    ],
  });
  if (!manifest.ok) throw new Error(manifest.reason);
  return {
    plan: plan.validated_plan,
    ledger: manifest.ledger,
    manifest: manifest.validated_manifest,
  };
}

function projectionFor(root: string) {
  const inspected = inspectRoot(root);
  const built = buildRuntimeTerminalProjectionV04({
    validated_plan: inspected.plan,
    ledger: inspected.ledger,
    manifest: inspected.manifest,
    authority_trust_context: trustContext(),
  });
  if (!built.ok) throw new Error(built.reason);
  return {
    projection: built.value,
    inspected,
  };
}

function observation(observedAt: string, elapsedMs: number) {
  const source = captureRuntimeClockSourceV04({
    boot_identity: "boot_terminal_write_s41",
    monotonic_clock_id: "mono_terminal_write_observer_s41",
    observe: () => ({ observed_at: observedAt, elapsed_ms: elapsedMs }),
  });
  if (source === null) throw new Error("clock source capture failed");
  const sampled = observeRuntimeClockV04(source);
  if (!sampled.ok) throw new Error(sampled.error);
  return sampled.value;
}

describe("S41 V04 terminal durable writes", () => {
  it("commits the first terminal freeze from a genuine abort projection", async () => {
    const fixture = createRuntimeCommandFixtureV04();
    try {
      const root = realpathSync(fixture.root);
      appendAbortToRoot(root);
      const built = projectionFor(root);
      expect(evaluateRuntimeTerminalV04(built.projection)).toMatchObject({
        decision: "freeze-work",
        candidate: "aborted",
      });

      const captured = await captureRuntimeFileStoreV04({ run_directory: root });
      if (!captured.ok) throw new Error(captured.error);

      const result = await writeRuntimeTerminalV04(captured.store, {
        projection: built.projection,
        observation: observation("2026-08-30T17:00:30Z", 30),
        event_id: "freeze_terminal_write_s41",
      });

      expect(result).toMatchObject({
        ok: true,
        classification: "COMMITTED",
        action: "FREEZE_ENTERED",
      });

      const after = inspectRoot(root);
      expect(after.ledger.events.at(-1)).toMatchObject({
        event_type: "run.terminal-freeze-entered",
        payload: {
          revision: 1,
          candidate: "aborted",
          fence_epoch: 0,
        },
      });
    } finally {
      fixture.cleanup();
    }
  });

  it("seals exactly the unchanged frozen prefix with the evaluator-derived snapshot hash and next fence", async () => {
    const fixture = createRuntimeCommandFixtureV04();
    try {
      const root = realpathSync(fixture.root);
      appendAbortToRoot(root);
      const freezeProjection = projectionFor(root).projection;
      const firstStore = await captureRuntimeFileStoreV04({ run_directory: root });
      if (!firstStore.ok) throw new Error(firstStore.error);
      const frozen = await writeRuntimeTerminalV04(firstStore.store, {
        projection: freezeProjection,
        observation: observation("2026-08-30T17:00:30Z", 30),
        event_id: "freeze_before_seal_s41",
      });
      expect(frozen).toMatchObject({ ok: true, action: "FREEZE_ENTERED" });

      const sealProjection = projectionFor(root).projection;
      const decision = evaluateRuntimeTerminalV04(sealProjection);
      expect(decision).toMatchObject({ decision: "seal", outcome: "aborted", current_fence_epoch: 0, next_fence_epoch: 1 });
      if (decision.decision !== "seal") return;
      const secondStore = await captureRuntimeFileStoreV04({ run_directory: root });
      if (!secondStore.ok) throw new Error(secondStore.error);
      const sealed = await writeRuntimeTerminalV04(secondStore.store, {
        projection: sealProjection,
        observation: observation("2026-08-30T17:00:31Z", 31),
        event_id: "seal_terminal_write_s41",
      });
      expect(sealed).toMatchObject({ ok: true, classification: "COMMITTED", action: "SEALED" });

      const after = inspectRoot(root);
      expect(after.ledger.events.at(-1)).toMatchObject({
        event_type: "run.terminal-sealed",
        payload: {
          outcome: "aborted",
          pre_seal_ledger_sequence: decision.expected_ledger_sequence,
          pre_seal_ledger_head_hash: decision.expected_ledger_head_hash,
          pre_seal_snapshot_hash: decision.pre_seal_snapshot_hash,
          previous_fence_epoch: 0,
          fence_epoch: 1,
        },
      });
      expect(after.ledger.state.state).toBe("sealed");
    } finally {
      fixture.cleanup();
    }
  });
});

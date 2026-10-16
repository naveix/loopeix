import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import { inspectRuntimePlanV03 } from "../../src/run/project-plan-v03.js";
import { captureAuthorityTrustContextV02 } from "../../src/run/runtime-record-admission-v02.js";
import { inspectRunManifestV04 } from "../../src/run/runtime-manifest-v04.js";
import { RuntimeEventV02 } from "../../src/schema/runtime.js";
import {
  buildRuntimeTerminalProjectionV04,
  evaluateRuntimeTerminalV04,
  isRuntimeTerminalProjectionV04,
} from "../../src/run/runtime-terminal-v04.js";
import { isTerminalObservationSnapshotV02 } from "../../src/run/terminal-snapshot.js";
import { createRuntimeCommandFixtureV04 } from "../helpers/runtime-v04-command-fixture.js";

function admittedSource(options: Readonly<{ paused?: boolean }> = {}) {
  const fixture = createRuntimeCommandFixtureV04(options);
  const ledgerBytes = new Uint8Array(readFileSync(join(fixture.root, "ledger.jsonl")));
  const planBytes = new Uint8Array(readFileSync(join(fixture.root, "resolved-run-plan.json")));
  const plan = inspectRuntimePlanV03(planBytes);
  const manifest = inspectRunManifestV04({
    manifest_bytes: new Uint8Array(readFileSync(join(fixture.root, "run-manifest.json"))),
    ledger_bytes: ledgerBytes,
    captured_files: [
      { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledgerBytes },
      { path: "resolved-run-plan.json", family: "primary", required: true, mode: 384, bytes: planBytes },
    ],
  });
  const { publicKey } = generateKeyPairSync("ed25519");
  const trust = captureAuthorityTrustContextV02({
    observed_at: "2026-08-30T15:02:00Z",
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [{
      context_version: "0.1", trust_domain: "local-operator", approval_channel: "local-ed25519",
      authenticated_principal_ref: "operator_terminal_s41", credential_ref: "operator_key_terminal_s41",
      channel_subject_hash: `sha256:${"1".repeat(64)}`, session_binding_hash: `sha256:${"2".repeat(64)}`,
      assurance_level: "phishing-resistant",
    }],
    operator_keys: [{
      operator_key_id: "operator_key_terminal_s41", authenticated_principal_ref: "operator_terminal_s41",
      trust_domain: "local-operator", public_key_spki_base64: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
      effective_from: "2026-08-30T15:00:00Z", effective_until: "2026-08-30T16:00:00Z", revoked_at: null,
    }],
    platform_channel_verifiers: [], host_producer_keys: [],
    authority_epochs: [{ authenticated_principal_ref: "operator_terminal_s41", revocation_epoch: 0, effective_from: "2026-08-30T15:00:00Z" }],
    durable_nonce_consumptions: [],
  });
  if (!plan.ok || !manifest.ok || !trust.ok) throw new Error("fixture admission failed");
  return { fixture, plan: plan.validated_plan, ledger: manifest.ledger, manifest: manifest.validated_manifest, trust: trust.value };
}

describe("S41 V04 terminal read bridge", () => {
  it("issues only its own opaque projection and evaluates an admitted open run", () => {
    const source = admittedSource();
    try {
      const built = buildRuntimeTerminalProjectionV04({
        validated_plan: source.plan, ledger: source.ledger, manifest: source.manifest,
        authority_trust_context: source.trust,
      });
      expect(built).toMatchObject({ ok: true });
      if (!built.ok) return;
      expect(isRuntimeTerminalProjectionV04(built.value)).toBe(true);
      expect(isTerminalObservationSnapshotV02(built.value)).toBe(false);
      expect(evaluateRuntimeTerminalV04(built.value)).toEqual({ decision: "continue", continuation: "work-open" });
      expect(isRuntimeTerminalProjectionV04({ ...built.value })).toBe(false);
      expect(() => evaluateRuntimeTerminalV04({ ...built.value })).toThrow(TypeError);
    } finally {
      source.fixture.cleanup();
    }
  });

  it("rejects raw family forgeries and mismatched manifest/ledger boundaries", () => {
    const first = admittedSource();
    const later = admittedSource({ paused: true });
    try {
      const base = {
        validated_plan: first.plan, ledger: first.ledger, manifest: first.manifest,
        authority_trust_context: first.trust,
      };
      expect(buildRuntimeTerminalProjectionV04({ ...base, validated_plan: { ...first.plan } }))
        .toEqual({ ok: false, reason: "RUNTIME_TERMINAL_INPUT_INVALID" });
      expect(buildRuntimeTerminalProjectionV04({ ...base, ledger: { ...first.ledger } }))
        .toEqual({ ok: false, reason: "RUNTIME_TERMINAL_INPUT_INVALID" });
      expect(buildRuntimeTerminalProjectionV04({ ...base, manifest: { ...first.manifest } }))
        .toEqual({ ok: false, reason: "RUNTIME_TERMINAL_INPUT_INVALID" });
      expect(buildRuntimeTerminalProjectionV04({ ...base, authority_trust_context: { ...first.trust } }))
        .toEqual({ ok: false, reason: "RUNTIME_TERMINAL_INPUT_INVALID" });
      expect(buildRuntimeTerminalProjectionV04({ ...base, manifest: later.manifest }))
        .toEqual({ ok: false, reason: "RUNTIME_TERMINAL_INPUT_INVALID" });
      expect(buildRuntimeTerminalProjectionV04({ ...base, ledger: later.ledger }))
        .toEqual({ ok: false, reason: "RUNTIME_TERMINAL_INPUT_INVALID" });
    } finally {
      first.fixture.cleanup();
      later.fixture.cleanup();
    }
  });

  it("down-projects only V02-compatible ledger events into the terminal evaluator boundary", () => {
    const source = admittedSource({ paused: true });
    try {
      const built = buildRuntimeTerminalProjectionV04({
        validated_plan: source.plan,
        ledger: source.ledger,
        manifest: source.manifest,
        authority_trust_context: source.trust,
      });
      expect(built).toMatchObject({ ok: true });
      if (!built.ok) return;

      expect(isRuntimeTerminalProjectionV04(built.value)).toBe(true);
      expect(isTerminalObservationSnapshotV02(built.value)).toBe(false);
      expect(evaluateRuntimeTerminalV04(built.value)).toEqual({ decision: "continue", continuation: "work-open" });
      expect(RuntimeEventV02.safeParse(source.ledger.events[0]).success).toBe(false);
    } finally {
      source.fixture.cleanup();
    }
  });
});

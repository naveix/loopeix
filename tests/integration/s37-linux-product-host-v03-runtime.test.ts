import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  simulateAuthorityDecisionV02,
} from "../../src/run/action-classifier-policy-v02.js";
import {
  createS37LocalLinuxProductProbeV03ForTest,
  runS37LocalLinuxProductProbeV03,
} from "../../src/run/linux-host-enforcement-v03.js";
import {
  admitS37LinuxLaunchQualificationV03,
  captureS37QualificationBootObserverV03,
  captureS37QualificationIssuerSignerV03,
  issueS37LinuxLaunchQualificationV03,
} from "../../src/run/s37-linux-launch-qualification-v03.js";
import { buildS37ActionInterpositionProfileV02 } from "../../src/run/pre-spawn-capability-broker-v02.js";
import { H, hashV03, makeAnchorV03 } from "../helpers/s37-product-host-v03-fixtures.js";

const DENY_ROWS = [
  "ambient-credentials", "child-process", "durable-state", "environment",
  "filesystem-write", "network", "output-limits", "retry", "stdin",
  "timeout", "tool-server", "unknown-outcome",
] as const;

function runtimeFixture() {
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const issuer = Object.freeze({
    key_ref: "qualification_key_1",
    algorithm: "ed25519",
    public_key_spki_base64: pair.publicKey.toString("base64"),
    public_key_spki_sha256: `sha256:${createHash("sha256").update(pair.publicKey).digest("hex")}`,
  });
  const base = makeAnchorV03();
  const subject = {
    schema_version: base.schema_version,
    product_profile: base.product_profile,
    runtime_profile_version: base.runtime_profile_version,
    runtime_profile_hash: base.runtime_profile_hash,
    host_role: base.host_role,
    transport: base.transport,
    host: base.host,
    artifacts: base.artifacts,
    cwd: base.cwd,
    install_bundle_hash: base.install_bundle_hash,
    qualification_issuer: issuer,
    generation: base.generation,
    predecessor_anchor_hash: base.predecessor_anchor_hash,
  };
  const anchorSubjectHash = hashV03({ purpose: "s37-local-product-host-anchor-subject-v03", ...subject });
  const anchorWithoutHash = {
    ...subject,
    anchor_subject_hash: anchorSubjectHash,
    operator_authority: { ...base.operator_authority, authorization_subject_hash: anchorSubjectHash },
    installed_at: base.installed_at,
  };
  const anchor = Object.freeze({
    ...anchorWithoutHash,
    anchor_hash: hashV03({ purpose: "s37-local-product-host-anchor-v03", ...anchorWithoutHash }),
  });
  const decisionInput = {
    proposal: {
      action_proposal_id: "proposal_s37_v03_probe",
      action_proposal_hash: H("a"),
      action_class: "task" as const,
      policy_action_kind: "deterministic-no-side-effect-check" as const,
      action_approval_class: "automatic" as const,
      policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
      action_scope_hash: H("a"), normalized_dispatch_hash: H("a"), repository_pre_state_hash: H("a"),
      classifier_rule_hash: H("a"), data_flow_hash: H("a"), effective_risk_tier: "T1" as const,
    },
    reviewer_view_hash: H("a"),
    reviewed_through_ref: { ledger_sequence: 1, event_hash: H("a") },
    recommendations: [],
    authority: { envelope_verified: true, contained: true, proof_fresh: true, revocation_epoch_current: true },
    enforcement: { available: true, information_flow_allowed: true, gates_passed: true, immediate_revalidation_passed: true },
    condition_results: [],
    issued_at: "2026-08-23T12:00:00Z",
    expires_at: "2026-08-23T12:01:00Z",
    fence_epoch: 0,
  } as const;
  const simulated = simulateAuthorityDecisionV02(decisionInput);
  if (!simulated.ok || simulated.value.simulated_lease === null) throw new Error("invalid decision fixture");
  const requestWithoutHash = {
    schema_version: "s37-product-host-qualification-request-v01",
    product_profile: anchor.product_profile,
    anchor_hash: anchor.anchor_hash,
    anchor_generation: anchor.generation,
    runtime_profile_hash: anchor.runtime_profile_hash,
    action_proposal_hash: decisionInput.proposal.action_proposal_hash,
    decision_input_hash: hashV03({ purpose: "s37-product-host-decision-input-v01", decision_input: decisionInput }),
    decision_simulation_hash: simulated.value.decision_simulation_hash,
    lease_simulation_hash: simulated.value.simulated_lease.lease_simulation_hash,
    launch_nonce: H("b"),
    requested_at: "2026-08-23T12:00:00Z",
    expires_at: "2026-08-23T12:10:00Z",
  };
  const request = Object.freeze({
    ...requestWithoutHash,
    request_hash: hashV03({ purpose: requestWithoutHash.schema_version, ...requestWithoutHash }),
  });
  const profile = buildS37ActionInterpositionProfileV02({
    actor_identity_hash: H("d"),
    on_behalf_of_chain_hash: H("e"),
    executable: { path: "/opt/loopeix/s37.1/probe", sha256: anchor.artifacts.probe.sha256 },
    cwd: anchor.cwd,
  });
  const tuple = Object.freeze({
    tuple_version: "0.1" as const,
    platform: "linux" as const,
    architecture: anchor.host.architecture,
    kernel_release: anchor.host.kernel_release,
    systemd_version: anchor.host.systemd_version,
    cgroup_version: "v2" as const,
    observed_at: "2026-08-23T12:00:10Z",
  });
  const receiptWithoutHash = {
    receipt_version: "0.1" as const,
    host_tuple_hash: hashCanonical({ purpose: "s37-linux-host-tuple-v02", ...tuple }),
    profile_hash: hashCanonical(profile),
    launcher_sha256: anchor.artifacts.supervisor.sha256,
    bwrap: {
      path: anchor.artifacts.bwrap.path,
      version: anchor.artifacts.bwrap.version,
      sha256: anchor.artifacts.bwrap.sha256,
      setuid: false as const,
    },
    seccomp_policy_sha256: anchor.artifacts.embedded_seccomp_policy_sha256,
    deny_rows: [...DENY_ROWS],
    skipped_rows: [] as const,
    issued_at: "2026-08-23T12:00:10Z",
    expires_at: "2026-08-23T12:00:35Z",
  };
  const receipt = Object.freeze({
    ...receiptWithoutHash,
    receipt_hash: hashCanonical({ purpose: "s37-linux-backend-identity-receipt-v02", ...receiptWithoutHash }),
  });
  const observation = Object.freeze({
    observed_at: "2026-08-23T12:00:20Z",
    boot_id_hash: H("c"),
    host: anchor.host,
    runtime_profile_hash: anchor.runtime_profile_hash,
    phase_b: Object.freeze({
      manifest_sha256: H("1"), readiness_evidence_sha256: H("2"), readiness_envelope_sha256: H("3"),
      conformance_evidence_sha256: H("4"), receipt_hash: receipt.receipt_hash,
    }),
    artifacts: anchor.artifacts,
    deny_witnesses: Object.freeze(DENY_ROWS.map((row, index) => Object.freeze({
      row, witness_sha256: H(String((index % 9) + 1)),
    }))),
  });
  const issued = issueS37LinuxLaunchQualificationV03({
    anchor,
    qualification_request: request,
    decision_input: decisionInput,
    decision: simulated.value,
    simulated_lease: simulated.value.simulated_lease,
  }, {
    signer: captureS37QualificationIssuerSignerV03(issuer.key_ref, pair.privateKey),
    boot_observer: captureS37QualificationBootObserverV03(() => ({ ...observation, observed_at: "2026-08-23T12:00:10Z" })),
  });
  if (!issued.ok) throw new Error("qualification issue failed");
  const admitted = admitS37LinuxLaunchQualificationV03({
    qualification: issued.value,
    anchor,
    qualification_request: request,
    decision_input: decisionInput,
    decision: simulated.value,
    simulated_lease: simulated.value.simulated_lease,
    observation,
  });
  if (!admitted.ok) throw new Error("qualification admission failed");
  return Object.freeze({
    authorization: admitted.value,
    anchor,
    observation,
    input: Object.freeze({
      qualification: admitted.value,
      profile,
      conformance_tuple: tuple,
      backend_receipt: receipt,
      phase_b_manifest_sha256: observation.phase_b.manifest_sha256,
    }),
  });
}

const injectedRuntimeOutcome = Object.freeze({
  ok: true as const,
  process_started: true as const,
  exit_code: 0,
  signal: null,
  timed_out: false,
  kill_attempted: false,
  reaped: true,
  forbidden_effect_denied: false,
  outcome_ambiguous: false,
  stdout: new Uint8Array(),
  stderr: new Uint8Array(),
});

const successfulOwnerOutcome = Object.freeze({
  ok: true as const,
  process_started: true as const,
  terminal: "completed" as const,
  outcome: "exited" as const,
  exit_code: 0,
  signal: null,
  stdout: new Uint8Array(),
  stderr: new Uint8Array(),
});

function stableCustody(fixture: ReturnType<typeof runtimeFixture>) {
  return Object.freeze({
    ok: true as const,
    status: "STABLE" as const,
    generation: fixture.anchor.generation,
    anchor_hash: fixture.anchor.anchor_hash,
  });
}

describe("S37.1-F4 synthetic-only V03 runtime", () => {
  it("reaches the existing V02 owner exactly once after two exact observations", async () => {
    const fixture = runtimeFixture();
    const custody = vi.fn(() => stableCustody(fixture));
    const observe = vi.fn(() => fixture.observation);
    const start = vi.fn(async () => injectedRuntimeOutcome);
    const run = createS37LocalLinuxProductProbeV03ForTest({
      observe_custody: custody,
      observe_host: observe,
      runtime: { start },
    });

    await expect(run(fixture.input)).resolves.toEqual(successfulOwnerOutcome);
    expect(custody).toHaveBeenCalledTimes(2);
    expect(observe).toHaveBeenCalledTimes(2);
    expect(start).toHaveBeenCalledTimes(1);
  });

  it.each(["first-custody", "first-host", "second-custody", "second-host", "observer-throw"] as const)(
    "returns confirmed-not-started HOLD with zero launcher calls on %s failure",
    async (failure) => {
      const fixture = runtimeFixture();
      let custodyCount = 0;
      let hostCount = 0;
      const start = vi.fn(async () => injectedRuntimeOutcome);
      const run = createS37LocalLinuxProductProbeV03ForTest({
        observe_custody: () => {
          custodyCount += 1;
          if (failure === "observer-throw" && custodyCount === 1) throw new Error("observer failed");
          if (failure === "first-custody" && custodyCount === 1) return { ...stableCustody(fixture), status: "PREPARING" };
          if (failure === "second-custody" && custodyCount === 2) return { ...stableCustody(fixture), anchor_hash: H("f") };
          return stableCustody(fixture);
        },
        observe_host: () => {
          hostCount += 1;
          if (failure === "first-host" && hostCount === 1) return { ...fixture.observation, boot_id_hash: H("f") };
          if (failure === "second-host" && hostCount === 2) return { ...fixture.observation, observed_at: "2026-08-23T12:00:21Z" };
          return fixture.observation;
        },
        runtime: { start },
      });
      await expect(run(fixture.input)).resolves.toEqual({
        ok: false, reason: "ENFORCEMENT_UNAVAILABLE", terminal: "hold", retryable: false, process_started: false,
      });
      expect(start).toHaveBeenCalledTimes(0);
    },
  );

  it("denies replay and concurrent reuse of one synthetic factory", async () => {
    const fixture = runtimeFixture();
    let releaseFirst!: () => void;
    const gate = new Promise<void>((resolve) => { releaseFirst = resolve; });
    let first = true;
    const start = vi.fn(async () => injectedRuntimeOutcome);
    const run = createS37LocalLinuxProductProbeV03ForTest({
      observe_custody: async () => { if (first) { first = false; await gate; } return stableCustody(fixture); },
      observe_host: () => fixture.observation,
      runtime: { start },
    });
    const active = run(fixture.input);
    await expect(run(fixture.input)).resolves.toEqual({
      ok: false, reason: "ENFORCEMENT_UNAVAILABLE", terminal: "hold", retryable: false, process_started: false,
    });
    releaseFirst();
    await expect(active).resolves.toEqual(successfulOwnerOutcome);
    await expect(run(fixture.input)).resolves.toEqual({
      ok: false, reason: "ENFORCEMENT_UNAVAILABLE", terminal: "hold", retryable: false, process_started: false,
    });
    expect(start).toHaveBeenCalledTimes(1);
  });

  it("production HOLD does not consume qualification or invoke synthetic capabilities", async () => {
    const fixture = runtimeFixture();
    await expect(runS37LocalLinuxProductProbeV03(fixture.input)).resolves.toEqual({
      ok: false, reason: "ENFORCEMENT_UNAVAILABLE", terminal: "hold", retryable: false, process_started: false,
    });
    const start = vi.fn(async () => injectedRuntimeOutcome);
    const run = createS37LocalLinuxProductProbeV03ForTest({
      observe_custody: () => stableCustody(fixture),
      observe_host: () => fixture.observation,
      runtime: { start },
    });
    await expect(run(fixture.input)).resolves.toEqual(successfulOwnerOutcome);
    expect(start).toHaveBeenCalledTimes(1);
  });
});

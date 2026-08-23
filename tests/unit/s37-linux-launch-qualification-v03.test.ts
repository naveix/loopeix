import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  simulateAuthorityDecisionV02,
} from "../../src/run/action-classifier-policy-v02.js";
import {
  admitS37LinuxLaunchQualificationV03,
  captureS37QualificationBootObserverV03,
  captureS37QualificationIssuerSignerV03,
  consumeAuthorizedS37LinuxLaunchQualificationV03,
  issueS37LinuxLaunchQualificationV03,
} from "../../src/run/s37-linux-launch-qualification-v03.js";
import {
  H,
  hashV03,
  makeAnchorV03,
} from "../helpers/s37-product-host-v03-fixtures.js";

const DENY_ROWS = [
  "ambient-credentials", "child-process", "durable-state", "environment",
  "filesystem-write", "network", "output-limits", "retry", "stdin",
  "timeout", "tool-server", "unknown-outcome",
] as const;

function qualificationFixture() {
  const keyPair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const issuer = Object.freeze({
    key_ref: "qualification_key_1",
    algorithm: "ed25519",
    public_key_spki_base64: keyPair.publicKey.toString("base64"),
    public_key_spki_sha256: `sha256:${createHash("sha256").update(keyPair.publicKey).digest("hex")}`,
  });
  const baseAnchor = makeAnchorV03();
  const subject = {
    schema_version: baseAnchor.schema_version,
    product_profile: baseAnchor.product_profile,
    runtime_profile_version: baseAnchor.runtime_profile_version,
    runtime_profile_hash: baseAnchor.runtime_profile_hash,
    host_role: baseAnchor.host_role,
    transport: baseAnchor.transport,
    host: baseAnchor.host,
    artifacts: baseAnchor.artifacts,
    cwd: baseAnchor.cwd,
    install_bundle_hash: baseAnchor.install_bundle_hash,
    qualification_issuer: issuer,
    generation: baseAnchor.generation,
    predecessor_anchor_hash: baseAnchor.predecessor_anchor_hash,
  };
  const anchorSubjectHash = hashV03({
    purpose: "s37-local-product-host-anchor-subject-v03",
    ...subject,
  });
  const operatorAuthority = {
    ...baseAnchor.operator_authority,
    authorization_subject_hash: anchorSubjectHash,
  };
  const anchorWithoutHash = {
    ...subject,
    anchor_subject_hash: anchorSubjectHash,
    operator_authority: operatorAuthority,
    installed_at: baseAnchor.installed_at,
  };
  const anchor = Object.freeze({
    ...anchorWithoutHash,
    anchor_hash: hashV03({ purpose: "s37-local-product-host-anchor-v03", ...anchorWithoutHash }),
  });
  const decisionInput = {
    proposal: {
      action_proposal_id: "proposal_s37_local_probe",
      action_proposal_hash: H("a"),
      action_class: "task" as const,
      policy_action_kind: "deterministic-no-side-effect-check" as const,
      action_approval_class: "automatic" as const,
      policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
      action_scope_hash: H("a"),
      normalized_dispatch_hash: H("a"),
      repository_pre_state_hash: H("a"),
      classifier_rule_hash: H("a"),
      data_flow_hash: H("a"),
      effective_risk_tier: "T1" as const,
    },
    reviewer_view_hash: H("a"),
    reviewed_through_ref: { ledger_sequence: 1, event_hash: H("a") },
    recommendations: [],
    authority: {
      envelope_verified: true, contained: true, proof_fresh: true, revocation_epoch_current: true,
    },
    enforcement: {
      available: true, information_flow_allowed: true, gates_passed: true, immediate_revalidation_passed: true,
    },
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
    decision_input_hash: hashV03({
      purpose: "s37-product-host-decision-input-v01",
      decision_input: decisionInput,
    }),
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
  const observation = Object.freeze({
    observed_at: "2026-08-23T12:00:10Z",
    boot_id_hash: H("c"),
    host: anchor.host,
    runtime_profile_hash: anchor.runtime_profile_hash,
    phase_b: Object.freeze({
      manifest_sha256: H("1"),
      readiness_evidence_sha256: H("2"),
      readiness_envelope_sha256: H("3"),
      conformance_evidence_sha256: H("4"),
      receipt_hash: H("5"),
    }),
    artifacts: anchor.artifacts,
    deny_witnesses: Object.freeze(DENY_ROWS.map((row, index) => Object.freeze({
      row,
      witness_sha256: H(String((index % 9) + 1)),
    }))),
  });
  return {
    anchor,
    request,
    decisionInput,
    decision: simulated.value,
    lease: simulated.value.simulated_lease,
    observation,
    signer: captureS37QualificationIssuerSignerV03(issuer.key_ref, keyPair.privateKey),
    observer: captureS37QualificationBootObserverV03(() => observation),
  };
}

describe("S37.1-F4 launch qualification authority", () => {
  it("issues, admits, and consumes one complete immutable qualification binding", () => {
    const fixture = qualificationFixture();
    const issued = issueS37LinuxLaunchQualificationV03({
      anchor: fixture.anchor,
      qualification_request: fixture.request,
      decision_input: fixture.decisionInput,
      decision: fixture.decision,
      simulated_lease: fixture.lease,
    }, {
      signer: fixture.signer,
      boot_observer: fixture.observer,
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;
    expect(issued.value.expires_at).toBe("2026-08-23T12:00:40Z");

    const admitted = admitS37LinuxLaunchQualificationV03({
      qualification: issued.value,
      anchor: fixture.anchor,
      qualification_request: fixture.request,
      decision_input: fixture.decisionInput,
      decision: fixture.decision,
      simulated_lease: fixture.lease,
      observation: { ...fixture.observation, observed_at: "2026-08-23T12:00:20Z" },
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;

    const consumed = consumeAuthorizedS37LinuxLaunchQualificationV03(admitted.value);
    expect(consumed?.qualification).toEqual(issued.value);
    expect(consumed?.anchor).toEqual(fixture.anchor);
    expect(consumed?.qualification_request).toEqual(fixture.request);
    expect(consumed?.decision).toEqual(fixture.decision);
    expect(consumed?.simulated_lease).toEqual(fixture.lease);
    expect(Object.isFrozen(consumed)).toBe(true);
    expect(Object.isFrozen(consumed?.qualification)).toBe(true);
    expect(consumeAuthorizedS37LinuxLaunchQualificationV03(admitted.value)).toBeNull();
  });

  it("rejects hostile issuer inputs with one content-free failure", () => {
    const fixture = qualificationFixture();
    const validInput = {
      anchor: fixture.anchor,
      qualification_request: fixture.request,
      decision_input: fixture.decisionInput,
      decision: fixture.decision,
      simulated_lease: fixture.lease,
    };
    const otherPair = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const otherSigner = captureS37QualificationIssuerSignerV03("qualification_key_1", otherPair.privateKey);
    let observationCount = 0;
    const bootDriftObserver = captureS37QualificationBootObserverV03(() => {
      observationCount += 1;
      return observationCount === 1
        ? fixture.observation
        : { ...fixture.observation, boot_id_hash: H("f") };
    });
    const invalidDecisionInput = {
      ...fixture.decisionInput,
      proposal: { ...fixture.decisionInput.proposal, policy_action_kind: "filesystem-write" },
    };
    const cases: ReadonlyArray<readonly [string, unknown, Readonly<{
      signer: typeof fixture.signer;
      boot_observer: typeof fixture.observer;
    }>]> = [
      ["raw private key", { ...validInput, private_key: "forbidden" }, { signer: fixture.signer, boot_observer: fixture.observer }],
      ["raw signer callback", { ...validInput, sign: () => "forbidden" }, { signer: fixture.signer, boot_observer: fixture.observer }],
      ["raw boot id", { ...validInput, boot_id_hash: H("f") }, { signer: fixture.signer, boot_observer: fixture.observer }],
      ["raw time", { ...validInput, now: "2026-08-23T12:00:10Z" }, { signer: fixture.signer, boot_observer: fixture.observer }],
      ["raw expiry", { ...validInput, expires_at: "2026-08-23T13:00:00Z" }, { signer: fixture.signer, boot_observer: fixture.observer }],
      ["signer mismatch", validInput, { signer: otherSigner, boot_observer: fixture.observer }],
      ["boot drift", validInput, { signer: fixture.signer, boot_observer: bootDriftObserver }],
      ["decision drift", { ...validInput, decision_input: invalidDecisionInput }, { signer: fixture.signer, boot_observer: fixture.observer }],
      ["request-expired observation", validInput, {
        signer: fixture.signer,
        boot_observer: captureS37QualificationBootObserverV03(() => ({
          ...fixture.observation,
          observed_at: fixture.request.expires_at,
        })),
      }],
    ];

    for (const [label, input, capabilities] of cases) {
      expect(issueS37LinuxLaunchQualificationV03(input, capabilities), label).toEqual({
        ok: false,
        error: "QUALIFICATION_ISSUANCE_INVALID",
      });
    }

    expect(() => captureS37QualificationIssuerSignerV03(
      "qualification_key_1",
      generateKeyPairSync("ec", {
        namedCurve: "prime256v1",
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      }).privateKey,
    )).toThrow("qualification signer must be Ed25519");
  });

  it("rejects admission drift and irreversibly reserves one qualification for one consume", () => {
    const fixture = qualificationFixture();
    const issued = issueS37LinuxLaunchQualificationV03({
      anchor: fixture.anchor,
      qualification_request: fixture.request,
      decision_input: fixture.decisionInput,
      decision: fixture.decision,
      simulated_lease: fixture.lease,
    }, { signer: fixture.signer, boot_observer: fixture.observer });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;
    const valid = {
      qualification: issued.value,
      anchor: fixture.anchor,
      qualification_request: fixture.request,
      decision_input: fixture.decisionInput,
      decision: fixture.decision,
      simulated_lease: fixture.lease,
      observation: { ...fixture.observation, observed_at: "2026-08-23T12:00:20Z" },
    };
    const invalidCases: ReadonlyArray<readonly [string, unknown]> = [
      ["raw verifier", { ...valid, verify: () => true }],
      ["less than fifteen seconds remain", {
        ...valid,
        observation: { ...valid.observation, observed_at: "2026-08-23T12:00:26Z" },
      }],
      ["boot drift", { ...valid, observation: { ...valid.observation, boot_id_hash: H("f") } }],
      ["host drift", {
        ...valid,
        observation: { ...valid.observation, host: { ...fixture.anchor.host, kernel_release: "drift" } },
      }],
      ["profile drift", {
        ...valid,
        observation: { ...valid.observation, runtime_profile_hash: H("f") },
      }],
      ["Phase-B drift", {
        ...valid,
        observation: {
          ...valid.observation,
          phase_b: { ...valid.observation.phase_b, receipt_hash: H("f") },
        },
      }],
      ["artifact drift", {
        ...valid,
        observation: {
          ...valid.observation,
          artifacts: {
            ...fixture.anchor.artifacts,
            supervisor: { ...fixture.anchor.artifacts.supervisor, sha256: H("f") },
          },
        },
      }],
      ["witness drift", {
        ...valid,
        observation: {
          ...valid.observation,
          deny_witnesses: valid.observation.deny_witnesses.map((witness, index) =>
            index === 0 ? { ...witness, witness_sha256: H("f") } : witness),
        },
      }],
      ["decision drift", { ...valid, decision: { ...fixture.decision, decision: "hold" } }],
      ["signature drift", {
        ...valid,
        qualification: {
          ...issued.value,
          attestation: { ...issued.value.attestation, signature_value: Buffer.alloc(64).toString("base64") },
        },
      }],
    ];
    for (const [label, candidate] of invalidCases) {
      expect(admitS37LinuxLaunchQualificationV03(candidate), label).toEqual({
        ok: false,
        error: "QUALIFICATION_ADMISSION_INVALID",
      });
    }

    const admitted = admitS37LinuxLaunchQualificationV03(valid);
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(consumeAuthorizedS37LinuxLaunchQualificationV03(structuredClone(admitted.value))).toBeNull();
    for (const primitive of [null, undefined, false, 0, "qualification"] as const) {
      expect(consumeAuthorizedS37LinuxLaunchQualificationV03(primitive)).toBeNull();
    }
    expect(consumeAuthorizedS37LinuxLaunchQualificationV03(admitted.value)).not.toBeNull();
    expect(consumeAuthorizedS37LinuxLaunchQualificationV03(admitted.value)).toBeNull();
    expect(admitS37LinuxLaunchQualificationV03(valid)).toEqual({
      ok: false,
      error: "QUALIFICATION_ADMISSION_INVALID",
    });
    expect(admitS37LinuxLaunchQualificationV03({
      ...valid,
      qualification: structuredClone(issued.value),
    })).toEqual({ ok: false, error: "QUALIFICATION_ADMISSION_INVALID" });
  });
});

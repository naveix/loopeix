import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import * as contract from "../../src/run/s37-product-host-contract-v03.js";

import {
  canonicalV03,
  hashCanonicalV03,
  parseS37LinuxLaunchQualificationV03,
  parseS37LocalProductHostAnchorV03,
  parseS37ProductHostBootstrapInspectionV01,
  parseS37ProductHostInstallBundleV01,
  parseS37ProductHostLifecycleStateV01,
  parseS37ProductHostQualificationRequestV01,
  parseS37ProductHostTransitionLockV01,
  qualificationSigningBytesV03,
  qualificationStatementHashV03,
  verifyS37LinuxLaunchQualificationSignatureV03,
} from "../../src/run/s37-product-host-contract-v03.js";

const H = (value: string) => `sha256:${value.repeat(64)}`;
const hash = (value: unknown): string => {
  const result = hashCanonicalV03(value);
  if (!result.ok) throw new Error(`hash fixture failed: ${result.error}`);
  return result.value;
};

const keyPair = generateKeyPairSync("ed25519", {
  publicKeyEncoding: { type: "spki", format: "der" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const issuer = {
  key_ref: "qualification_key_1",
  algorithm: "ed25519",
  public_key_spki_base64: keyPair.publicKey.toString("base64"),
  public_key_spki_sha256: `sha256:${createHash("sha256").update(keyPair.publicKey).digest("hex")}`,
};
const managed = (path: string, digit: string) => ({
  path,
  source_sha256: H(digit),
  sha256: H(digit),
  mode: "0555",
  uid: 0,
  gid: 0,
  nlink: 1,
  setuid: false,
});
const hostExecutable = (path: string, digit: string) => ({
  path,
  sha256: H(digit),
  mode: "0755",
  uid: 0,
  gid: 0,
  nlink: 1,
  setuid: false,
});
const artifacts = {
  supervisor: managed("/opt/loopeix/s37.1/supervisor", "1"),
  probe: managed("/opt/loopeix/s37.1/probe", "2"),
  bwrap: { ...managed("/opt/loopeix/s37.1/bwrap", "3"), version: "0.11.0" },
  systemd_run: hostExecutable("/usr/bin/systemd-run", "4"),
  systemctl: hostExecutable("/usr/bin/systemctl", "5"),
  embedded_seccomp_policy_sha256: H("6"),
};
const host = {
  platform: "linux",
  distribution_id: "debian",
  distribution_version_id: "13",
  architecture: "x86_64",
  kernel_release: "6.12.0-amd64",
  systemd_version: "257",
  cgroup_version: "v2",
  host_identity_hash: H("7"),
  controller_uid: 1000,
};

function anchorFixture(issuerValue = issuer) {
  const base = {
    schema_version: "s37-local-product-host-anchor-v03",
    product_profile: "s37-local-product-inert-v03",
    runtime_profile_version: "0.1",
    runtime_profile_hash: H("8"),
    host_role: "local-product",
    transport: "local-only",
    host,
    artifacts,
    cwd: { path: "/", identity_hash: H("9") },
    install_bundle_hash: H("a"),
    qualification_issuer: issuerValue,
    generation: 1,
    predecessor_anchor_hash: null,
  };
  const anchorSubjectHash = hash({ purpose: "s37-local-product-host-anchor-subject-v03", ...base });
  const withoutHash = {
    ...base,
    anchor_subject_hash: anchorSubjectHash,
    operator_authority: {
      authorization_id: "authorization_1",
      authenticated_principal_ref: "principal_1",
      operator_key_id: "operator_key_1",
      authorization_transaction_id: "transaction_1",
      mutation_plan_hash: H("b"),
      authorization_subject_hash: anchorSubjectHash,
      action_scope_hash: H("c"),
      approval_nonce: H("d"),
      authorization_statement_hash: H("e"),
      proof_record_hash: H("f"),
      revocation_epoch: 0,
      expires_at: "2026-08-23T12:01:00Z",
    },
    installed_at: "2026-08-23T12:00:00Z",
  };
  return {
    ...withoutHash,
    anchor_hash: hash({ purpose: "s37-local-product-host-anchor-v03", ...withoutHash }),
  };
}

describe("S37.1-F V03 pure contract", () => {
  it("returns deterministic canonical JSON and a closed hash result without throwing", () => {
    expect(canonicalV03({ z: 1, a: "value" })).toEqual({
      ok: true,
      value: '{"a":"value","z":1}',
    });
    expect(hashCanonicalV03({ z: 1, a: "value" })).toEqual({
      ok: true,
      value: "sha256:5aaca98f7ea3b0364fe69ff79e271b638a88fad50ad5482ac2829be070200775",
    });

    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalV03(cyclic)).not.toThrow();
    expect(canonicalV03(cyclic)).toEqual({ ok: false, error: "V03_INPUT_INVALID" });
  });

  it("rejects non-JSON Unicode and accessors without invoking getters", () => {
    for (const candidate of [{ value: "\ud800" }, { value: "\udfff" }, { ["\ud800"]: "value" }]) {
      expect(canonicalV03(candidate)).toEqual({ ok: false, error: "V03_INPUT_INVALID" });
    }

    let getterCalls = 0;
    const object = {};
    Object.defineProperty(object, "value", {
      enumerable: true,
      get() { getterCalls += 1; return "secret"; },
    });
    const array: unknown[] = [];
    Object.defineProperty(array, "0", {
      enumerable: true,
      configurable: true,
      get() { getterCalls += 1; return "secret"; },
    });
    array.length = 1;

    expect(canonicalV03(object)).toEqual({ ok: false, error: "V03_INPUT_INVALID" });
    expect(canonicalV03(array)).toEqual({ ok: false, error: "V03_INPUT_INVALID" });
    expect(getterCalls).toBe(0);
  });

  it("uses insertion-independent INPUT-before-LIMIT precedence", () => {
    const tooLong = "x".repeat(1_025);
    const left = { limited: tooLong, invalid: 1.5 };
    const right = { invalid: 1.5, limited: tooLong };
    expect(canonicalV03(left)).toEqual({ ok: false, error: "V03_INPUT_INVALID" });
    expect(canonicalV03(right)).toEqual({ ok: false, error: "V03_INPUT_INVALID" });
  });

  it("enforces exact string, depth, node, and canonical-byte boundaries", () => {
    expect(canonicalV03("x".repeat(1_024)).ok).toBe(true);
    expect(canonicalV03("x".repeat(1_025))).toEqual({ ok: false, error: "V03_LIMIT_EXCEEDED" });

    let depthEight: unknown = "leaf";
    for (let index = 0; index < 7; index += 1) depthEight = [depthEight];
    expect(canonicalV03(depthEight).ok).toBe(true);
    expect(canonicalV03([depthEight])).toEqual({ ok: false, error: "V03_LIMIT_EXCEEDED" });

    expect(canonicalV03(Array.from({ length: 511 }, () => 0)).ok).toBe(true);
    expect(canonicalV03(Array.from({ length: 512 }, () => 0)))
      .toEqual({ ok: false, error: "V03_LIMIT_EXCEEDED" });

    const exactBytes = Array.from({ length: 255 }, () => "x".repeat(254));
    expect(Buffer.byteLength(JSON.stringify(exactBytes), "utf8")).toBe(65_536);
    expect(canonicalV03(exactBytes).ok).toBe(true);
    exactBytes[0] += "x";
    expect(canonicalV03(exactBytes)).toEqual({ ok: false, error: "V03_LIMIT_EXCEEDED" });
  });

  it.each([1.5, Number.MAX_SAFE_INTEGER + 1, -0, Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects non-JSON or non-canonical number %s",
    (value) => expect(canonicalV03({ value })).toEqual({ ok: false, error: "V03_INPUT_INVALID" }),
  );

  it("strictly admits a self-consistent V03 anchor and rejects downgrade, widening, and hash drift", () => {
    const anchor = anchorFixture();
    expect(parseS37LocalProductHostAnchorV03(anchor)).toEqual({ ok: true, value: anchor });
    expect(parseS37LocalProductHostAnchorV03({ ...anchor, schema_version: "s37-local-product-binding-v02" }))
      .toEqual({ ok: false, error: "V03_VERSION_UNSUPPORTED" });
    expect(parseS37LocalProductHostAnchorV03({ ...anchor, extra_authority: true }))
      .toEqual({ ok: false, error: "V03_SHAPE_INVALID" });
    expect(parseS37LocalProductHostAnchorV03({ ...anchor, anchor_hash: H("0") }))
      .toEqual({ ok: false, error: "V03_HASH_INVALID" });

    expect(parseS37LocalProductHostAnchorV03(anchorFixture({ ...issuer, public_key_spki_base64: "bad" })))
      .toEqual({ ok: false, error: "V03_SCALAR_INVALID" });
    const p256 = generateKeyPairSync("ec", {
      namedCurve: "P-256",
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    }).publicKey;
    expect(parseS37LocalProductHostAnchorV03(anchorFixture({
      ...issuer,
      public_key_spki_base64: p256.toString("base64"),
      public_key_spki_sha256: `sha256:${createHash("sha256").update(p256).digest("hex")}`,
    }))).toEqual({ ok: false, error: "V03_SCALAR_INVALID" });
    expect(parseS37LocalProductHostAnchorV03(anchorFixture({ ...issuer, public_key_spki_sha256: H("0") })))
      .toEqual({ ok: false, error: "V03_HASH_INVALID" });
  });

  it("admits only exact self-hashed STABLE and PREPARING lifecycle refinements", () => {
    const stableBody = {
      schema_version: "s37-product-host-lifecycle-state-v01",
      status: "STABLE",
      generation: 1,
      stable_anchor_hash: H("1"),
      expected_previous_anchor_hash: null,
      proposed_anchor_hash: null,
      authorization_transaction_id: null,
      authorization_record_hash: null,
      updated_at: "2026-08-23T12:00:00Z",
    };
    const stable = { ...stableBody, state_hash: hash({ purpose: stableBody.schema_version, ...stableBody }) };
    expect(parseS37ProductHostLifecycleStateV01(stable)).toEqual({ ok: true, value: stable });

    const preparingBody = {
      ...stableBody,
      status: "PREPARING",
      stable_anchor_hash: null,
      proposed_anchor_hash: H("2"),
      authorization_transaction_id: "transaction_1",
      authorization_record_hash: H("3"),
    };
    const preparing = { ...preparingBody, state_hash: hash({ purpose: stableBody.schema_version, ...preparingBody }) };
    expect(parseS37ProductHostLifecycleStateV01(preparing)).toEqual({ ok: true, value: preparing });
    expect(parseS37ProductHostLifecycleStateV01({ ...stable, proposed_anchor_hash: H("2") }))
      .toEqual({ ok: false, error: "V03_SEMANTIC_INVALID" });
  });

  it("admits only the exact digest-pinned local install bundle", () => {
    const body = {
      schema_version: "s37-product-host-install-bundle-v01",
      product_profile: "s37-local-product-inert-v03",
      runtime_profile_version: "0.1",
      runtime_profile_hash: H("8"),
      host_role: "local-product",
      transport: "local-only",
      target: {
        platform: "linux",
        distribution_id: "debian",
        distribution_version_id: "13",
        architecture: "x86_64",
        cgroup_version: "v2",
        controller_uid: 1000,
        anchor_path: "/etc/loopeix/s37.1/product-host-v03/anchor.json",
        lifecycle_path: "/etc/loopeix/s37.1/product-host-v03/lifecycle-state.json",
      },
      artifacts,
      cwd: { path: "/", identity_hash: H("9") },
      qualification_issuer: issuer,
      created_at: "2026-08-23T12:00:00Z",
    };
    const bundle = { ...body, bundle_hash: hash({ purpose: body.schema_version, ...body }) };
    expect(parseS37ProductHostInstallBundleV01(bundle)).toEqual({ ok: true, value: bundle });
    expect(parseS37ProductHostInstallBundleV01({ ...bundle, product_profile: "s37-local-product-v02" }))
      .toEqual({ ok: false, error: "V03_VERSION_MIXED" });
  });

  it("admits only a self-hashed Debian x86_64 bootstrap inspection with exact controller mapping", () => {
    const body = {
      schema_version: "s37-product-host-bootstrap-inspection-v01",
      observed_at: "2026-08-23T12:00:00Z",
      platform: "linux",
      distribution: { id: "debian", version_id: "13" },
      architecture: "x86_64",
      kernel_release: "6.12.0-amd64",
      systemd_version: "257",
      cgroup_version: "v2",
      required_cgroup_controllers: ["cpu", "io", "memory", "pids"],
      host_identity_hash: H("7"),
      boot_id_hash: H("8"),
      expected_controller: { username: "loopeix", uid: 1000 },
      observed_controller: { username: "loopeix", uid: 1000, gid: 1000, home: "/home/loopeix", shell: "/bin/bash" },
      user_manager: { active: true, runtime_directory: "/run/user/1000", bus_path: "/run/user/1000/bus" },
      checks: { controller_nonroot: true, username_uid_mapping_exact: true, user_manager_active: true, cgroup_controllers_complete: true },
    };
    const inspection = { ...body, inspection_hash: hash({ purpose: body.schema_version, ...body }) };
    expect(parseS37ProductHostBootstrapInspectionV01(inspection)).toEqual({ ok: true, value: inspection });
    expect(parseS37ProductHostBootstrapInspectionV01({ ...inspection, user_manager: { ...inspection.user_manager, bus_path: "/run/user/1001/bus" } }))
      .toEqual({ ok: false, error: "V03_SEMANTIC_INVALID" });
  });

  it("admits only an exact short-lived request-bound decision and lease tuple", () => {
    const body = {
      schema_version: "s37-product-host-qualification-request-v01",
      product_profile: "s37-local-product-inert-v03",
      anchor_hash: H("1"),
      anchor_generation: 1,
      runtime_profile_hash: H("2"),
      action_proposal_hash: H("3"),
      decision_input_hash: H("4"),
      decision_simulation_hash: H("5"),
      lease_simulation_hash: H("6"),
      launch_nonce: H("7"),
      requested_at: "2026-08-23T12:00:00Z",
      expires_at: "2026-08-23T12:10:00Z",
    };
    const request = { ...body, request_hash: hash({ purpose: body.schema_version, ...body }) };
    expect(parseS37ProductHostQualificationRequestV01(request)).toEqual({ ok: true, value: request });
    expect(parseS37ProductHostQualificationRequestV01({ ...request, expires_at: body.requested_at }))
      .toEqual({ ok: false, error: "V03_SEMANTIC_INVALID" });
    expect(parseS37ProductHostQualificationRequestV01({ ...request, boot_id_hash: H("8") }))
      .toEqual({ ok: false, error: "V03_SHAPE_INVALID" });
    for (const timestamp of [
      "2026-08-23T12:00:00.000Z",
      "2026-08-23T12:00:00+00:00",
      "2026-02-30T12:00:00Z",
    ]) {
      expect(parseS37ProductHostQualificationRequestV01({ ...request, requested_at: timestamp }))
        .toEqual({ ok: false, error: "V03_SCALAR_INVALID" });
    }
  });

  it("derives and verifies an exact signed short-lived launch qualification", () => {
    const denyRows = [
      "ambient-credentials", "child-process", "durable-state", "environment",
      "filesystem-write", "network", "output-limits", "retry", "stdin",
      "timeout", "tool-server", "unknown-outcome",
    ];
    const unsigned = {
      schema_version: "s37-linux-launch-qualification-v03",
      product_profile: "s37-local-product-inert-v03",
      anchor_hash: H("1"),
      anchor_generation: 1,
      boot_id_hash: H("2"),
      host,
      observed_at: "2026-08-23T12:00:00Z",
      runtime_profile_hash: H("3"),
      phase_b: {
        manifest_sha256: H("4"), readiness_evidence_sha256: H("5"),
        readiness_envelope_sha256: H("6"), conformance_evidence_sha256: H("7"), receipt_hash: H("8"),
      },
      artifacts,
      deny_witnesses: denyRows.map((row, index) => ({ row, witness_sha256: H(String((index % 9) + 1)) })),
      request_hash: H("9"),
      decision_input_hash: H("a"),
      decision_simulation_hash: H("b"),
      lease_simulation_hash: H("c"),
      action_proposal_hash: H("d"),
      launch_nonce: H("e"),
      issued_at: "2026-08-23T12:00:01Z",
      expires_at: "2026-08-23T12:00:30Z",
    };
    const header = { issuer_key_ref: issuer.key_ref, signature_algorithm: "ed25519" };
    const statementHash = hash({ purpose: "s37-linux-launch-qualification-statement-v03", ...unsigned, attestation: header });
    expect(qualificationStatementHashV03(unsigned, header)).toEqual({ ok: true, value: statementHash });
    const signingBytes = qualificationSigningBytesV03(unsigned, header);
    expect(signingBytes.ok && Buffer.from(signingBytes.value).toString("ascii")).toBe(statementHash);
    const attestation = {
      ...header,
      statement_hash: statementHash,
      signature_value: sign(null, signingBytes.ok ? signingBytes.value : Buffer.alloc(0), keyPair.privateKey).toString("base64"),
    };
    const body = { ...unsigned, attestation };
    const qualification = { ...body, qualification_hash: hash({ purpose: unsigned.schema_version, ...body }) };

    expect(parseS37LinuxLaunchQualificationV03(qualification)).toEqual({ ok: true, value: qualification });
    expect(verifyS37LinuxLaunchQualificationSignatureV03(qualification, issuer)).toEqual({ ok: true, value: qualification });

    const secondSigningBytes = qualificationSigningBytesV03(unsigned, header);
    expect(signingBytes.ok && secondSigningBytes.ok && signingBytes.value).not.toBe(secondSigningBytes.ok && secondSigningBytes.value);
    expect(signingBytes.ok && signingBytes.value.byteLength).toBe(71);
    if (signingBytes.ok) signingBytes.value[0] = 0;
    expect(secondSigningBytes.ok && Buffer.from(secondSigningBytes.value).toString("ascii")).toBe(statementHash);

    expect(qualificationStatementHashV03(qualification, header))
      .toEqual({ ok: false, error: "V03_SHAPE_INVALID" });
    expect(qualificationStatementHashV03({ ...unsigned, statement_hash: H("f") }, header))
      .toEqual({ ok: false, error: "V03_SHAPE_INVALID" });
    expect(qualificationStatementHashV03(unsigned, { ...header, signature_value: "dummy" }))
      .toEqual({ ok: false, error: "V03_SHAPE_INVALID" });
    expect(qualificationStatementHashV03({ ...unsigned, product_profile: "s37-local-product-v02" }, header))
      .toEqual({ ok: false, error: "V03_VERSION_MIXED" });
    expect(() => qualificationSigningBytesV03(null, header)).not.toThrow();
    expect(qualificationSigningBytesV03(null, header)).toEqual({ ok: false, error: "V03_INPUT_INVALID" });

    const oversizedUnsigned = { ...unsigned, extra: Array.from({ length: 35 }, () => "x".repeat(1_000)) };
    const oversizedHeader = { ...header, extra: Array.from({ length: 35 }, () => "x".repeat(1_000)) };
    expect(canonicalV03(oversizedUnsigned).ok).toBe(true);
    expect(canonicalV03(oversizedHeader).ok).toBe(true);
    expect(qualificationStatementHashV03(oversizedUnsigned, oversizedHeader))
      .toEqual({ ok: false, error: "V03_LIMIT_EXCEEDED" });

    const reversed = { ...qualification, deny_witnesses: [...qualification.deny_witnesses].reverse() };
    expect(parseS37LinuxLaunchQualificationV03(reversed)).toEqual({ ok: false, error: "V03_SEMANTIC_INVALID" });
    const badAttestation = { ...attestation, signature_value: Buffer.alloc(64).toString("base64") };
    const badBody = { ...unsigned, attestation: badAttestation };
    const badSignature = { ...badBody, qualification_hash: hash({ purpose: unsigned.schema_version, ...badBody }) };
    expect(verifyS37LinuxLaunchQualificationSignatureV03(badSignature, issuer))
      .toEqual({ ok: false, error: "V03_SIGNATURE_INVALID" });
    const statementDriftAttestation = { ...attestation, statement_hash: H("f") };
    const statementDriftBody = { ...unsigned, attestation: statementDriftAttestation };
    const statementDrift = {
      ...statementDriftBody,
      qualification_hash: hash({ purpose: unsigned.schema_version, ...statementDriftBody }),
    };
    expect(parseS37LinuxLaunchQualificationV03(statementDrift))
      .toEqual({ ok: false, error: "V03_HASH_INVALID" });
    expect(parseS37LinuxLaunchQualificationV03({ ...qualification, attestation: badAttestation }))
      .toEqual({ ok: false, error: "V03_HASH_INVALID" });

    const otherPair = generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "der" } });
    const otherIssuer = {
      ...issuer,
      key_ref: "qualification_key_2",
      public_key_spki_base64: otherPair.publicKey.toString("base64"),
      public_key_spki_sha256: `sha256:${createHash("sha256").update(otherPair.publicKey).digest("hex")}`,
    };
    expect(verifyS37LinuxLaunchQualificationSignatureV03(qualification, otherIssuer))
      .toEqual({ ok: false, error: "V03_SIGNATURE_INVALID" });
    expect(verifyS37LinuxLaunchQualificationSignatureV03(qualification, { ...issuer, public_key_spki_base64: "bad" }))
      .toEqual({ ok: false, error: "V03_SIGNATURE_INVALID" });

    const parsed = parseS37LinuxLaunchQualificationV03(qualification);
    expect(parsed.ok && Object.isFrozen(parsed.value.deny_witnesses)).toBe(true);
    expect(parsed.ok && Object.isFrozen(parsed.value.deny_witnesses[0])).toBe(true);
    const admittedFirstWitness = parsed.ok ? parsed.value.deny_witnesses[0].witness_sha256 : null;
    qualification.deny_witnesses[0].witness_sha256 = H("f");
    expect(parsed.ok && parsed.value.deny_witnesses[0].witness_sha256).toBe(admittedFirstWitness);
  });

  it("admits only an exact self-hashed install or forward-transition lock", () => {
    const installBody = {
      schema_version: "s37-product-host-transition-lock-v01",
      operation: "install",
      authorization_transaction_id: "transaction_1",
      generation: 1,
      expected_previous_anchor_hash: null,
      proposed_anchor_hash: H("1"),
      authorization_record_hash: H("2"),
    };
    const install = { ...installBody, lock_hash: hash({ purpose: installBody.schema_version, ...installBody }) };
    expect(parseS37ProductHostTransitionLockV01(install)).toEqual({ ok: true, value: install });

    const transitionBody = { ...installBody, operation: "transition", generation: 2, expected_previous_anchor_hash: H("3") };
    const transition = { ...transitionBody, lock_hash: hash({ purpose: installBody.schema_version, ...transitionBody }) };
    expect(parseS37ProductHostTransitionLockV01(transition)).toEqual({ ok: true, value: transition });
    expect(parseS37ProductHostTransitionLockV01({ ...install, operation: "transition" }))
      .toEqual({ ok: false, error: "V03_SEMANTIC_INVALID" });
  });

  it("applies closed failure precedence and remains total for hostile candidates", () => {
    const anchor = anchorFixture();
    expect(parseS37LocalProductHostAnchorV03({ ...anchor, schema_version: "x".repeat(1_025) }))
      .toEqual({ ok: false, error: "V03_LIMIT_EXCEEDED" });
    expect(parseS37LocalProductHostAnchorV03({ ...anchor, cwd: { ...anchor.cwd, schema_version: "0.2" } }))
      .toEqual({ ok: false, error: "V03_VERSION_MIXED" });
    expect(parseS37LocalProductHostAnchorV03({
      ...anchor,
      host: { ...anchor.host, controller_uid: "root" },
      anchor_hash: "wrong",
    })).toEqual({ ok: false, error: "V03_SCALAR_INVALID" });

    const parsers = [
      parseS37LocalProductHostAnchorV03,
      parseS37ProductHostLifecycleStateV01,
      parseS37LinuxLaunchQualificationV03,
      parseS37ProductHostBootstrapInspectionV01,
      parseS37ProductHostInstallBundleV01,
      parseS37ProductHostQualificationRequestV01,
      parseS37ProductHostTransitionLockV01,
    ];
    for (const parser of parsers) {
      expect(() => parser(null)).not.toThrow();
      expect(parser(null)).toEqual({ ok: false, error: "V03_INPUT_INVALID" });
    }

    const parsed = parseS37LocalProductHostAnchorV03(anchor);
    expect(parsed.ok && Object.isFrozen(parsed.value)).toBe(true);
    expect(parsed.ok && Object.isFrozen(parsed.value.artifacts)).toBe(true);
  });

  it("exports only the pure frozen contract surface", () => {
    expect(Object.keys(contract).sort()).toEqual([
      "canonicalV03",
      "hashCanonicalV03",
      "parseS37LinuxLaunchQualificationV03",
      "parseS37LocalProductHostAnchorV03",
      "parseS37ProductHostBootstrapInspectionV01",
      "parseS37ProductHostInstallBundleV01",
      "parseS37ProductHostLifecycleStateV01",
      "parseS37ProductHostQualificationRequestV01",
      "parseS37ProductHostTransitionLockV01",
      "qualificationSigningBytesV03",
      "qualificationStatementHashV03",
      "verifyS37LinuxLaunchQualificationSignatureV03",
    ].sort());
  });
});

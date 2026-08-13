import { describe, expect, it } from "vitest";

import { canonicalize, hashCanonical } from "../../src/hash.js";
import * as policyModule from "../../src/run/action-classifier-policy-v02.js";

type ExtensionApi = {
  resolveS36BuiltInAuthorityDecisionPolicyExtensionV1: (digest: string) => Record<string, unknown> | null;
  resolveAgencyQuorumRequirementV02: (selector: Record<string, unknown>) => Record<string, unknown> | null;
  resolveAgencyQuorumRequirementByHashV02: (digest: string, quorumHash: string) => Record<string, unknown> | null;
  resolveAuthorityPolicyReasonDeclarationV02: (digest: string, declarationRef: string) => Record<string, unknown> | null;
  authorityPolicyReasonRefIsCompatibleV02: (
    digest: string, declarationRef: string, recordKind: string, decision: string,
  ) => boolean;
  validateAuthorityDecisionPolicyExtensionV1: (candidate: unknown) => Readonly<{ ok: boolean; reason?: string }>;
};

const api = policyModule as unknown as ExtensionApi;
const BASE_DIGEST = policyModule.S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02;
const OTHER_DIGEST = `sha256:${"f".repeat(64)}`;

describe("S36 immutable authority decision-policy extension", () => {
  it("resolves one exact extension for the release-pinned S35 base digest", () => {
    expect(typeof api.resolveS36BuiltInAuthorityDecisionPolicyExtensionV1).toBe("function");
    const extension = api.resolveS36BuiltInAuthorityDecisionPolicyExtensionV1(BASE_DIGEST)!;
    expect(extension).not.toBeNull();
    expect(extension.extension_version).toBe("0.1");
    expect(extension.base_policy_digest).toBe(BASE_DIGEST);
    expect(extension.extension_hash).toBe(hashCanonical({
      purpose: "authority-decision-policy-extension-v1",
      extension_version: extension.extension_version,
      base_policy_digest: extension.base_policy_digest,
      quorum_requirements: extension.quorum_requirements,
      reason_declarations: extension.reason_declarations,
    }));
    expect(api.resolveS36BuiltInAuthorityDecisionPolicyExtensionV1(OTHER_DIGEST)).toBeNull();
  });

  it("contains exactly the three classifier-produced agency selectors with conservative unanimous policy", () => {
    const extension = api.resolveS36BuiltInAuthorityDecisionPolicyExtensionV1(BASE_DIGEST)!;
    const requirements = extension.quorum_requirements as Record<string, unknown>[];
    expect(requirements.map((row) => [row.action_class, row.policy_action_kind])).toEqual([
      ["artifact-write", "reversible-workspace-edit"],
      ["tool", "authenticated-read"],
      ["tool", "network-read"],
    ]);
    for (const requirement of requirements) {
      expect(requirement).toMatchObject({
        policy_digest: BASE_DIGEST,
        action_approval_class: "agency",
        required_reviewer_role_refs: [
          "authority-governor", "evidence-reviewer", "scope-guardian", "security-information-flow-reviewer",
        ],
        minimum_allow_recommendations: 4,
        minimum_independent_reviewer_roots: 4,
        minimum_evidence_roots_per_recommendation: 1,
        max_recommendation_ttl_ms: 300_000,
        independent_evidence_producer_required: true,
      });
      const resolved = api.resolveAgencyQuorumRequirementV02({
        policy_digest: BASE_DIGEST,
        action_class: requirement.action_class,
        policy_action_kind: requirement.policy_action_kind,
        action_approval_class: "agency",
      })!;
      expect(resolved.requirement).toEqual(requirement);
      expect(resolved.quorum_requirement_hash).toBe(hashCanonical({
        purpose: "agency-quorum-requirement-v02", ...requirement,
      }));
      expect(api.resolveAgencyQuorumRequirementByHashV02(BASE_DIGEST, String(resolved.quorum_requirement_hash))).toEqual(resolved);
    }
    expect(api.resolveAgencyQuorumRequirementV02({
      policy_digest: BASE_DIGEST, action_class: "task", policy_action_kind: "planning", action_approval_class: "automatic",
    })).toBeNull();
    expect(api.resolveAgencyQuorumRequirementByHashV02(BASE_DIGEST, OTHER_DIGEST)).toBeNull();
  });

  it("resolves only globally unique, canonically ordered, branch-compatible reason declarations", () => {
    const extension = api.resolveS36BuiltInAuthorityDecisionPolicyExtensionV1(BASE_DIGEST)!;
    const declarations = extension.reason_declarations as Record<string, unknown>[];
    expect(declarations).toHaveLength(16);
    expect([...declarations].sort((a, b) => Buffer.from(canonicalize([a.record_kind, a.declaration_ref])).compare(Buffer.from(canonicalize([b.record_kind, b.declaration_ref]))))).toEqual(declarations);
    expect(api.resolveAuthorityPolicyReasonDeclarationV02(BASE_DIGEST, "recommendation-allow-evidence")).toEqual({
      record_kind: "agency-recommendation", declaration_ref: "recommendation-allow-evidence", compatible_decisions: ["allow"],
    });
    expect(api.resolveAuthorityPolicyReasonDeclarationV02(BASE_DIGEST, "decision-agency-quorum-hold")).toEqual({
      record_kind: "policy-decision", declaration_ref: "decision-agency-quorum-hold", compatible_decisions: ["hold"],
    });
    expect(api.resolveAuthorityPolicyReasonDeclarationV02(OTHER_DIGEST, "decision-agency-quorum-hold")).toBeNull();
    expect(api.resolveAuthorityPolicyReasonDeclarationV02(BASE_DIGEST, "caller-free-text")).toBeNull();
    expect(api.authorityPolicyReasonRefIsCompatibleV02(
      BASE_DIGEST, "recommendation-allow-evidence", "agency-recommendation", "allow",
    )).toBe(true);
    expect(api.authorityPolicyReasonRefIsCompatibleV02(
      BASE_DIGEST, "recommendation-allow-evidence", "policy-decision", "allow",
    )).toBe(false);
    expect(api.authorityPolicyReasonRefIsCompatibleV02(
      BASE_DIGEST, "recommendation-allow-evidence", "agency-recommendation", "deny",
    )).toBe(false);
  });

  it("returns defensive snapshots and rejects mutation, duplicate selectors, and forged hashes", () => {
    const first = api.resolveS36BuiltInAuthorityDecisionPolicyExtensionV1(BASE_DIGEST)!;
    (first.quorum_requirements as Record<string, unknown>[])[0]!.requirement_ref = "mutated";
    expect(((api.resolveS36BuiltInAuthorityDecisionPolicyExtensionV1(BASE_DIGEST)!.quorum_requirements as Record<string, unknown>[])[0]!.requirement_ref))
      .toBe("agency-artifact-write-reversible-workspace-edit-v1");

    const valid = api.resolveS36BuiltInAuthorityDecisionPolicyExtensionV1(BASE_DIGEST)!;
    expect(api.validateAuthorityDecisionPolicyExtensionV1(valid)).toEqual({ ok: true });
    expect(api.validateAuthorityDecisionPolicyExtensionV1({ ...valid, extension_hash: OTHER_DIGEST })).toMatchObject({ ok: false });
    expect(api.validateAuthorityDecisionPolicyExtensionV1({
      ...valid,
      quorum_requirements: [
        ...(valid.quorum_requirements as Record<string, unknown>[]),
        (valid.quorum_requirements as Record<string, unknown>[])[0],
      ],
    })).toMatchObject({ ok: false });
    expect(api.validateAuthorityDecisionPolicyExtensionV1({
      ...valid,
      reason_declarations: [...(valid.reason_declarations as Record<string, unknown>[])].reverse(),
    })).toMatchObject({ ok: false });
    const declarations = valid.reason_declarations as Record<string, unknown>[];
    expect(api.validateAuthorityDecisionPolicyExtensionV1({
      ...valid,
      reason_declarations: declarations.map((declaration, index) => index === 0
        ? { ...declaration, compatible_decisions: ["abort", "abort"] }
        : declaration),
    })).toMatchObject({ ok: false });
    expect(api.validateAuthorityDecisionPolicyExtensionV1({
      ...valid,
      reason_declarations: declarations.map((declaration, index) => index === 0
        ? { ...declaration, compatible_decisions: ["abort", "allow"] }
        : declaration),
    })).toMatchObject({ ok: false });
  });
});

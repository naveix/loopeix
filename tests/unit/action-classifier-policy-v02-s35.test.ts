import { canonicalize, hashCanonical } from "../../src/hash.js";
import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  admitHostCapturedPolicyBundleV02,
  registerHostCapturedPolicyBundleV02,
  resolveImmutableActionApprovalPolicyV02,
  resolveS35BuiltInActionApprovalPolicyV02,
  type HostCapturedPolicyBundleV02,
} from "../../src/run/action-classifier-policy-v02.js";
import { describe, expect, it } from "vitest";

const UNRELATED_DIGEST = `sha256:${"f".repeat(64)}`;
const ACTION_CLASSES = {
  planning: "automatic",
  "local-read": "automatic",
  "deterministic-no-side-effect-check": "automatic",
  "authenticated-read": "agency",
  "network-read": "agency",
  "reversible-workspace-edit": "agency",
  "authenticated-write": "human_exception",
  commit: "human_exception",
  deploy: "human_exception",
  "destructive-action": "human_exception",
  "irreversible-action": "human_exception",
  merge: "human_exception",
  "new-secret-scope": "human_exception",
  "package-change": "human_exception",
  "protected-ref-mutation": "human_exception",
  publish: "human_exception",
  push: "human_exception",
  rebase: "human_exception",
  release: "human_exception",
  send: "human_exception",
  "t4-action": "human_exception",
  "approval-contract-edit": "blocked",
  "connector-admin": "blocked",
  "connector-delete": "blocked",
  "force-push": "blocked",
  "policy-weakening": "blocked",
  "self-widening": "blocked",
  "t5-action": "blocked",
  "uninspectable-side-effect": "blocked",
} as const;

const HUMAN_EXCEPTION = ["authenticated-write", "commit", "deploy", "destructive-action", "irreversible-action", "merge", "new-secret-scope", "package-change", "protected-ref-mutation", "publish", "push", "rebase", "release", "send", "t4-action"];
const BLOCKED = ["approval-contract-edit", "connector-admin", "connector-delete", "force-push", "policy-weakening", "self-widening", "t5-action", "uninspectable-side-effect"];

function policyFixture(suffix = "v1") {
  const kinds = Object.keys(ACTION_CLASSES).sort((left, right) => Buffer.from(left).compare(Buffer.from(right))) as Array<keyof typeof ACTION_CLASSES>;
  const rules = kinds.map((actionKind) => {
    const key = {
      action_class: "task",
      dispatch_kind: "process",
      adapter_ref: "codex-cli",
      adapter_version_hash: `sha256:${"1".repeat(64)}`,
      capability_ref: `${actionKind}-${suffix}`,
      capability_definition_hash: `sha256:${"2".repeat(64)}`,
      operation: "read",
      effective_risk_tier: "T2",
      effect_classes: ["none"],
      all_effects_inspectable: true,
      all_effects_reversible: true,
      data_access_mode: "local",
      repository_transition_intent: "none",
      cost_mode: "none",
    } as const;
    const rule = {
      rule_version: "0.1",
      key,
      policy_action_kind: actionKind,
      action_approval_class: ACTION_CLASSES[actionKind],
    } as const;
    return { ...rule, rule_hash: hashCanonical({ purpose: "action-classifier-rule-v1", ...rule }) };
  }).sort((left, right) => Buffer.from(canonicalize(left.key)).compare(Buffer.from(canonicalize(right.key))));
  const classifierRegistry = {
    registry_version: "0.1" as const,
    rules,
    registry_hash: hashCanonical({ purpose: "action-classifier-registry-v1", registry_version: "0.1", rules }),
  };
  const entries = kinds.map((actionKind) => ({
    action_kind: actionKind,
    approval_class: ACTION_CLASSES[actionKind],
    classifier_rule_hash: rules.find((rule) => rule.policy_action_kind === actionKind)!.rule_hash,
  }));
  const policyWithoutRegistryHash = {
    registry_version: "0.1" as const,
    classifier_registry: classifierRegistry,
    entries,
    human_exception_action_kinds: HUMAN_EXCEPTION,
    blocked_action_kinds: BLOCKED,
  };
  const policyWithoutDigest = {
    ...policyWithoutRegistryHash,
    registry_hash: hashCanonical({
      purpose: "action-approval-policy-v1",
      registry_version: policyWithoutRegistryHash.registry_version,
      classifier_registry: policyWithoutRegistryHash.classifier_registry,
      entries: policyWithoutRegistryHash.entries,
      human_exception_action_kinds: policyWithoutRegistryHash.human_exception_action_kinds,
      blocked_action_kinds: policyWithoutRegistryHash.blocked_action_kinds,
    }),
  };
  return {
    registry_version: policyWithoutDigest.registry_version,
    policy_digest: hashCanonical({ purpose: "action-approval-policy-bundle-v02", ...policyWithoutDigest }),
    classifier_registry: policyWithoutDigest.classifier_registry,
    entries: policyWithoutDigest.entries,
    human_exception_action_kinds: policyWithoutDigest.human_exception_action_kinds,
    blocked_action_kinds: policyWithoutDigest.blocked_action_kinds,
    registry_hash: policyWithoutDigest.registry_hash,
  };
}

describe("S35 immutable action-classifier policy registry", () => {
  it("ships one release-pinned complete built-in bundle without runtime registration", () => {
    expect(S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02).toBe(
      "sha256:f9fb5daca837efaf274a0567e70d6b90c690ea7ed0ed69e8089cc16bbf6d0dd9",
    );

    const policy = resolveS35BuiltInActionApprovalPolicyV02(
      S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    );
    expect(policy).not.toBeNull();
    expect(resolveImmutableActionApprovalPolicyV02(
      S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    )).toEqual(policy);
    expect(policy?.entries).toHaveLength(29);
    expect(Object.fromEntries(policy!.entries.map((entry) => [entry.action_kind, entry.approval_class])))
      .toEqual(ACTION_CLASSES);

    for (const rule of policy!.classifier_registry.rules) {
      expect(rule.rule_hash).toBe(hashCanonical({
        purpose: "action-classifier-rule-v1",
        rule_version: rule.rule_version,
        key: rule.key,
        policy_action_kind: rule.policy_action_kind,
        action_approval_class: rule.action_approval_class,
      }));
    }
    expect(policy!.classifier_registry.registry_hash).toBe(hashCanonical({
      purpose: "action-classifier-registry-v1",
      registry_version: policy!.classifier_registry.registry_version,
      rules: policy!.classifier_registry.rules,
    }));
    expect(policy!.registry_hash).toBe(hashCanonical({
      purpose: "action-approval-policy-v1",
      registry_version: policy!.registry_version,
      classifier_registry: policy!.classifier_registry,
      entries: policy!.entries,
      human_exception_action_kinds: policy!.human_exception_action_kinds,
      blocked_action_kinds: policy!.blocked_action_kinds,
    }));
    expect(policy!.policy_digest).toBe(hashCanonical({
      purpose: "action-approval-policy-bundle-v02",
      registry_version: policy!.registry_version,
      classifier_registry: policy!.classifier_registry,
      entries: policy!.entries,
      human_exception_action_kinds: policy!.human_exception_action_kinds,
      blocked_action_kinds: policy!.blocked_action_kinds,
      registry_hash: policy!.registry_hash,
    }));
  });

  it("resolves the built-in only by its exact digest and returns defensive snapshots", () => {
    expect(resolveS35BuiltInActionApprovalPolicyV02(UNRELATED_DIGEST)).toBeNull();
    const first = resolveS35BuiltInActionApprovalPolicyV02(
      S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    );
    expect(first).not.toBeNull();
    first!.entries[0]!.approval_class = "automatic";
    expect(resolveS35BuiltInActionApprovalPolicyV02(
      S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    )?.entries[0]?.approval_class).toBe("blocked");
  });

  it("admits an exact bundle once, registers it immutably, and returns defensive snapshots", () => {
    const candidate = policyFixture("valid");
    const admitted = admitHostCapturedPolicyBundleV02(candidate, candidate.policy_digest);
    expect(admitted.ok, admitted.ok ? undefined : admitted).toBe(true);
    if (!admitted.ok) return;

    candidate.entries[0]!.approval_class = "automatic";
    expect(registerHostCapturedPolicyBundleV02(admitted.bundle)).toBe(true);
    expect(registerHostCapturedPolicyBundleV02(admitted.bundle)).toBe(false);

    const first = resolveImmutableActionApprovalPolicyV02(candidate.policy_digest);
    expect(first?.entries).toHaveLength(29);
    expect(first?.entries[0]?.approval_class).toBe(ACTION_CLASSES[first.entries[0]!.action_kind]);
    first!.entries[0]!.approval_class = "automatic";
    expect(resolveImmutableActionApprovalPolicyV02(candidate.policy_digest)?.entries[0]?.approval_class).toBe("blocked");
  });

  it("rejects structural tokens and every canonical inner-hash or taxonomy drift", () => {
    expect(registerHostCapturedPolicyBundleV02(Object.freeze({ policy_digest: UNRELATED_DIGEST }) as HostCapturedPolicyBundleV02)).toBe(false);

    for (const [index, mutate] of [
      (policy: ReturnType<typeof policyFixture>) => { policy.classifier_registry.rules[0]!.rule_hash = `sha256:${"0".repeat(64)}`; },
      (policy: ReturnType<typeof policyFixture>) => { policy.classifier_registry.registry_hash = `sha256:${"0".repeat(64)}`; },
      (policy: ReturnType<typeof policyFixture>) => { policy.registry_hash = `sha256:${"0".repeat(64)}`; },
      (policy: ReturnType<typeof policyFixture>) => { policy.entries.reverse(); },
      (policy: ReturnType<typeof policyFixture>) => { policy.entries.pop(); },
    ].entries()) {
      const policy = policyFixture(`invalid-${index}`);
      mutate(policy);
      expect(admitHostCapturedPolicyBundleV02(policy, policy.policy_digest)).toMatchObject({ ok: false, reason: "INVALID_POLICY_BUNDLE" });
    }
  });

  it("rejects a caller-supplied digest and permits only byte-identical registration under an existing digest", () => {
    const candidate = policyFixture("valid");
    const forgedDigest = { ...candidate, policy_digest: UNRELATED_DIGEST };
    expect(admitHostCapturedPolicyBundleV02(forgedDigest, UNRELATED_DIGEST)).toMatchObject({
      ok: false,
      reason: "INVALID_POLICY_BUNDLE",
    });
    const admitted = admitHostCapturedPolicyBundleV02(candidate, candidate.policy_digest);
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(registerHostCapturedPolicyBundleV02(admitted.bundle)).toBe(true);
  });
});

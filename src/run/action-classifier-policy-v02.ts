import { z } from "zod";

import { canonicalize, hashCanonical } from "../hash.js";
import { Hash, RiskTierV1 } from "../schema/scalars.js";
import { HumanIdV02 } from "../schema/scalars-v02.js";
import type { ResolvedRunPlanV02Value } from "../schema/runtime.js";

type ActionApprovalPolicyV1 = ResolvedRunPlanV02Value["authority_subject"]["protection"]["action_approval_policy"];

const strictObject = <T extends z.ZodRawShape>(shape: T): z.ZodObject<T> => z.object(shape).strict();

const POLICY_CLASS_BY_ACTION_KIND = Object.freeze({
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
} as const);

type PolicyActionKindV1 = keyof typeof POLICY_CLASS_BY_ACTION_KIND;
type ActionApprovalClassV1 = (typeof POLICY_CLASS_BY_ACTION_KIND)[PolicyActionKindV1];

const POLICY_ACTION_KINDS = Object.freeze(
  (Object.keys(POLICY_CLASS_BY_ACTION_KIND) as PolicyActionKindV1[])
    .sort((left, right) => Buffer.from(left).compare(Buffer.from(right))),
);

const HUMAN_EXCEPTION_ACTION_KINDS = Object.freeze([
  "authenticated-write",
  "commit",
  "deploy",
  "destructive-action",
  "irreversible-action",
  "merge",
  "new-secret-scope",
  "package-change",
  "protected-ref-mutation",
  "publish",
  "push",
  "rebase",
  "release",
  "send",
  "t4-action",
] as const);

const BLOCKED_ACTION_KINDS = Object.freeze([
  "approval-contract-edit",
  "connector-admin",
  "connector-delete",
  "force-push",
  "policy-weakening",
  "self-widening",
  "t5-action",
  "uninspectable-side-effect",
] as const);

const ActionApprovalClass = z.enum(["automatic", "agency", "human_exception", "blocked"]);
const PolicyActionKind = z.enum(POLICY_ACTION_KINDS);
const ActionClassifierKey = strictObject({
  action_class: z.enum(["task", "tool", "artifact-write"]),
  dispatch_kind: z.enum(["process", "tool", "connector", "artifact-write"]),
  adapter_ref: HumanIdV02,
  adapter_version_hash: Hash,
  capability_ref: HumanIdV02,
  capability_definition_hash: Hash,
  operation: z.enum(["read", "write", "delete", "export", "send", "waive"]),
  effective_risk_tier: RiskTierV1,
  effect_classes: z.array(z.enum(["none", "workspace-write", "external-read", "external-write", "destructive"])),
  all_effects_inspectable: z.boolean(),
  all_effects_reversible: z.boolean(),
  data_access_mode: z.enum(["none", "local", "authenticated", "network", "export"]),
  repository_transition_intent: z.enum(["none", "workspace-edit", "commit", "protected-ref-mutation"]),
  cost_mode: z.enum(["none", "metered"]),
});
const ActionClassifierRule = strictObject({
  rule_version: z.literal("0.1"),
  key: ActionClassifierKey,
  policy_action_kind: PolicyActionKind,
  action_approval_class: ActionApprovalClass,
  rule_hash: Hash,
});
const ActionClassifierRegistry = strictObject({
  registry_version: z.literal("0.1"),
  rules: z.array(ActionClassifierRule).min(1),
  registry_hash: Hash,
});
const ActionApprovalPolicyEntry = strictObject({
  action_kind: PolicyActionKind,
  approval_class: ActionApprovalClass,
  classifier_rule_hash: Hash,
});
const HumanExceptionActionKinds = z.tuple([
  z.literal("authenticated-write"),
  z.literal("commit"),
  z.literal("deploy"),
  z.literal("destructive-action"),
  z.literal("irreversible-action"),
  z.literal("merge"),
  z.literal("new-secret-scope"),
  z.literal("package-change"),
  z.literal("protected-ref-mutation"),
  z.literal("publish"),
  z.literal("push"),
  z.literal("rebase"),
  z.literal("release"),
  z.literal("send"),
  z.literal("t4-action"),
]);
const BlockedActionKinds = z.tuple([
  z.literal("approval-contract-edit"),
  z.literal("connector-admin"),
  z.literal("connector-delete"),
  z.literal("force-push"),
  z.literal("policy-weakening"),
  z.literal("self-widening"),
  z.literal("t5-action"),
  z.literal("uninspectable-side-effect"),
]);
const ActionApprovalPolicy = strictObject({
  registry_version: z.literal("0.1"),
  policy_digest: Hash,
  classifier_registry: ActionClassifierRegistry,
  entries: z.array(ActionApprovalPolicyEntry).min(1),
  human_exception_action_kinds: HumanExceptionActionKinds,
  blocked_action_kinds: BlockedActionKinds,
  registry_hash: Hash,
});

export type HostCapturedPolicyBundleV02 = Readonly<{
  policy_digest: string;
  readonly __host_captured_policy_bundle_v02: unique symbol;
}>;

export type AdmitHostCapturedPolicyBundleV02Result =
  | { ok: true; bundle: HostCapturedPolicyBundleV02 }
  | { ok: false; reason: "INVALID_POLICY_BUNDLE"; message: string };

const admittedBundles = new WeakMap<HostCapturedPolicyBundleV02, ActionApprovalPolicyV1>();
const immutablePolicyRegistry = new Map<string, ActionApprovalPolicyV1>();

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function invalidPolicy(message: string): AdmitHostCapturedPolicyBundleV02Result {
  return { ok: false, reason: "INVALID_POLICY_BUNDLE", message };
}

function equalTuple(actual: readonly string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

function validatePolicy(candidate: z.infer<typeof ActionApprovalPolicy>): string | null {
  if (!equalTuple(candidate.human_exception_action_kinds, HUMAN_EXCEPTION_ACTION_KINDS)) {
    return "Human-exception action kinds do not match the closed canonical tuple.";
  }
  if (!equalTuple(candidate.blocked_action_kinds, BLOCKED_ACTION_KINDS)) {
    return "Blocked action kinds do not match the closed canonical tuple.";
  }
  if (candidate.entries.length !== POLICY_ACTION_KINDS.length) {
    return "Policy entries must contain every action kind exactly once.";
  }
  for (const [index, actionKind] of POLICY_ACTION_KINDS.entries()) {
    const entry = candidate.entries[index];
    if (entry?.action_kind !== actionKind || entry.approval_class !== POLICY_CLASS_BY_ACTION_KIND[actionKind]) {
      return "Policy entries must be UTF-8 sorted and carry the canonical approval class.";
    }
  }

  const ruleKeyBytes = candidate.classifier_registry.rules.map((rule) => canonicalize(rule.key));
  if (new Set(ruleKeyBytes).size !== ruleKeyBytes.length) return "Classifier keys must be unique.";
  for (let index = 1; index < ruleKeyBytes.length; index += 1) {
    if (Buffer.from(ruleKeyBytes[index - 1]!).compare(Buffer.from(ruleKeyBytes[index]!)) >= 0) {
      return "Classifier rules must be sorted by canonical key bytes.";
    }
  }
  for (const rule of candidate.classifier_registry.rules) {
    const expectedHash = hashCanonical({
      purpose: "action-classifier-rule-v1",
      rule_version: rule.rule_version,
      key: rule.key,
      policy_action_kind: rule.policy_action_kind,
      action_approval_class: rule.action_approval_class,
    });
    if (rule.rule_hash !== expectedHash) return "Classifier rule hash does not match its canonical preimage.";
  }
  const expectedRegistryHash = hashCanonical({
    purpose: "action-classifier-registry-v1",
    registry_version: candidate.classifier_registry.registry_version,
    rules: candidate.classifier_registry.rules,
  });
  if (candidate.classifier_registry.registry_hash !== expectedRegistryHash) {
    return "Classifier registry hash does not match its canonical preimage.";
  }
  const ruleByHash = new Map(candidate.classifier_registry.rules.map((rule) => [rule.rule_hash, rule]));
  for (const entry of candidate.entries) {
    const rule = ruleByHash.get(entry.classifier_rule_hash);
    if (rule === undefined || rule.policy_action_kind !== entry.action_kind || rule.action_approval_class !== entry.approval_class) {
      return "Every approval entry must resolve to one classifier rule with the same kind and class.";
    }
  }
  const expectedPolicyRegistryHash = hashCanonical({
    purpose: "action-approval-policy-v1",
    registry_version: candidate.registry_version,
    classifier_registry: candidate.classifier_registry,
    entries: candidate.entries,
    human_exception_action_kinds: candidate.human_exception_action_kinds,
    blocked_action_kinds: candidate.blocked_action_kinds,
  });
  if (candidate.registry_hash !== expectedPolicyRegistryHash) {
    return "Approval-policy registry hash does not match its canonical preimage.";
  }
  const expectedPolicyDigest = hashCanonical({
    purpose: "action-approval-policy-bundle-v02",
    registry_version: candidate.registry_version,
    classifier_registry: candidate.classifier_registry,
    entries: candidate.entries,
    human_exception_action_kinds: candidate.human_exception_action_kinds,
    blocked_action_kinds: candidate.blocked_action_kinds,
    registry_hash: candidate.registry_hash,
  });
  if (candidate.policy_digest !== expectedPolicyDigest) {
    return "Policy digest does not match the completed immutable bundle preimage.";
  }
  return null;
}

function builtInRuleKey(
  actionKind: PolicyActionKindV1,
  approvalClass: ActionApprovalClassV1,
): z.infer<typeof ActionClassifierKey> {
  const workspaceKinds = new Set<PolicyActionKindV1>([
    "reversible-workspace-edit", "commit", "merge", "package-change", "rebase",
    "approval-contract-edit", "policy-weakening", "self-widening",
  ]);
  const destructiveKinds = new Set<PolicyActionKindV1>([
    "destructive-action", "connector-delete", "force-push", "t5-action", "uninspectable-side-effect",
  ]);
  const externalWriteKinds = new Set<PolicyActionKindV1>([
    "authenticated-write", "deploy", "irreversible-action", "new-secret-scope",
    "protected-ref-mutation", "publish", "push", "release", "send", "t4-action",
    "connector-admin",
  ]);
  const connectorKinds = new Set<PolicyActionKindV1>(["connector-admin", "connector-delete"]);

  const effect = destructiveKinds.has(actionKind)
    ? "destructive" as const
    : workspaceKinds.has(actionKind)
      ? "workspace-write" as const
      : externalWriteKinds.has(actionKind)
        ? "external-write" as const
        : actionKind === "network-read"
          ? "external-read" as const
          : "none" as const;
  const operation = actionKind === "destructive-action" || actionKind === "connector-delete"
    ? "delete" as const
    : actionKind === "publish" || actionKind === "release"
      ? "export" as const
      : actionKind === "push" || actionKind === "send" || actionKind === "force-push"
        ? "send" as const
        : effect === "none" || effect === "external-read"
          ? "read" as const
          : "write" as const;
  const repositoryTransition = actionKind === "protected-ref-mutation"
    ? "protected-ref-mutation" as const
    : actionKind === "commit" || actionKind === "merge" || actionKind === "rebase"
      ? "commit" as const
      : effect === "workspace-write"
        ? "workspace-edit" as const
        : "none" as const;
  const dataAccess = operation === "export" || operation === "send"
    ? "export" as const
    : actionKind === "network-read" || actionKind === "deploy" || actionKind === "push" || actionKind === "force-push" || actionKind === "t4-action" || actionKind === "uninspectable-side-effect"
      ? "network" as const
      : actionKind === "authenticated-read" || actionKind === "authenticated-write" || connectorKinds.has(actionKind)
        ? "authenticated" as const
        : "local" as const;
  const adapterRef = connectorKinds.has(actionKind)
    ? "host-connector"
    : dataAccess === "network" || dataAccess === "authenticated" || dataAccess === "export"
      ? "host-adapter"
      : "loopeix-core";

  return ActionClassifierKey.parse({
    action_class: actionKind === "planning" || approvalClass === "automatic"
      ? "task"
      : actionKind === "reversible-workspace-edit"
        ? "artifact-write"
        : "tool",
    dispatch_kind: actionKind === "planning" || approvalClass === "automatic"
      ? "process"
      : actionKind === "reversible-workspace-edit"
        ? "artifact-write"
        : connectorKinds.has(actionKind)
          ? "connector"
          : "tool",
    adapter_ref: adapterRef,
    adapter_version_hash: hashCanonical({
      purpose: "s35-built-in-adapter-version-v1",
      adapter_ref: adapterRef,
      version: "0.1",
    }),
    capability_ref: `${actionKind}-action`,
    capability_definition_hash: hashCanonical({
      purpose: "s35-built-in-capability-v1",
      action_kind: actionKind,
      approval_class: approvalClass,
    }),
    operation,
    effective_risk_tier: approvalClass === "automatic" ? "T1" : approvalClass === "agency" ? "T2" : "T4",
    effect_classes: [effect],
    all_effects_inspectable: actionKind !== "uninspectable-side-effect",
    all_effects_reversible: effect === "none" || actionKind === "reversible-workspace-edit",
    data_access_mode: dataAccess,
    repository_transition_intent: repositoryTransition,
    cost_mode: dataAccess === "network" || dataAccess === "authenticated" || dataAccess === "export" ? "metered" : "none",
  });
}

function createS35BuiltInActionApprovalPolicyV02(): ActionApprovalPolicyV1 {
  const rules = POLICY_ACTION_KINDS.map((actionKind) => {
    const actionApprovalClass = POLICY_CLASS_BY_ACTION_KIND[actionKind];
    const key = builtInRuleKey(actionKind, actionApprovalClass);
    const preimage = {
      rule_version: "0.1" as const,
      key,
      policy_action_kind: actionKind,
      action_approval_class: actionApprovalClass,
    };
    return ActionClassifierRule.parse({
      ...preimage,
      rule_hash: hashCanonical({ purpose: "action-classifier-rule-v1", ...preimage }),
    });
  }).sort((left, right) => Buffer.from(canonicalize(left.key)).compare(Buffer.from(canonicalize(right.key))));
  const classifierRegistry = ActionClassifierRegistry.parse({
    registry_version: "0.1",
    rules,
    registry_hash: hashCanonical({
      purpose: "action-classifier-registry-v1",
      registry_version: "0.1",
      rules,
    }),
  });
  const entries = POLICY_ACTION_KINDS.map((actionKind) => ({
    action_kind: actionKind,
    approval_class: POLICY_CLASS_BY_ACTION_KIND[actionKind],
    classifier_rule_hash: rules.find((rule) => rule.policy_action_kind === actionKind)!.rule_hash,
  }));
  const registryHash = hashCanonical({
    purpose: "action-approval-policy-v1",
    registry_version: "0.1",
    classifier_registry: classifierRegistry,
    entries,
    human_exception_action_kinds: HUMAN_EXCEPTION_ACTION_KINDS,
    blocked_action_kinds: BLOCKED_ACTION_KINDS,
  });
  const candidate = ActionApprovalPolicy.parse({
    registry_version: "0.1",
    policy_digest: hashCanonical({
      purpose: "action-approval-policy-bundle-v02",
      registry_version: "0.1",
      classifier_registry: classifierRegistry,
      entries,
      human_exception_action_kinds: HUMAN_EXCEPTION_ACTION_KINDS,
      blocked_action_kinds: BLOCKED_ACTION_KINDS,
      registry_hash: registryHash,
    }),
    classifier_registry: classifierRegistry,
    entries,
    human_exception_action_kinds: HUMAN_EXCEPTION_ACTION_KINDS,
    blocked_action_kinds: BLOCKED_ACTION_KINDS,
    registry_hash: registryHash,
  });
  const problem = validatePolicy(candidate);
  if (problem !== null) throw new Error(`Invalid built-in S35 action policy: ${problem}`);
  return deepFreeze(candidate) as ActionApprovalPolicyV1;
}

const S35_BUILT_IN_ACTION_APPROVAL_POLICY_V02 = createS35BuiltInActionApprovalPolicyV02();

/** Release-pinned S35 action-approval bundle identity. */
export const S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 =
  "sha256:f9fb5daca837efaf274a0567e70d6b90c690ea7ed0ed69e8089cc16bbf6d0dd9" as const;

if (S35_BUILT_IN_ACTION_APPROVAL_POLICY_V02.policy_digest !== S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02) {
  throw new Error("The built-in S35 action-approval policy differs from its release-pinned digest.");
}

immutablePolicyRegistry.set(
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_V02,
);

/**
 * Package-private boundary for a host that acknowledges the independently
 * recomputed outer policy-bundle digest. Host equality alone is not authority.
 */
export function admitHostCapturedPolicyBundleV02(
  candidate: unknown,
  hostVerifiedPolicyDigest: string,
): AdmitHostCapturedPolicyBundleV02Result {
  const digest = Hash.safeParse(hostVerifiedPolicyDigest);
  const parsed = ActionApprovalPolicy.safeParse(candidate);
  if (!digest.success || !parsed.success || parsed.data.policy_digest !== digest.data) {
    return invalidPolicy("The host-verified digest and strict policy bundle must agree.");
  }
  const problem = validatePolicy(parsed.data);
  if (problem !== null) return invalidPolicy(problem);
  const bundle = Object.freeze({ policy_digest: digest.data }) as HostCapturedPolicyBundleV02;
  admittedBundles.set(bundle, deepFreeze(structuredClone(parsed.data)) as ActionApprovalPolicyV1);
  return { ok: true, bundle };
}

export function registerHostCapturedPolicyBundleV02(bundle: HostCapturedPolicyBundleV02): boolean {
  const policy = admittedBundles.get(bundle);
  if (policy === undefined) return false;
  admittedBundles.delete(bundle);
  const existing = immutablePolicyRegistry.get(policy.policy_digest);
  if (existing !== undefined) return canonicalize(existing) === canonicalize(policy);
  immutablePolicyRegistry.set(policy.policy_digest, policy);
  return true;
}

export function resolveImmutableActionApprovalPolicyV02(policyDigest: string): ActionApprovalPolicyV1 | null {
  const policy = immutablePolicyRegistry.get(policyDigest);
  return policy === undefined ? null : structuredClone(policy);
}

/** Package-private S35 planner boundary: no alias, override, or non-release digest resolves. */
export function resolveS35BuiltInActionApprovalPolicyV02(
  policyDigest: string,
): ActionApprovalPolicyV1 | null {
  return policyDigest === S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02
    ? structuredClone(S35_BUILT_IN_ACTION_APPROVAL_POLICY_V02)
    : null;
}

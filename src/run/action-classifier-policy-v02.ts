import { z } from "zod";

import { canonicalize, hashCanonical } from "../hash.js";
import { Hash, RiskTierV1 } from "../schema/scalars.js";
import { HumanIdV02, MachineIdV02 } from "../schema/scalars-v02.js";
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

const AgencyPolicyActionKind = z.enum([
  "authenticated-read",
  "network-read",
  "reversible-workspace-edit",
]);
const AuthorityActionClass = z.enum(["task", "tool", "artifact-write"]);
const CanonicalAuthorityReviewerRoles = z.tuple([
  z.literal("authority-governor"),
  z.literal("evidence-reviewer"),
  z.literal("scope-guardian"),
  z.literal("security-information-flow-reviewer"),
]);
const AgencyQuorumRequirementV02 = strictObject({
  requirement_ref: HumanIdV02,
  policy_digest: Hash,
  action_class: AuthorityActionClass,
  policy_action_kind: AgencyPolicyActionKind,
  action_approval_class: z.literal("agency"),
  required_reviewer_role_refs: CanonicalAuthorityReviewerRoles,
  minimum_allow_recommendations: z.literal(4),
  minimum_independent_reviewer_roots: z.literal(4),
  minimum_evidence_roots_per_recommendation: z.literal(1),
  max_recommendation_ttl_ms: z.literal(300_000),
  independent_evidence_producer_required: z.literal(true),
});
const AgencyRecommendationDecision = z.enum(["allow", "allow_with_conditions", "deny", "escalate", "abort"]);
const PolicyDecisionDecision = z.enum(["allow", "deny", "escalate", "abort", "hold"]);
const canonicalDecisionList = <T extends string>(
  decisionSchema: z.ZodType<T>,
  canonicalOrder: readonly T[],
) => z.array(decisionSchema).min(1).superRefine((decisions, context) => {
  if (new Set(decisions).size !== decisions.length) {
    context.addIssue({
      code: "custom",
      message: "compatible_decisions must be unique",
    });
  }
  const positions = decisions.map((decision) => canonicalOrder.indexOf(decision));
  if (positions.some((position, index) => index > 0 && position <= positions[index - 1]!)) {
    context.addIssue({
      code: "custom",
      message: "compatible_decisions must follow the record union's canonical order",
    });
  }
});
const CanonicalAgencyRecommendationDecisions = canonicalDecisionList(
  AgencyRecommendationDecision,
  AgencyRecommendationDecision.options,
);
const CanonicalPolicyDecisionDecisions = canonicalDecisionList(
  PolicyDecisionDecision,
  PolicyDecisionDecision.options,
);
const PolicyReasonCodeDeclarationV02 = z.discriminatedUnion("record_kind", [
  strictObject({
    record_kind: z.literal("agency-recommendation"),
    declaration_ref: HumanIdV02,
    compatible_decisions: CanonicalAgencyRecommendationDecisions,
  }),
  strictObject({
    record_kind: z.literal("policy-decision"),
    declaration_ref: HumanIdV02,
    compatible_decisions: CanonicalPolicyDecisionDecisions,
  }),
]);
const AuthorityDecisionPolicyExtensionV1 = strictObject({
  extension_version: z.literal("0.1"),
  base_policy_digest: Hash,
  quorum_requirements: z.array(AgencyQuorumRequirementV02).min(1),
  reason_declarations: z.array(PolicyReasonCodeDeclarationV02).min(1),
  extension_hash: Hash,
});

export type AgencyQuorumRequirementV02Value = z.infer<typeof AgencyQuorumRequirementV02>;
export type PolicyReasonCodeDeclarationV02Value = z.infer<typeof PolicyReasonCodeDeclarationV02>;
export type AuthorityDecisionPolicyExtensionV1Value = z.infer<typeof AuthorityDecisionPolicyExtensionV1>;
export type ValidateAuthorityDecisionPolicyExtensionV1Result =
  | Readonly<{ ok: true }>
  | Readonly<{ ok: false; reason: "INVALID_AUTHORITY_DECISION_POLICY_EXTENSION"; message: string }>;

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

const AUTHORITY_REVIEWER_ROLES_V1 = [
  "authority-governor",
  "evidence-reviewer",
  "scope-guardian",
  "security-information-flow-reviewer",
] as const;

function createQuorumRequirement(
  requirementRef: string,
  actionClass: "tool" | "artifact-write",
  policyActionKind: "authenticated-read" | "network-read" | "reversible-workspace-edit",
): AgencyQuorumRequirementV02Value {
  return AgencyQuorumRequirementV02.parse({
    requirement_ref: requirementRef,
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    action_class: actionClass,
    policy_action_kind: policyActionKind,
    action_approval_class: "agency",
    required_reviewer_role_refs: AUTHORITY_REVIEWER_ROLES_V1,
    minimum_allow_recommendations: 4,
    minimum_independent_reviewer_roots: 4,
    minimum_evidence_roots_per_recommendation: 1,
    max_recommendation_ttl_ms: 300_000,
    independent_evidence_producer_required: true,
  });
}

const S36_QUORUM_REQUIREMENTS_V1 = [
  createQuorumRequirement("agency-artifact-write-reversible-workspace-edit-v1", "artifact-write", "reversible-workspace-edit"),
  createQuorumRequirement("agency-tool-authenticated-read-v1", "tool", "authenticated-read"),
  createQuorumRequirement("agency-tool-network-read-v1", "tool", "network-read"),
] as const;

const S36_REASON_DECLARATIONS_V1 = PolicyReasonCodeDeclarationV02.array().parse([
  { record_kind: "agency-recommendation", declaration_ref: "recommendation-abort-safety", compatible_decisions: ["abort"] },
  { record_kind: "agency-recommendation", declaration_ref: "recommendation-allow-conditions", compatible_decisions: ["allow_with_conditions"] },
  { record_kind: "agency-recommendation", declaration_ref: "recommendation-allow-evidence", compatible_decisions: ["allow"] },
  { record_kind: "agency-recommendation", declaration_ref: "recommendation-deny-policy", compatible_decisions: ["deny"] },
  { record_kind: "agency-recommendation", declaration_ref: "recommendation-escalate-human", compatible_decisions: ["escalate"] },
  { record_kind: "policy-decision", declaration_ref: "decision-agency-abort", compatible_decisions: ["abort"] },
  { record_kind: "policy-decision", declaration_ref: "decision-agency-allow", compatible_decisions: ["allow"] },
  { record_kind: "policy-decision", declaration_ref: "decision-agency-condition-hold", compatible_decisions: ["hold"] },
  { record_kind: "policy-decision", declaration_ref: "decision-agency-deny", compatible_decisions: ["deny"] },
  { record_kind: "policy-decision", declaration_ref: "decision-agency-escalate", compatible_decisions: ["escalate"] },
  { record_kind: "policy-decision", declaration_ref: "decision-agency-quorum-hold", compatible_decisions: ["hold"] },
  { record_kind: "policy-decision", declaration_ref: "decision-automatic-allow", compatible_decisions: ["allow"] },
  { record_kind: "policy-decision", declaration_ref: "decision-automatic-enforcement-hold", compatible_decisions: ["hold"] },
  { record_kind: "policy-decision", declaration_ref: "decision-blocked-hold", compatible_decisions: ["hold"] },
  { record_kind: "policy-decision", declaration_ref: "decision-compensation-safety-hold", compatible_decisions: ["hold"] },
  { record_kind: "policy-decision", declaration_ref: "decision-human-exception-hold", compatible_decisions: ["hold"] },
]);

const S36_EXTENSION_PREIMAGE_V1 = {
  extension_version: "0.1" as const,
  base_policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  quorum_requirements: S36_QUORUM_REQUIREMENTS_V1,
  reason_declarations: S36_REASON_DECLARATIONS_V1,
};
const S36_BUILT_IN_AUTHORITY_DECISION_POLICY_EXTENSION_V1 = deepFreeze(AuthorityDecisionPolicyExtensionV1.parse({
  ...S36_EXTENSION_PREIMAGE_V1,
  extension_hash: hashCanonical({ purpose: "authority-decision-policy-extension-v1", ...S36_EXTENSION_PREIMAGE_V1 }),
}));

function quorumSelectorKey(selector: {
  policy_digest: string;
  action_class: string;
  policy_action_kind: string;
  action_approval_class: string;
}): string {
  return canonicalize(selector);
}

const S36_QUORUM_BY_SELECTOR_V1 = new Map(S36_QUORUM_REQUIREMENTS_V1.map((requirement) => [
  quorumSelectorKey({
    policy_digest: requirement.policy_digest,
    action_class: requirement.action_class,
    policy_action_kind: requirement.policy_action_kind,
    action_approval_class: requirement.action_approval_class,
  }),
  requirement,
]));
const S36_QUORUM_BY_HASH_V1 = new Map(S36_QUORUM_REQUIREMENTS_V1.map((requirement) => [
  hashCanonical({ purpose: "agency-quorum-requirement-v02", ...requirement }),
  requirement,
]));
const S36_REASON_BY_REF_V1 = new Map(S36_REASON_DECLARATIONS_V1.map((declaration) => [declaration.declaration_ref, declaration]));

function invalidAuthorityExtension(message: string): ValidateAuthorityDecisionPolicyExtensionV1Result {
  return { ok: false, reason: "INVALID_AUTHORITY_DECISION_POLICY_EXTENSION", message };
}

export function validateAuthorityDecisionPolicyExtensionV1(candidate: unknown): ValidateAuthorityDecisionPolicyExtensionV1Result {
  const parsed = AuthorityDecisionPolicyExtensionV1.safeParse(candidate);
  if (!parsed.success) return invalidAuthorityExtension("The authority decision-policy extension shape is invalid.");
  const { extension_hash: extensionHash, ...preimage } = parsed.data;
  if (extensionHash !== hashCanonical({ purpose: "authority-decision-policy-extension-v1", ...preimage })) {
    return invalidAuthorityExtension("The authority decision-policy extension hash is invalid.");
  }
  if (canonicalize(parsed.data) !== canonicalize(S36_BUILT_IN_AUTHORITY_DECISION_POLICY_EXTENSION_V1)) {
    return invalidAuthorityExtension("The extension does not equal the release-pinned S36 policy table.");
  }
  return { ok: true };
}

export function resolveS36BuiltInAuthorityDecisionPolicyExtensionV1(
  basePolicyDigest: string,
): AuthorityDecisionPolicyExtensionV1Value | null {
  return basePolicyDigest === S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02
    ? structuredClone(S36_BUILT_IN_AUTHORITY_DECISION_POLICY_EXTENSION_V1)
    : null;
}

export function resolveAgencyQuorumRequirementV02(selector: unknown): Readonly<{
  requirement: AgencyQuorumRequirementV02Value;
  quorum_requirement_hash: string;
}> | null {
  const parsed = strictObject({
    policy_digest: Hash,
    action_class: AuthorityActionClass,
    policy_action_kind: AgencyPolicyActionKind,
    action_approval_class: z.literal("agency"),
  }).safeParse(selector);
  if (!parsed.success) return null;
  const requirement = S36_QUORUM_BY_SELECTOR_V1.get(quorumSelectorKey(parsed.data));
  if (requirement === undefined) return null;
  return {
    requirement: structuredClone(requirement),
    quorum_requirement_hash: hashCanonical({ purpose: "agency-quorum-requirement-v02", ...requirement }),
  };
}

export function resolveAuthorityPolicyReasonDeclarationV02(
  policyDigest: string,
  declarationRef: string,
): PolicyReasonCodeDeclarationV02Value | null {
  if (policyDigest !== S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02) return null;
  const declaration = S36_REASON_BY_REF_V1.get(declarationRef);
  return declaration === undefined ? null : structuredClone(declaration);
}

export function resolveAgencyQuorumRequirementByHashV02(
  policyDigest: string,
  quorumRequirementHash: string,
): Readonly<{ requirement: AgencyQuorumRequirementV02Value; quorum_requirement_hash: string }> | null {
  if (policyDigest !== S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 || !Hash.safeParse(quorumRequirementHash).success) {
    return null;
  }
  const requirement = S36_QUORUM_BY_HASH_V1.get(quorumRequirementHash);
  return requirement === undefined
    ? null
    : { requirement: structuredClone(requirement), quorum_requirement_hash: quorumRequirementHash };
}

export function authorityPolicyReasonRefIsCompatibleV02(
  policyDigest: string,
  declarationRef: string,
  recordKind: string,
  decision: string,
): boolean {
  const declaration = resolveAuthorityPolicyReasonDeclarationV02(policyDigest, declarationRef);
  if (declaration === null || declaration.record_kind !== recordKind) return false;
  return (declaration.compatible_decisions as readonly string[]).includes(decision);
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

const DecisionLedgerRefV02 = strictObject({ ledger_sequence: z.number().int().nonnegative(), event_hash: Hash });
const DecisionProposalV02 = strictObject({
  action_proposal_id: MachineIdV02, action_proposal_hash: Hash,
  action_class: z.enum(["task", "tool", "artifact-write"]),
  policy_action_kind: PolicyActionKind, action_approval_class: ActionApprovalClass,
  policy_digest: Hash, action_scope_hash: Hash, normalized_dispatch_hash: Hash,
  repository_pre_state_hash: Hash, classifier_rule_hash: Hash, data_flow_hash: Hash,
  effective_risk_tier: RiskTierV1,
});
const DecisionRecommendationV02 = strictObject({
  verified: z.literal(true), event_ref: DecisionLedgerRefV02, recommendation_id: MachineIdV02,
  action_proposal_hash: Hash, reviewer_view_hash: Hash, quorum_requirement_hash: Hash, reviewed_through_ref: DecisionLedgerRefV02,
  evaluator_role_ref: HumanIdV02, evaluator_stable_identity_hash: Hash,
  decision: z.enum(["allow", "allow_with_conditions", "deny", "escalate", "abort"]),
  conditions: z.array(z.unknown()), evidence_refs: z.array(DecisionLedgerRefV02).min(1),
  evidence_independence_keys: z.array(Hash).min(1), issued_at: z.string().check(z.iso.datetime()), expires_at: z.string().check(z.iso.datetime()),
});
const AuthorityDecisionSimulationInputV02 = strictObject({
  proposal: DecisionProposalV02,
  reviewer_view_hash: Hash,
  reviewed_through_ref: DecisionLedgerRefV02,
  recommendations: z.array(DecisionRecommendationV02),
  authority: strictObject({ envelope_verified: z.boolean(), contained: z.boolean(), proof_fresh: z.boolean(), revocation_epoch_current: z.boolean() }),
  enforcement: strictObject({ available: z.boolean(), information_flow_allowed: z.boolean(), gates_passed: z.boolean(), immediate_revalidation_passed: z.boolean() }),
  condition_results: z.array(strictObject({ condition_hash: Hash, satisfied: z.boolean() })),
  issued_at: z.string().check(z.iso.datetime()), expires_at: z.string().check(z.iso.datetime()), fence_epoch: z.number().int().nonnegative(),
});
type AuthorityDecisionSimulationInputV02Value = z.infer<typeof AuthorityDecisionSimulationInputV02>;
export type SimulatedAuthorityLeaseV02 = Readonly<{
  durable: false; single_use_slot: 0; action_proposal_hash: string;
  invalidation_fingerprint: string; lease_simulation_hash: string;
}>;
export type AuthorityDecisionSimulationValueV02 = Readonly<{
  decision: "allow" | "deny" | "escalate" | "abort" | "hold";
  decision_disposition: "lease-eligible" | "proposal-final" | "human-exception-required" | "abort-run" | "redecide-after-prefix-change" | "non-resumable";
  reason_codes: readonly Readonly<{ policy_digest: string; declaration_ref: string }>[];
  required_reviewer_role_refs: readonly string[];
  quorum_requirement_hash: string | null;
  recommendation_event_refs: readonly z.infer<typeof DecisionLedgerRefV02>[];
  condition_hashes: readonly string[]; failed_condition_hashes: readonly string[];
  simulated_lease: SimulatedAuthorityLeaseV02 | null;
  decision_simulation_hash: string;
}>;

function decisionReasonV02(policyDigest: string, declarationRef: string) {
  return Object.freeze({ policy_digest: policyDigest, declaration_ref: declarationRef });
}

function authorityDecisionInputFingerprintV02(input: AuthorityDecisionSimulationInputV02Value): string {
  return hashCanonical({ purpose: "authority-decision-invalidation-fingerprint-v02", ...input });
}

function finalizeAuthorityDecisionV02(
  input: AuthorityDecisionSimulationInputV02Value,
  branch: Omit<AuthorityDecisionSimulationValueV02, "decision_simulation_hash" | "simulated_lease">,
): AuthorityDecisionSimulationValueV02 {
  const invalidationFingerprint = authorityDecisionInputFingerprintV02(input);
  const simulatedLease = branch.decision === "allow" && branch.decision_disposition === "lease-eligible"
    ? Object.freeze({
      durable: false as const, single_use_slot: 0 as const,
      action_proposal_hash: input.proposal.action_proposal_hash,
      invalidation_fingerprint: invalidationFingerprint,
      lease_simulation_hash: hashCanonical({
        purpose: "simulated-authority-lease-v02", action_proposal_hash: input.proposal.action_proposal_hash,
        invalidation_fingerprint: invalidationFingerprint, single_use_slot: 0,
      }),
    }) : null;
  const withoutHash = { ...branch, simulated_lease: simulatedLease };
  return Object.freeze({
    ...withoutHash,
    decision_simulation_hash: hashCanonical({ purpose: "authority-decision-simulation-v02", ...withoutHash }),
  });
}

/** Pure S36 decision point. It consumes admitted facts and cannot write, execute, or issue a durable lease. */
export function simulateAuthorityDecisionV02(input: unknown): Readonly<{ ok: true; value: AuthorityDecisionSimulationValueV02 }>
  | Readonly<{ ok: false; error: "AUTHORITY_DECISION_INPUT_INVALID" }> {
  const parsed = AuthorityDecisionSimulationInputV02.safeParse(input);
  if (!parsed.success) return { ok: false, error: "AUTHORITY_DECISION_INPUT_INVALID" };
  const facts = parsed.data; const proposal = facts.proposal;
  const common = { recommendation_event_refs: [] as z.infer<typeof DecisionLedgerRefV02>[], condition_hashes: [] as string[], failed_condition_hashes: [] as string[] };
  const protectedBranch = proposal.action_approval_class === "blocked" ? "decision-blocked-hold"
    : proposal.action_approval_class === "human_exception" ? "decision-human-exception-hold" : null;
  if (protectedBranch !== null) return { ok: true, value: finalizeAuthorityDecisionV02(facts, {
    decision: "hold", decision_disposition: "non-resumable", reason_codes: [decisionReasonV02(proposal.policy_digest, protectedBranch)],
    required_reviewer_role_refs: [], quorum_requirement_hash: null, ...common,
  }) };
  const hardClosed = !facts.authority.envelope_verified || !facts.authority.contained || !facts.authority.proof_fresh
    || !facts.authority.revocation_epoch_current || !facts.enforcement.available || !facts.enforcement.information_flow_allowed
    || !facts.enforcement.gates_passed || !facts.enforcement.immediate_revalidation_passed
    || Date.parse(facts.issued_at) >= Date.parse(facts.expires_at);
  if (proposal.action_approval_class === "automatic") {
    const kindAllowed = ["planning", "local-read", "deterministic-no-side-effect-check"].includes(proposal.policy_action_kind);
    if (hardClosed || !kindAllowed) return { ok: true, value: finalizeAuthorityDecisionV02(facts, {
      decision: "hold", decision_disposition: "non-resumable",
      reason_codes: [decisionReasonV02(proposal.policy_digest, "decision-automatic-enforcement-hold")],
      required_reviewer_role_refs: [], quorum_requirement_hash: null, ...common,
    }) };
    return { ok: true, value: finalizeAuthorityDecisionV02(facts, {
      decision: "allow", decision_disposition: "lease-eligible",
      reason_codes: [decisionReasonV02(proposal.policy_digest, "decision-automatic-allow")],
      required_reviewer_role_refs: [], quorum_requirement_hash: null, ...common,
    }) };
  }
  const quorum = resolveAgencyQuorumRequirementV02({
    policy_digest: proposal.policy_digest, action_class: proposal.action_class,
    policy_action_kind: proposal.policy_action_kind, action_approval_class: proposal.action_approval_class,
  });
  if (quorum === null) return { ok: false, error: "AUTHORITY_DECISION_INPUT_INVALID" };
  const requiredRoles = [...quorum.requirement.required_reviewer_role_refs];
  const eventRefs = facts.recommendations.map(({ event_ref }) => event_ref);
  const roots = facts.recommendations.map(({ evaluator_stable_identity_hash }) => evaluator_stable_identity_hash);
  const roles = facts.recommendations.map(({ evaluator_role_ref }) => evaluator_role_ref);
  const decisionTime = Date.parse(facts.issued_at);
  const completeWindow = facts.recommendations.length === requiredRoles.length
    && facts.recommendations.length >= quorum.requirement.minimum_allow_recommendations
    && new Set(roots).size === facts.recommendations.length
    && new Set(roots).size >= quorum.requirement.minimum_independent_reviewer_roots
    && requiredRoles.every((role) => roles.filter((value) => value === role).length === 1)
    && roles.every((role) => requiredRoles.includes(role as never))
    && facts.recommendations.every((recommendation, index) =>
      recommendation.action_proposal_hash === proposal.action_proposal_hash
      && recommendation.reviewer_view_hash === facts.reviewer_view_hash
      && recommendation.quorum_requirement_hash === quorum.quorum_requirement_hash
      && canonicalize(recommendation.reviewed_through_ref) === canonicalize(facts.reviewed_through_ref)
      && recommendation.event_ref.ledger_sequence === facts.reviewed_through_ref.ledger_sequence + index + 1
      && Date.parse(recommendation.issued_at) <= decisionTime && decisionTime < Date.parse(recommendation.expires_at)
      && Date.parse(recommendation.expires_at) - Date.parse(recommendation.issued_at) <= quorum.requirement.max_recommendation_ttl_ms
      && recommendation.evidence_refs.length >= quorum.requirement.minimum_evidence_roots_per_recommendation
      && recommendation.evidence_independence_keys.length >= quorum.requirement.minimum_evidence_roots_per_recommendation);
  if (hardClosed || !completeWindow) return { ok: true, value: finalizeAuthorityDecisionV02(facts, {
    decision: "hold", decision_disposition: "non-resumable", reason_codes: [decisionReasonV02(proposal.policy_digest, "decision-agency-quorum-hold")],
    required_reviewer_role_refs: requiredRoles, quorum_requirement_hash: quorum.quorum_requirement_hash, ...common, recommendation_event_refs: eventRefs,
  }) };
  const combined = facts.recommendations.some(({ decision }) => decision === "abort") ? "abort"
    : facts.recommendations.some(({ decision }) => decision === "deny") ? "deny"
      : facts.recommendations.some(({ decision }) => decision === "escalate") ? "escalate" : "allow";
  const conditionHashes = [...new Set(facts.recommendations.flatMap(({ conditions }) => conditions.map((condition) => hashCanonical({ purpose: "agency-recommendation-condition-v02", condition }))))].sort();
  const failed = conditionHashes.filter((conditionHash) => !facts.condition_results.some((result) => result.condition_hash === conditionHash && result.satisfied));
  if (combined === "allow" && failed.length > 0) return { ok: true, value: finalizeAuthorityDecisionV02(facts, {
    decision: "hold", decision_disposition: "redecide-after-prefix-change", reason_codes: [decisionReasonV02(proposal.policy_digest, "decision-agency-condition-hold")],
    required_reviewer_role_refs: requiredRoles, quorum_requirement_hash: quorum.quorum_requirement_hash,
    recommendation_event_refs: eventRefs, condition_hashes: conditionHashes, failed_condition_hashes: failed,
  }) };
  const disposition = combined === "abort" ? "abort-run" : combined === "deny" ? "proposal-final"
    : combined === "escalate" ? "human-exception-required" : "lease-eligible";
  return { ok: true, value: finalizeAuthorityDecisionV02(facts, {
    decision: combined, decision_disposition: disposition,
    reason_codes: [decisionReasonV02(proposal.policy_digest, `decision-agency-${combined}`)],
    required_reviewer_role_refs: requiredRoles, quorum_requirement_hash: quorum.quorum_requirement_hash,
    recommendation_event_refs: eventRefs, condition_hashes: conditionHashes, failed_condition_hashes: [],
  }) };
}

/** Pure immediate revalidation: any input drift or failed enforcement invalidates the in-memory slot. */
export function revalidateSimulatedAuthorityLeaseV02(
  lease: SimulatedAuthorityLeaseV02,
  input: unknown,
): Readonly<{ ok: true }> | Readonly<{ ok: false; error: "SIMULATED_LEASE_INVALID" }> {
  const parsedLease = z.object({
    durable: z.literal(false), single_use_slot: z.literal(0), action_proposal_hash: Hash,
    invalidation_fingerprint: Hash, lease_simulation_hash: Hash,
  }).strict().safeParse(lease);
  const parsedInput = AuthorityDecisionSimulationInputV02.safeParse(input);
  if (!parsedLease.success || !parsedInput.success || !parsedInput.data.enforcement.immediate_revalidation_passed
    || parsedLease.data.action_proposal_hash !== parsedInput.data.proposal.action_proposal_hash
    || parsedLease.data.invalidation_fingerprint !== authorityDecisionInputFingerprintV02(parsedInput.data)
    || parsedLease.data.lease_simulation_hash !== hashCanonical({
      purpose: "simulated-authority-lease-v02", action_proposal_hash: parsedLease.data.action_proposal_hash,
      invalidation_fingerprint: parsedLease.data.invalidation_fingerprint, single_use_slot: 0,
    })) return { ok: false, error: "SIMULATED_LEASE_INVALID" };
  return { ok: true };
}

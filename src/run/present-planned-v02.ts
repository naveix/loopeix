import { canonicalize } from "../hash.js";
import { hashCanonical } from "../hash.js";
import { z } from "zod";
import { Hash } from "../schema/scalars.js";
import type { PlanReportControlRowV02 } from "../report/plan-renderer.js";
import type { ResolvedRunPlanV02Value } from "../schema/runtime.js";

export type PlannedRunPresentationV02 = Readonly<{
  schema_version: "0.2";
  execution_profile: "bounded-v02";
  run_id: string;
  run_state: "planned";
  execution_supported: false;
  controls_enforced: false;
  reason: "UNSUPPORTED_EXECUTION_PROFILE";
  work_execution: "NOT EXECUTED";
  control_enforcement: "NOT ENFORCED";
  next_action: null;
  controls: readonly PlanReportControlRowV02[];
}>;

type ControlCategory = PlanReportControlRowV02["category"];

const DELEGATION_PROFILES_V02 = Object.freeze({
  manual_every_action: Object.freeze({
    profile: "manual_every_action" as const, delegated_action_classes: [] as readonly string[], operations: [] as readonly string[],
    workspace_write: false, reversible_only: true, human_approval_required_for_every_action: true,
  }),
  read_only_research: Object.freeze({
    profile: "read_only_research" as const, delegated_action_classes: ["agency"] as readonly string[],
    operations: ["read", "list", "search"] as const, workspace_write: false, reversible_only: true,
    human_approval_required_for_every_action: false,
  }),
  bounded_workspace: Object.freeze({
    profile: "bounded_workspace" as const, delegated_action_classes: ["agency"] as readonly string[],
    operations: ["create", "append", "update", "rename"] as const, workspace_write: true, reversible_only: true,
    human_approval_required_for_every_action: false,
  }),
});

/** Expands a convenience label into a conservative proposal only; the profile name is never authority. */
export function expandDelegationProfileV02(profile: unknown): Readonly<{ ok: true; value: typeof DELEGATION_PROFILES_V02[keyof typeof DELEGATION_PROFILES_V02] }>
  | Readonly<{ ok: false; error: "DELEGATION_PROFILE_INVALID" }> {
  if (typeof profile !== "string" || !Object.hasOwn(DELEGATION_PROFILES_V02, profile)) return { ok: false, error: "DELEGATION_PROFILE_INVALID" };
  return { ok: true, value: structuredClone(DELEGATION_PROFILES_V02[profile as keyof typeof DELEGATION_PROFILES_V02]) };
}

const AuthorityPreviewSubjectV02 = z.object({
  preview_kind: z.enum(["mandate", "exception", "pause", "resume", "revoke", "deny", "answer", "abort"]),
  action_proposal_hash: Hash, action_scope_hash: Hash,
  scope_delta: z.object({
    operations_added: z.array(z.never()).max(0), selectors_added: z.array(z.never()).max(0), risk_change: z.null(),
  }).strict(),
  reversible: z.boolean(), evidence_needed: z.array(z.string().min(1)),
  safe_default: z.enum(["hold", "deny", "abort"]),
  smallest_safe_alternative: z.object({ operation: z.string().min(1), target_ref: z.string().min(1) }).strict(),
  requested_decision: z.enum(["mandate", "pause", "resume", "revoke", "deny", "answer", "abort"]),
  reason_ref: z.string().min(1), resume_boundary: z.string().min(1), policy_digest: Hash,
}).strict();
const AuthorityInteractionViewInputV02 = z.object({
  view: z.enum(["guided", "standard", "expert"]), subject: AuthorityPreviewSubjectV02,
}).strict();

/** Renders density-only projections over one exact typed authority subject. */
export function projectAuthorityInteractionViewV02(input: unknown): Readonly<{ ok: true; value: Readonly<Record<string, unknown>> }>
  | Readonly<{ ok: false; error: "AUTHORITY_PREVIEW_INVALID" }> {
  const parsed = AuthorityInteractionViewInputV02.safeParse(input);
  if (!parsed.success) return { ok: false, error: "AUTHORITY_PREVIEW_INVALID" };
  const { view, subject } = parsed.data;
  const authorityFingerprint = hashCanonical({ purpose: "authority-preview-subject-v02", ...subject });
  const common = {
    view, preview_kind: subject.preview_kind, action_proposal_hash: subject.action_proposal_hash,
    reversible: subject.reversible, evidence_needed: subject.evidence_needed,
    safe_default: subject.safe_default, smallest_safe_alternative: subject.smallest_safe_alternative,
    requested_decision: subject.requested_decision, authority_fingerprint: authorityFingerprint,
    scope_delta: subject.scope_delta,
  };
  const density = view === "guided" ? {}
    : view === "standard" ? { reason_ref: subject.reason_ref, resume_boundary: subject.resume_boundary }
      : { reason_ref: subject.reason_ref, resume_boundary: subject.resume_boundary, action_scope_hash: subject.action_scope_hash, policy_digest: subject.policy_digest };
  return { ok: true, value: Object.freeze({ ...common, ...density }) };
}

function row(
  category: ControlCategory,
  controlRef: string,
  label: string,
  value: unknown,
): PlanReportControlRowV02 {
  return Object.freeze({
    category,
    control_ref: controlRef,
    label,
    value: canonicalize(value),
  });
}

function indexedRows(
  category: ControlCategory,
  prefix: string,
  label: string,
  values: readonly unknown[],
): PlanReportControlRowV02[] {
  return values.map((value, index) => row(category, `${prefix}-${index.toString().padStart(6, "0")}`, label, value));
}

export function presentPlannedRunV02(plan: ResolvedRunPlanV02Value): PlannedRunPresentationV02 {
  const controls: PlanReportControlRowV02[] = [
    row("trigger", "trigger", "Trigger", plan.trigger),
    row("goal", "goal", "Goal", plan.goal),
    row("context", "assurance-profile", "Assurance profile", plan.assurance_profile),
    row("context", "context-snapshot", "Context snapshot", plan.context_snapshot),
    ...indexedRows("context", "role", "Specialist role", plan.roles),
    ...indexedRows("context", "task", "Task", plan.tasks),
    ...indexedRows("context", "tool-grant", "Tool grant", plan.tool_grants),
    row("context", "workspace-boundary", "Workspace boundary", plan.workspace_boundary),
    row("progress", "progress-policy", "Progress policy", plan.progress),
    row("stop", "stop-policy", "Stop policy", plan.stop_policy),
    row("limit", "limit-policy", "Limit policy", plan.limit_policy),
    row("limit", "required-control-plane-output-bytes", "Required control-plane output bytes", plan.required_control_plane_output_bytes),
    row("limit", "runtime-record-limits", "Runtime record limits", plan.runtime_record_limits),
    row("retry", "retry-policy", "Retry policy", plan.retry_policy),
    ...indexedRows("retry", "retry-rule", "Retry rule", plan.retry_policy.rules),
    row("recovery", "recovery-policy", "Recovery policy", plan.recovery_policy),
    ...indexedRows("side-effect", "side-effect", "Side-effect policy", plan.side_effects),
    ...indexedRows("compensation", "compensation", "Compensation", plan.compensations),
    ...indexedRows("gate", "gate", "Gate", plan.gates),
    ...indexedRows("evaluation", "evaluation", "Evaluation", plan.evaluations),
    ...indexedRows("evaluation", "evidence-requirement", "Evidence requirement", plan.evidence_requirements),
    ...indexedRows("terminal", "terminal-state", "Terminal state", plan.stop_policy.terminal_states),
    row("engine", "adapter-plan", "Adapter plan", plan.adapter_plan),
    row("engine", "risk-controls", "Risk controls", plan.risk_controls),
    row("proof-boundary", "authority-subject", "Authority subject", plan.authority_subject),
    row("proof-boundary", "compile-lineage", "Compile lineage", {
      loopeix_version: plan.loopeix_version,
      loopeix_version_hash: plan.loopeix_version_hash,
      source_authoring_hash: plan.source_authoring_hash,
      compiler_bundle_id: plan.compiler_bundle_id,
      catalog_version_hash: plan.catalog_version_hash,
      binding_input_id: plan.binding_input_id,
      binding_input_hash: plan.binding_input_hash,
      compile_pack_manifest_hash: plan.compile_pack_manifest_hash,
      work_item_id: plan.work_item_id,
      intake_brief_id: plan.intake_brief_id,
    }),
    ...indexedRows("proof-boundary", "role-assignment", "Role assignment", plan.role_assignments),
  ];

  return Object.freeze({
    schema_version: "0.2",
    execution_profile: "bounded-v02",
    run_id: plan.run_id,
    run_state: "planned",
    execution_supported: false,
    controls_enforced: false,
    reason: "UNSUPPORTED_EXECUTION_PROFILE",
    work_execution: "NOT EXECUTED",
    control_enforcement: "NOT ENFORCED",
    next_action: null,
    controls: Object.freeze(controls),
  });
}

import { compareUtf8BytesV02 } from "../catalog/item-v02.js";
import { lookupRegisteredCatalogV02 } from "../catalog/registry.js";
import { deriveControlPlaneBudgetV02 } from "../compiler/control-plane-budget-v02.js";
import { projectCatalogEntryV02 } from "../compiler/project-v02.js";
import type { ReadCompilePackV02Success } from "../compiler/read-pack-v02.js";
import {
  ApprovedIntakeBriefV02,
  type ApprovedIntakeBriefV02 as ApprovedIntakeBriefV02Value,
} from "../compiler/records.js";
import {
  consumeExactV02ReplayForPlanning,
  type ExactV02ReplaySuccess,
} from "../compiler/replay-v02.js";
import { hashCanonical, hashRawBytes } from "../hash.js";
import { parseDirectChildName, type DirectChildName } from "../io/captured-file.js";
import {
  ResolvedRunPlanV02,
  type ResolvedRunPlanV02Value,
} from "../schema/runtime.js";
import {
  resolveS35BuiltInActionApprovalPolicyV02,
} from "./action-classifier-policy-v02.js";
import {
  consumeApprovedAuthorityPlanningInputV02,
  type ApprovedAuthorityPlanningInputV02,
  type AuthorityPlanningInputV02Value,
} from "./authority-planning-input-v02.js";
import type { PlanIdentityV02 } from "./plan-id-v02.js";
import {
  consumeApprovedRepositoryObservationV02,
  type ApprovedRepositoryObservationV02,
  type RepositoryStateObservationV02,
} from "./repository-observation-v02.js";

const UTF8 = new TextEncoder();
const MAX_CANDIDATE_PROJECTIONS = 16;
const INVALIDATION_RULES = [
  "spec-subject-changed",
  "compile-subject-changed",
  "plan-hash-changed",
  "planning-approval-changed",
  "policy-digest-changed",
  "repository-root-changed",
  "repository-base-ref-changed",
  "repository-state-chain-broken",
  "authorized-change-set-mismatched",
  "tool-definition-changed",
  "authority-revoked",
  "authority-expired",
] as const;

export type PlanProjectionResult =
  | {
      ok: true;
      disposition: "planned";
      schema_version: "0.2";
      run_id: string;
      resolved_run_plan_hash: string;
      run_ref: string;
      reason: null;
      findings: [];
    }
  | PlanProjectionHoldV02;

export type PlanProjectionHoldV02 = {
  ok: false;
  disposition: "hold";
  schema_version: "0.2";
  terminal_state: "hold-ambiguous" | "hold-risk" | "hold-no-item" | "hold-project-binding-required" | null;
  run_id: null;
  resolved_run_plan_hash: null;
  run_ref: null;
  reason:
    | "CATALOG_AMBIGUOUS"
    | "RISK_BOUNDARY_UNRESOLVED"
    | "NO_CATALOG_ITEM"
    | "PROJECT_BINDING_REQUIRED"
    | "PLAN_BINDING_MISMATCH"
    | "INVALID_AUTHORITY_PLANNING_INPUT"
    | "INVALID_COMPILE_PACK"
    | "INVALID_V02_PROJECTION";
  findings: [];
};

export type PlanProjectionExpectedInputV02 = Readonly<{
  engine: "codex" | "claude";
  workspace_root: string;
}>;

export type PreflightedPlanV02 = Readonly<{
  loop_family: string;
  readonly __preflighted_plan_v02: unique symbol;
}>;

export type PreparedPlanProjectionV02 = Readonly<{
  run_id: string;
  readonly __prepared_plan_projection_v02: unique symbol;
}>;

export type PreparedPlanMemberV02 = Readonly<{
  name: DirectChildName;
  bytes: Uint8Array;
}>;

export type PreparedPlanProjectionSnapshotV02 = Readonly<{
  intake_brief: ApprovedIntakeBriefV02Value;
  resolved_run_plan: ResolvedRunPlanV02Value;
  output_descriptor: Readonly<{
    kind: "plan";
    schema_version: "0.2";
    source_pack_root_hash: string;
    run_id: string;
    output_budget_bytes: 33_554_432;
    loop_family: string;
    workspace_root_hash: string;
    engine: "codex" | "claude";
  }>;
  members: readonly PreparedPlanMemberV02[];
}>;

export type PreflightPlannedRunV02Result =
  | Readonly<{
      ok: true;
      disposition: "preflighted";
      schema_version: "0.2";
      loop_family: string;
      preflight: PreflightedPlanV02;
      reason: null;
      findings: [];
    }>
  | PlanProjectionHoldV02;

export type ProjectPreflightedRunV02Result =
  | Readonly<{
      ok: true;
      disposition: "prepared";
      schema_version: "0.2";
      run_id: string;
      prepared: PreparedPlanProjectionV02;
      reason: null;
      findings: [];
    }>
  | PlanProjectionHoldV02;

type PreflightState = {
  source_pack_root_hash: string;
  authority: AuthorityPlanningInputV02Value;
  observation: RepositoryStateObservationV02;
  policy: ResolvedRunPlanV02Value["authority_subject"]["protection"]["action_approval_policy"];
  generated_loop_bytes: Uint8Array;
  generated_loop: NonNullable<ReadCompilePackV02Success["generated_loop"]>;
  selected_minimum_assurance_profile: string;
  resolved_plan_input: Readonly<{
    adapter_plan: ResolvedRunPlanV02Value["adapter_plan"];
    workspace_boundary: ResolvedRunPlanV02Value["workspace_boundary"];
  }>;
  runtime_record_limits: ResolvedRunPlanV02Value["runtime_record_limits"];
  required_control_plane_output_bytes: number;
  read: ReadCompilePackV02Success;
  projected_identity_keys: Set<string>;
  projection_count: number;
};

const preflightRegistry = new WeakMap<PreflightedPlanV02, PreflightState>();
const preparedRegistry = new WeakMap<PreparedPlanProjectionV02, PreparedPlanProjectionSnapshotV02>();

function hold(
  reason: PlanProjectionHoldV02["reason"],
  terminalState: PlanProjectionHoldV02["terminal_state"] = null,
): PlanProjectionHoldV02 {
  return {
    ok: false,
    disposition: "hold",
    schema_version: "0.2",
    terminal_state: terminalState,
    run_id: null,
    resolved_run_plan_hash: null,
    run_ref: null,
    reason,
    findings: [],
  };
}

function compilerHold(terminalState: string): PlanProjectionHoldV02 | null {
  switch (terminalState) {
    case "hold-ambiguous": return hold("CATALOG_AMBIGUOUS", terminalState);
    case "hold-risk": return hold("RISK_BOUNDARY_UNRESOLVED", terminalState);
    case "hold-no-item": return hold("NO_CATALOG_ITEM", terminalState);
    case "hold-project-binding-required": return hold("PROJECT_BINDING_REQUIRED", terminalState);
    default: return null;
  }
}

function fixedName(value: string): DirectChildName | null {
  return parseDirectChildName(value);
}

function snapshotMember(
  read: PreflightState["read"],
  name: string,
): Uint8Array | null {
  const parsed = fixedName(name);
  if (parsed === null) return null;
  const result = read.pack.snapshotMemberBytes(parsed);
  return result.ok ? new Uint8Array(result.value) : null;
}

function sameValue(left: unknown, right: unknown): boolean {
  try {
    return hashCanonical(left) === hashCanonical(right);
  } catch {
    return false;
  }
}

function expectedRoleAssignments(
  roles: readonly { id: string }[],
  assignments: AuthorityPlanningInputV02Value["role_assignments"],
): boolean {
  const roleIds = roles.map(({ id }) => id);
  if (new Set(roleIds).size !== roleIds.length || assignments.length !== roleIds.length) return false;
  const assigned = assignments.map(({ role_ref }) => role_ref);
  return assigned.every((role, index) => role === [...roleIds].sort(compareUtf8BytesV02)[index]);
}

function evaluatorBindingsAreApproved(
  generated: NonNullable<PreflightState["read"]["generated_loop"]>,
  assignments: AuthorityPlanningInputV02Value["role_assignments"],
  policyDigest: string,
): boolean {
  return [...generated.gates, ...generated.evaluations].every(({ evaluator_binding: binding }) =>
    binding.policy_digest === policyDigest
    && assignments.filter(({ role_ref, actor_ref }) =>
      role_ref === binding.role_ref && actor_ref === binding.evaluator_identity_ref).length === 1);
}

function validIdentity(identity: PlanIdentityV02): boolean {
  const match = /^([0-9a-z]+)_([0-9a-f]{16})$/u.exec(identity.plan_token);
  if (match === null || identity.run_id !== `run_${identity.plan_token}`) return false;
  const milliseconds = Number.parseInt(match[1]!, 36);
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) return false;
  const expected = new Date(milliseconds).toISOString();
  return identity.created_at === `${expected.slice(0, 19)}Z`;
}

function runtimeRecordLimits(plan: Pick<ResolvedRunPlanV02Value,
  "tasks" | "gates" | "evaluations" | "artifacts" | "goal" | "compensations" | "retry_policy"
>): ResolvedRunPlanV02Value["runtime_record_limits"] | null {
  const retryByTask = new Map<string, number>();
  for (const rule of plan.retry_policy.rules) {
    retryByTask.set(rule.task_ref, Math.max(retryByTask.get(rule.task_ref) ?? 0, rule.max_task_executions));
  }
  const attemptBudget = plan.tasks.reduce((sum, task) => sum + (retryByTask.get(task.id) ?? 0), 0);
  const G = plan.gates.length;
  const E = plan.evaluations.length;
  const R = plan.artifacts.length;
  const S = plan.goal.success_criteria.length;
  const C = plan.compensations.length;
  const evidence = 8 * attemptBudget + 12 * G + 4 * E + 2 * R + 32;
  const values = [attemptBudget, G, E, R, S, C, evidence];
  if (values.some((value) => !Number.isSafeInteger(value) || value < 0)) return null;
  const result = {
    max_authority_records: 9 * attemptBudget + 10 * G,
    max_agency_recommendation_records: 8 * (2 * attemptBudget + C),
    max_authority_revocation_records: attemptBudget + 2 * G,
    max_evidence_records: evidence,
    max_task_result_records: attemptBudget,
    max_manual_observation_records: evidence,
    max_export_decision_records: R + evidence,
    max_claim_records: S + G + E,
    max_finding_records: 4 * attemptBudget + 2 * G + 2 * E + 2 * R + 32,
    max_waiver_records: G,
    max_preseal_custody_events: 2 * (R + evidence),
  };
  return Object.values(result).every((value) => Number.isSafeInteger(value) && value > 0) ? result : null;
}

function compileToken(workItemId: string): string | null {
  const match = /^wi_([0-9a-z]+_[0-9a-f]{16})$/u.exec(workItemId);
  return match?.[1] ?? null;
}

export function preflightPlannedRunV02(
  replay: ExactV02ReplaySuccess,
  authority: ApprovedAuthorityPlanningInputV02,
  repositoryObservation: ApprovedRepositoryObservationV02 | undefined,
  expected: PlanProjectionExpectedInputV02,
): PreflightPlannedRunV02Result {
  const read = consumeExactV02ReplayForPlanning(replay);
  const approved = consumeApprovedAuthorityPlanningInputV02(authority);
  if (read === null || approved === null) return hold("INVALID_COMPILE_PACK");
  const terminal = compilerHold(read.manifest.terminal_state);
  if (terminal !== null) return terminal;
  if (read.manifest.terminal_state !== "compiled" || read.generated_loop === null || read.compilation === null) {
    return hold("INVALID_COMPILE_PACK");
  }
  const manifestBytes = snapshotMember(read, "pack-manifest.json");
  const generatedLoopBytes = snapshotMember(read, "generated.loop.yaml");
  if (manifestBytes === null || generatedLoopBytes === null
    || approved.compile_pack_manifest_hash !== hashRawBytes(manifestBytes)
    || read.manifest.generated_loop_hash !== hashRawBytes(generatedLoopBytes)) {
    return hold("INVALID_V02_PROJECTION");
  }
  const policy = resolveS35BuiltInActionApprovalPolicyV02(approved.policy_digest);
  if (policy === null) return hold("INVALID_AUTHORITY_PLANNING_INPUT");
  if (repositoryObservation === undefined) return hold("INVALID_V02_PROJECTION");
  const observed = consumeApprovedRepositoryObservationV02(repositoryObservation);
  if (observed === null
    || observed.repository_root_ref !== approved.repository.repository_root_ref
    || observed.base_ref_identity_hash !== approved.repository.base_ref.identity_hash
    || observed.head.algorithm !== approved.repository.object_format
    || observed.merge_base.algorithm !== approved.repository.object_format) {
    return hold("INVALID_AUTHORITY_PLANNING_INPUT");
  }

  const catalog = lookupRegisteredCatalogV02(read.selector);
  const selected = catalog.ok
    ? catalog.entries.find(({ item_id }) => item_id === read.manifest.selected_item_id)
    : undefined;
  if (selected === undefined) return hold("INVALID_V02_PROJECTION");
  const projection = projectCatalogEntryV02({ entry: selected, binding_input: read.binding_input });
  if (!projection.ok
    || !sameValue(projection.value.authoring, read.generated_loop)
    || projection.value.approved_intake_brief.objective !== read.intake.objective) {
    return hold("INVALID_V02_PROJECTION");
  }
  if (projection.value.resolved_plan_input.workspace_boundary.workspace_root !== expected.workspace_root
    || projection.value.resolved_plan_input.adapter_plan.engine !== `${expected.engine}_cli`) {
    return hold("PLAN_BINDING_MISMATCH");
  }
  if (!expectedRoleAssignments(read.generated_loop.roles, approved.role_assignments)
    || !evaluatorBindingsAreApproved(read.generated_loop, approved.role_assignments, approved.policy_digest)) {
    return hold("INVALID_AUTHORITY_PLANNING_INPUT");
  }
  const limits = runtimeRecordLimits(read.generated_loop);
  if (limits === null) return hold("INVALID_V02_PROJECTION");
  const budget = deriveControlPlaneBudgetV02({
    ...read.generated_loop,
    runtime_record_limits: limits,
  });
  if (!budget.ok) return hold("INVALID_V02_PROJECTION");

  const preflight = Object.freeze({ loop_family: read.generated_loop.loop_family }) as PreflightedPlanV02;
  preflightRegistry.set(preflight, {
    source_pack_root_hash: replay.source_pack_root_hash,
    authority: structuredClone(approved),
    observation: structuredClone(observed),
    policy: structuredClone(policy),
    generated_loop_bytes: new Uint8Array(generatedLoopBytes),
    generated_loop: structuredClone(read.generated_loop),
    selected_minimum_assurance_profile: selected.minimum_assurance_profile,
    resolved_plan_input: structuredClone(projection.value.resolved_plan_input),
    runtime_record_limits: structuredClone(limits),
    required_control_plane_output_bytes: budget.value.required_control_plane_output_bytes,
    read,
    projected_identity_keys: new Set(),
    projection_count: 0,
  });
  return {
    ok: true,
    disposition: "preflighted",
    schema_version: "0.2",
    loop_family: preflight.loop_family,
    preflight,
    reason: null,
    findings: [],
  };
}

function jsonBytes(value: unknown): Uint8Array {
  return UTF8.encode(`${JSON.stringify(value, null, 2)}\n`);
}

function preparedMember(name: string, bytes: Uint8Array): PreparedPlanMemberV02 | null {
  const parsed = fixedName(name);
  return parsed === null ? null : Object.freeze({ name: parsed, bytes: new Uint8Array(bytes) });
}

export function projectPreflightedRunV02(
  preflight: PreflightedPlanV02,
  identity: PlanIdentityV02,
): ProjectPreflightedRunV02Result {
  const state = preflightRegistry.get(preflight);
  const identityKey = `${identity.plan_token}\0${identity.run_id}\0${identity.created_at}`;
  if (state === undefined || state.projection_count >= MAX_CANDIDATE_PROJECTIONS
    || state.projected_identity_keys.has(identityKey) || !validIdentity(identity)) {
    return hold("INVALID_V02_PROJECTION");
  }
  state.projected_identity_keys.add(identityKey);
  state.projection_count += 1;

  try {
    const generated = state.generated_loop;
    if (generated === null) return hold("INVALID_V02_PROJECTION");
    const token = compileToken(state.read.work_item.work_item_id);
    if (token === null || state.read.intake.objective === null) return hold("INVALID_V02_PROJECTION");
    const brief = ApprovedIntakeBriefV02.parse({
      schema_version: "0.2",
      intake_brief_id: `brief_${token}`,
      objective: state.read.intake.objective,
      scope: generated.goal.success_criteria.map(({ description }) => description),
      allowed_context: structuredClone(generated.context_contract.required),
      forbidden_context: structuredClone(generated.context_contract.forbidden),
      allowed_tools: generated.tool_grants.map(({ id }) => id),
      allowed_connectors: [],
      max_risk_tier: generated.risk_controls.max_tier_without_approval,
      approval_bindings: generated.gates
        .filter(({ control_kind }) => control_kind === "approval")
        .map(({ id }) => id),
    });
    const generatedHash = hashRawBytes(state.generated_loop_bytes);
    const plan = ResolvedRunPlanV02.parse({
      schema_version: "0.2",
      execution_profile: "bounded-v02",
      run_id: identity.run_id,
      loop_family: generated.loop_family,
      loopeix_version: generated.version,
      loopeix_version_hash: generatedHash,
      source_authoring_hash: generatedHash,
      compiler_bundle_id: state.read.manifest.compiler_bundle_id,
      catalog_version_hash: state.read.manifest.catalog_version_hash,
      binding_input_id: state.read.binding_input.binding_input_id,
      binding_input_hash: state.read.manifest.file_hashes.binding_input,
      compile_pack_manifest_hash: state.authority.compile_pack_manifest_hash,
      work_item_id: state.read.work_item.work_item_id,
      intake_brief_id: brief.intake_brief_id,
      created_at: identity.created_at,
      trigger: structuredClone(generated.trigger),
      goal: structuredClone(generated.goal),
      roles: structuredClone(generated.roles),
      tasks: structuredClone(generated.tasks),
      artifacts: structuredClone(generated.artifacts),
      gates: structuredClone(generated.gates),
      evaluations: structuredClone(generated.evaluations),
      evidence_requirements: structuredClone(generated.evidence_requirements),
      progress: structuredClone(generated.progress),
      stop_policy: structuredClone(generated.stop_policy),
      limit_policy: structuredClone(generated.limit_policy),
      retry_policy: structuredClone(generated.retry_policy),
      recovery_policy: structuredClone(generated.recovery_policy),
      side_effects: structuredClone(generated.side_effects),
      compensations: structuredClone(generated.compensations),
      runtime_record_limits: structuredClone(state.runtime_record_limits),
      required_control_plane_output_bytes: state.required_control_plane_output_bytes,
      assurance_profile: { id: state.selected_minimum_assurance_profile, tightens: [] },
      context_snapshot: structuredClone(generated.context_contract),
      authority_subject: {
        mission: {
          objective: generated.goal.statement,
          success_criteria: structuredClone(generated.goal.success_criteria),
          forbidden_outcomes: structuredClone(state.authority.forbidden_outcomes),
          terminal_states: structuredClone(generated.stop_policy.terminal_states),
        },
        repository: {
          spec_subject: {
            source_authoring_hash: generatedHash,
            loopeix_version_hash: generatedHash,
          },
          compile_subject: {
            compile_pack_manifest_hash: state.authority.compile_pack_manifest_hash,
            compiler_bundle_id: state.read.manifest.compiler_bundle_id,
            catalog_version_hash: state.read.manifest.catalog_version_hash,
            binding_input_hash: state.read.manifest.file_hashes.binding_input,
          },
          repository_root_ref: state.authority.repository.repository_root_ref,
          object_format: state.authority.repository.object_format,
          base_ref: structuredClone(state.authority.repository.base_ref),
          transition_mode: state.authority.repository.transition_mode,
          initial_state: structuredClone(state.observation),
        },
        protection: {
          delegation_mode: state.authority.delegation_mode,
          action_approval_policy: structuredClone(state.policy),
          planning_approval_hash: state.authority.approval_hash,
          invalidation_rules: INVALIDATION_RULES,
          human_exception_destination: structuredClone(state.authority.human_exception_destination),
        },
        policy_digest: state.authority.policy_digest,
      },
      role_assignments: structuredClone(state.authority.role_assignments),
      tool_grants: structuredClone(generated.tool_grants),
      workspace_boundary: structuredClone(state.resolved_plan_input.workspace_boundary),
      adapter_plan: structuredClone(state.resolved_plan_input.adapter_plan),
      risk_controls: structuredClone(generated.risk_controls),
    });
    const sourceMembers = [
      ["work-item.json", "work-item.json"],
      ["binding-input.json", "binding-input.json"],
      ["intake-record.json", "intake-record.json"],
      ["catalog-resolution.json", "catalog-resolution.json"],
      ["compilation-record.json", "compilation-record.json"],
      ["compile-pack-manifest.json", "pack-manifest.json"],
      ["generated.loop.yaml", "generated.loop.yaml"],
    ] as const;
    const members: PreparedPlanMemberV02[] = [];
    for (const [destination, source] of sourceMembers) {
      const bytes = snapshotMember(state.read, source);
      const member = bytes === null ? null : preparedMember(destination, bytes);
      if (member === null) return hold("INVALID_V02_PROJECTION");
      members.push(member);
    }
    const briefMember = preparedMember("intake-brief.json", jsonBytes(brief));
    const planMember = preparedMember("resolved-run-plan.json", jsonBytes(plan));
    if (briefMember === null || planMember === null) return hold("INVALID_V02_PROJECTION");
    members.push(briefMember, planMember);
    const workspaceRootHash = hashCanonical({
      purpose: "workspace-root-v02",
      workspace_root: plan.workspace_boundary.workspace_root,
      read: plan.workspace_boundary.read,
      write: plan.workspace_boundary.write,
    });
    const prepared = Object.freeze({ run_id: identity.run_id }) as PreparedPlanProjectionV02;
    preparedRegistry.set(prepared, Object.freeze({
      intake_brief: structuredClone(brief),
      resolved_run_plan: structuredClone(plan),
      output_descriptor: Object.freeze({
        kind: "plan" as const,
        schema_version: "0.2" as const,
        source_pack_root_hash: state.source_pack_root_hash,
        run_id: identity.run_id,
        output_budget_bytes: 33_554_432 as const,
        loop_family: plan.loop_family,
        workspace_root_hash: workspaceRootHash,
        engine: state.resolved_plan_input.adapter_plan.engine === "codex_cli" ? "codex" as const : "claude" as const,
      }),
      members: Object.freeze(members),
    }));
    return {
      ok: true,
      disposition: "prepared",
      schema_version: "0.2",
      run_id: identity.run_id,
      prepared,
      reason: null,
      findings: [],
    };
  } catch {
    return hold("INVALID_V02_PROJECTION");
  }
}

export function consumePreparedPlanProjectionV02(
  prepared: PreparedPlanProjectionV02,
): PreparedPlanProjectionSnapshotV02 | null {
  const snapshot = preparedRegistry.get(prepared);
  if (snapshot === undefined) return null;
  preparedRegistry.delete(prepared);
  return {
    intake_brief: structuredClone(snapshot.intake_brief),
    resolved_run_plan: structuredClone(snapshot.resolved_run_plan),
    output_descriptor: structuredClone(snapshot.output_descriptor),
    members: snapshot.members.map(({ name, bytes }) => Object.freeze({ name, bytes: new Uint8Array(bytes) })),
  };
}

/**
 * Compatibility boundary retained until the CLI's identity allocator is wired
 * to the two-phase preflight/project API. Three-argument calls never allocate
 * identity or expose candidate bytes.
 */
export function projectPlannedRunV02(
  replay: ExactV02ReplaySuccess,
  authority: ApprovedAuthorityPlanningInputV02,
  repositoryObservation?: ApprovedRepositoryObservationV02,
): PlanProjectionResult {
  const read = consumeExactV02ReplayForPlanning(replay);
  const approved = consumeApprovedAuthorityPlanningInputV02(authority);
  if (read === null || approved === null) return hold("INVALID_COMPILE_PACK");
  const terminal = compilerHold(read.manifest.terminal_state);
  if (terminal !== null) return terminal;
  void repositoryObservation;
  return hold("INVALID_V02_PROJECTION");
}

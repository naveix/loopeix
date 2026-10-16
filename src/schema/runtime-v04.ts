import { z } from "zod";

import { hashCanonical } from "../hash.js";
import { deriveRuntimeExecutionPolicyForRegisteredAdapterV03 } from "./runtime-plan-v03.js";
import * as v02 from "./runtime.js";
import {
  HumanIdV02,
  IsoTimestampV02,
  MachineIdV02,
  RelativeRunPathV02,
} from "./scalars-v02.js";

type WithSchemaVersion<
  S extends z.ZodRawShape,
  Version extends string,
> = Omit<S, "schema_version"> & { schema_version: z.ZodLiteral<Version> };

type WithPlanVersion<S extends z.ZodRawShape> = Omit<S, "schema_version" | "execution_profile"> & {
  schema_version: z.ZodLiteral<"0.3">;
  execution_profile: z.ZodLiteral<"bounded-v04">;
};

type LeaseIssuedPayloadChecks = {
  phase: "work" | "compensation";
  compensation_ref: string | null;
  issued_at: string;
  expires_at: string;
};

type TaskActionAdmittedPayloadChecks = {
  admission_clock_ref: z.infer<typeof v02.LedgerRefV02>;
  waiver_gate_use_checks: Array<{ use_clock_ref: z.infer<typeof v02.LedgerRefV02> }>;
};

type RuntimeInputHashPlanV03 = Omit<z.infer<typeof v02.ResolvedRunPlanV02>, "schema_version" | "execution_profile">;

const strictObject = <T extends z.ZodRawShape>(shape: T): z.ZodObject<T> => z.object(shape).strict();
const safeInteger = z.number().int().refine(Number.isSafeInteger, { message: "must be a safe integer" });

const HashV02 = v02.RunInitializedEventV02.shape.payload.shape.plan_hash;
const LedgerRefV02 = v02.LedgerRefV02;
const MachineIdScalarV02 = MachineIdV02;
const HumanIdScalarV02 = HumanIdV02;
const RelativeRunPathScalarV02 = RelativeRunPathV02;
const IsoTimestampScalarV02 = IsoTimestampV02;

function checkedAdd(left: number, right: number): number | null {
  const value = left + right;
  return Number.isSafeInteger(value) ? value : null;
}

function ledgerRefsEqual(
  left: z.infer<typeof LedgerRefV02>,
  right: z.infer<typeof LedgerRefV02>,
): boolean {
  return left.ledger_sequence === right.ledger_sequence && left.event_hash === right.event_hash;
}

function compareLedgerRefs(
  left: z.infer<typeof LedgerRefV02>,
  right: z.infer<typeof LedgerRefV02>,
): number {
  return left.ledger_sequence === right.ledger_sequence
    ? v02.compareRuntimeUtf8BytesV02(left.event_hash, right.event_hash)
    : left.ledger_sequence - right.ledger_sequence;
}

function canonicalLedgerRefs(min = 0) {
  return z.array(LedgerRefV02).min(min).superRefine((refs, ctx) => {
    for (let index = 1; index < refs.length; index += 1) {
      if (compareLedgerRefs(refs[index - 1]!, refs[index]!) >= 0) {
        ctx.addIssue({
          code: "custom",
          path: [index],
          message: "must be unique and sorted by ledger_sequence then raw UTF-8 event_hash bytes",
        });
      }
    }
  });
}

function withV04Version<
  S extends z.ZodRawShape & { schema_version: z.ZodType },
  C extends z.core.$ZodObjectConfig,
>(schema: z.ZodObject<S, C>): z.ZodObject<WithSchemaVersion<S, "0.4">, C> {
  const composable = schema as unknown as z.ZodObject<
    Omit<S, "schema_version"> & { schema_version: z.ZodUnknown },
    C
  >;
  return composable.safeExtend({ schema_version: z.literal("0.4") } as never) as z.ZodObject<
    WithSchemaVersion<S, "0.4">,
    C
  >;
}

const RuntimeEventEnvelopeV02Shape = v02.RunClockObservedEventV02.shape;
const RuntimeEventEnvelopeV04 = strictObject({
  schema_version: z.literal("0.4"),
  event_id: RuntimeEventEnvelopeV02Shape.event_id,
  run_id: RuntimeEventEnvelopeV02Shape.run_id,
  sequence: RuntimeEventEnvelopeV02Shape.sequence,
  recorded_at: RuntimeEventEnvelopeV02Shape.recorded_at,
  source: RuntimeEventEnvelopeV02Shape.source,
  authority_ref: RuntimeEventEnvelopeV02Shape.authority_ref,
  risk_tier: RuntimeEventEnvelopeV02Shape.risk_tier,
  related_ids: RuntimeEventEnvelopeV02Shape.related_ids,
  previous_event_hash: RuntimeEventEnvelopeV02Shape.previous_event_hash,
  event_hash: RuntimeEventEnvelopeV02Shape.event_hash,
});

const CanonicalLedgerRefsV04 = canonicalLedgerRefs();
const NonEmptyCanonicalLedgerRefsV04 = canonicalLedgerRefs(1);

const RuntimeSchemaInventoryV04Shape = {
  ...v02.RuntimeSchemaInventoryV02.shape,
  resolved_run_plan: z.literal("0.3"),
  ledger_event: z.literal("0.4"),
  run_manifest: z.literal("0.4"),
  summary_artifact: z.literal("0.1"),
} satisfies z.ZodRawShape;

export const RuntimeSchemaInventoryV04 = strictObject(RuntimeSchemaInventoryV04Shape);

export const RuntimeExecutionPolicyV03 = strictObject({
  profile_id: z.literal("runtime-execution-controls-v04-s41-1"),
  charge_profile_id: z.literal("control-plane-charge-ceilings-v04-s41-1"),
  max_process_runtime_ms: safeInteger.positive(),
  max_execution_attempts: safeInteger.positive(),
  run_owner_acquisition_max: safeInteger.positive(),
  task_owner_acquisition_max: safeInteger.positive(),
  integrator_acquisition_max: safeInteger.positive(),
  owner_lease_duration_ms: safeInteger.positive(),
  heartbeat_interval_ms: safeInteger.positive(),
  run_heartbeat_event_max: safeInteger.positive(),
  task_heartbeat_event_max: safeInteger.positive(),
  integrator_heartbeat_event_max: safeInteger.positive(),
  run_owner_release_max: safeInteger.positive(),
  task_owner_release_max: safeInteger.positive(),
  integrator_release_max: safeInteger.positive(),
  max_compaction_events: safeInteger.positive(),
  max_summary_records: safeInteger.positive(),
  max_summary_content_bytes: safeInteger.positive(),
}).superRefine((policy, ctx) => {
  if (policy.owner_lease_duration_ms < 2) {
    ctx.addIssue({ code: "custom", path: ["owner_lease_duration_ms"], message: "owner lease duration must be at least 2 ms" });
  }
  if (policy.heartbeat_interval_ms >= policy.owner_lease_duration_ms) {
    ctx.addIssue({ code: "custom", path: ["heartbeat_interval_ms"], message: "heartbeat interval must stay strictly below the lease duration" });
  }
  if (policy.max_process_runtime_ms < policy.owner_lease_duration_ms) {
    ctx.addIssue({ code: "custom", path: ["max_process_runtime_ms"], message: "process runtime ceiling must cover at least one full lease duration" });
  }
  if (policy.max_process_runtime_ms > 30_000) {
    ctx.addIssue({ code: "custom", path: ["max_process_runtime_ms"], message: "process runtime ceiling must not exceed the registered adapter ceiling" });
  }
  if (policy.run_owner_acquisition_max !== policy.max_execution_attempts) {
    ctx.addIssue({ code: "custom", path: ["run_owner_acquisition_max"], message: "run owner acquisitions must equal max execution attempts" });
  }
  if (policy.integrator_acquisition_max !== policy.max_execution_attempts) {
    ctx.addIssue({ code: "custom", path: ["integrator_acquisition_max"], message: "integrator acquisitions must equal max execution attempts" });
  }
  if (policy.run_owner_release_max !== policy.run_owner_acquisition_max) {
    ctx.addIssue({ code: "custom", path: ["run_owner_release_max"], message: "run owner releases must equal run owner acquisitions" });
  }
  if (policy.task_owner_release_max !== policy.task_owner_acquisition_max) {
    ctx.addIssue({ code: "custom", path: ["task_owner_release_max"], message: "task owner releases must equal task owner acquisitions" });
  }
  if (policy.integrator_release_max !== policy.integrator_acquisition_max) {
    ctx.addIssue({ code: "custom", path: ["integrator_release_max"], message: "integrator releases must equal integrator acquisitions" });
  }
  if (policy.max_compaction_events !== policy.max_summary_records) {
    ctx.addIssue({ code: "custom", path: ["max_summary_records"], message: "summary records must equal compaction events" });
  }
  if (policy.max_summary_content_bytes > 65_536) {
    ctx.addIssue({ code: "custom", path: ["max_summary_content_bytes"], message: "summary content bytes must stay within the V04 fixed cap" });
  }
});

export function HashRuntimeInputV03(plan: RuntimeInputHashPlanV03): string {
  return hashCanonical({
    purpose: "runtime-input-v03",
    schema_version: "0.3",
    compile_pack_manifest_hash: plan.compile_pack_manifest_hash,
    work_item_id: plan.work_item_id,
    intake_brief_id: plan.intake_brief_id,
    tasks: plan.tasks,
    context_snapshot: plan.context_snapshot,
  });
}

export function HashRuntimeRecoveryPolicyV03(plan: RuntimeInputHashPlanV03): string {
  return hashCanonical({
    purpose: "runtime-recovery-policy-v03",
    schema_version: "0.3",
    trigger: plan.trigger,
    goal: plan.goal,
    progress: plan.progress,
    stop_policy: plan.stop_policy,
    limit_policy: plan.limit_policy,
    retry_policy: plan.retry_policy,
    recovery_policy: plan.recovery_policy,
    side_effects: plan.side_effects,
    compensations: plan.compensations,
    runtime_record_limits: plan.runtime_record_limits,
    assurance_profile: plan.assurance_profile,
    risk_controls: plan.risk_controls,
    tool_grants: plan.tool_grants,
    workspace_boundary: plan.workspace_boundary,
    adapter_plan: plan.adapter_plan,
    gates: plan.gates,
    evaluations: plan.evaluations,
  });
}

const resolvedRunPlanV02Composable = v02.ResolvedRunPlanV02 as unknown as z.ZodObject<
  Omit<typeof v02.ResolvedRunPlanV02.shape, "schema_version" | "execution_profile"> & {
    schema_version: z.ZodUnknown;
    execution_profile: z.ZodUnknown;
  }
>;

const ResolvedRunPlanV03Base = resolvedRunPlanV02Composable.safeExtend({
  schema_version: z.literal("0.3"),
  execution_profile: z.literal("bounded-v04"),
  runtime_input_hash: HashV02,
  runtime_recovery_policy_hash: HashV02,
  runtime_execution_policy: RuntimeExecutionPolicyV03,
} as never) as z.ZodObject<
  WithPlanVersion<typeof v02.ResolvedRunPlanV02.shape> & {
    runtime_input_hash: typeof HashV02;
    runtime_recovery_policy_hash: typeof HashV02;
    runtime_execution_policy: typeof RuntimeExecutionPolicyV03;
  }
>;

export const ResolvedRunPlanV03 = ResolvedRunPlanV03Base.superRefine((plan, ctx) => {
  const {
    runtime_execution_policy: _suppliedPolicy,
    runtime_input_hash: _suppliedInputHash,
    runtime_recovery_policy_hash: _suppliedRecoveryPolicyHash,
    ...inherited
  } = plan;
  const v02PlanLike = {
    ...inherited,
    schema_version: "0.2",
    execution_profile: "bounded-v02",
  };
  const derived = deriveRuntimeExecutionPolicyForRegisteredAdapterV03(v02PlanLike);
  if (!derived.ok) {
    ctx.addIssue({ code: "custom", path: ["runtime_execution_policy"], message: "INVALID_V03_RUNTIME_EXECUTION_POLICY" });
    return;
  }
  const expectedPolicy = derived.value.runtime_execution_policy;
  const expectedControlBytes = derived.value.required_control_plane_output_bytes;

  for (const [key, value] of Object.entries(expectedPolicy) as Array<[keyof typeof expectedPolicy, number | string]>) {
    if (plan.runtime_execution_policy[key] !== value) {
      ctx.addIssue({ code: "custom", path: ["runtime_execution_policy", key], message: "must equal the exact derived V04 runtime execution policy value" });
    }
  }
  if (plan.required_control_plane_output_bytes !== expectedControlBytes) {
    ctx.addIssue({ code: "custom", path: ["required_control_plane_output_bytes"], message: "must equal the exact derived V04 control-byte requirement" });
  }
  if (plan.runtime_input_hash !== HashRuntimeInputV03(v02PlanLike)) {
    ctx.addIssue({ code: "custom", path: ["runtime_input_hash"], message: "must equal the exact derived V04 runtime input hash" });
  }
  if (plan.runtime_recovery_policy_hash !== HashRuntimeRecoveryPolicyV03(v02PlanLike)) {
    ctx.addIssue({ code: "custom", path: ["runtime_recovery_policy_hash"], message: "must equal the exact derived V04 runtime recovery policy hash" });
  }
});

const RunInitializedPayloadV04 = strictObject({
  ...v02.RunInitializedEventV02.shape.payload.shape,
  runtime_schema_versions: RuntimeSchemaInventoryV04,
});

export const RunInitializedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("run.initialized"),
  payload: RunInitializedPayloadV04,
}).superRefine((event, ctx) => {
  if (event.source !== "kernel") ctx.addIssue({ code: "custom", path: ["source"], message: "run.initialized must use source 'kernel'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.initialized must not name authority" });
  if (event.sequence !== 1) ctx.addIssue({ code: "custom", path: ["sequence"], message: "run.initialized must be sequence 1" });
  if (event.previous_event_hash !== null) {
    ctx.addIssue({ code: "custom", path: ["previous_event_hash"], message: "run.initialized must not name a previous event" });
  }
});

const ClockObservedCommonV04 = {
  clock_id: MachineIdScalarV02,
  observed_at: IsoTimestampScalarV02,
  elapsed_ms: safeInteger.nonnegative(),
} satisfies z.ZodRawShape;

const RunClockObservedPayloadV04 = z.discriminatedUnion("reason", [
  strictObject({
    ...ClockObservedCommonV04,
    reason: z.literal("action-admission"),
    task_ref: HumanIdScalarV02,
    failure_ordinal: z.null(),
    use_ref: MachineIdScalarV02,
    attempt_ref: LedgerRefV02,
    owner_lease_ref: LedgerRefV02,
    boot_id_hash: z.null(),
    monotonic_clock_id: z.null(),
  }),
  strictObject({
    ...ClockObservedCommonV04,
    reason: z.literal("retry-check"),
    task_ref: HumanIdScalarV02,
    failure_ordinal: safeInteger.positive(),
    use_ref: z.null(),
    attempt_ref: LedgerRefV02,
    owner_lease_ref: LedgerRefV02,
    boot_id_hash: z.null(),
    monotonic_clock_id: z.null(),
  }),
  strictObject({
    ...ClockObservedCommonV04,
    reason: z.enum(["waiver-boundary", "terminal-use"]),
    task_ref: z.null(),
    failure_ordinal: z.null(),
    use_ref: MachineIdScalarV02,
    attempt_ref: z.null(),
    owner_lease_ref: z.null(),
    boot_id_hash: z.null(),
    monotonic_clock_id: z.null(),
  }),
  strictObject({
    ...ClockObservedCommonV04,
    reason: z.enum(["recovery-request", "pause-request"]),
    task_ref: z.null(),
    failure_ordinal: z.null(),
    use_ref: MachineIdScalarV02,
    attempt_ref: LedgerRefV02,
    owner_lease_ref: LedgerRefV02,
    boot_id_hash: z.null(),
    monotonic_clock_id: z.null(),
  }),
  strictObject({
    ...ClockObservedCommonV04,
    reason: z.literal("run-owner-acquisition"),
    task_ref: z.null(),
    failure_ordinal: z.null(),
    use_ref: MachineIdScalarV02,
    attempt_ref: z.null(),
    owner_lease_ref: z.null(),
    boot_id_hash: HashV02,
    monotonic_clock_id: MachineIdScalarV02,
  }),
  strictObject({
    ...ClockObservedCommonV04,
    reason: z.enum(["owner-acquisition", "owner-heartbeat", "owner-release", "stale-owner-check"]),
    task_ref: z.null(),
    failure_ordinal: z.null(),
    use_ref: MachineIdScalarV02,
    attempt_ref: LedgerRefV02,
    owner_lease_ref: LedgerRefV02,
    boot_id_hash: HashV02,
    monotonic_clock_id: MachineIdScalarV02,
  }),
]);

export const RunClockObservedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("run.clock-observed"),
  payload: RunClockObservedPayloadV04,
}).superRefine((event, ctx) => {
  if (event.source !== "kernel") ctx.addIssue({ code: "custom", path: ["source"], message: "run.clock-observed must use source 'kernel'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.clock-observed must not name authority" });
});

const RunFenceAdvancedPayloadV04 = strictObject({
  previous_fence_epoch: safeInteger.nonnegative(),
  fence_epoch: safeInteger.positive(),
  reason: z.enum(["pause-request", "authority-revoked", "abort-request", "lease-revoked"]),
  evidence_refs: CanonicalLedgerRefsV04,
  attempt_ref: LedgerRefV02,
  owner_lease_refs: NonEmptyCanonicalLedgerRefsV04,
});

export const RunFenceAdvancedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("run.fence-advanced"),
  payload: RunFenceAdvancedPayloadV04,
}).superRefine((event, ctx) => {
  if (event.source !== "policy-enforcement-point") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "run.fence-advanced must use source 'policy-enforcement-point'" });
  }
  if (event.authority_ref === null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.fence-advanced requires authority" });
  }
  if (
    event.payload.previous_fence_epoch >= Number.MAX_SAFE_INTEGER
    || event.payload.fence_epoch !== event.payload.previous_fence_epoch + 1
  ) {
    ctx.addIssue({ code: "custom", path: ["payload", "fence_epoch"], message: "fence epoch must increment by exactly one without overflow" });
  }
});

export const ControlAbortRequestedEventV04 = withV04Version(v02.ControlAbortRequestedEventV02);
export const GateResultRequiredEventV04 = withV04Version(v02.GateResultRequiredEventV02);
export const GateResultRecordedEventV04 = withV04Version(v02.GateResultRecordedEventV02);
export const EvaluationResultRequiredEventV04 = withV04Version(v02.EvaluationResultRequiredEventV02);
export const EvaluationResultRecordedEventV04 = withV04Version(v02.EvaluationResultRecordedEventV02);
export const AuthorityHumanAuthorizationRecordedEventV04 = withV04Version(v02.AuthorityHumanAuthorizationRecordedEventV02);
export const AuthorityEnvelopeRecordedEventV04 = withV04Version(v02.AuthorityEnvelopeRecordedEventV02);
export const ApprovalRecommendationRecordedEventV04 = withV04Version(v02.ApprovalRecommendationRecordedEventV02);
export const PolicyDecisionRecordedEventV04 = withV04Version(v02.PolicyDecisionRecordedEventV02);
export const AuthorityWaiverRecordedEventV04 = withV04Version(v02.AuthorityWaiverRecordedEventV02);
export const AuthorityGrantRevokedEventV04 = withV04Version(v02.AuthorityGrantRevokedEventV02);
export const EvidenceRecordedEventV04 = withV04Version(v02.EvidenceRecordedEventV02);
export const ObservationManualRecordedEventV04 = withV04Version(v02.ObservationManualRecordedEventV02);
export const ClaimRecordedEventV04 = withV04Version(v02.ClaimRecordedEventV02);
export const FindingRecordedEventV04 = withV04Version(v02.FindingRecordedEventV02);
export const WaiverRecordedEventV04 = withV04Version(v02.WaiverRecordedEventV02);

const LeaseIssuedPayloadOptionsV02 = v02.LeaseIssuedEventV02.shape.payload.options as unknown as [
  z.ZodObject<z.ZodRawShape>,
  z.ZodObject<z.ZodRawShape>,
];

const LeaseIssuedPayloadV04 = z.discriminatedUnion("action_approval_class", [
  LeaseIssuedPayloadOptionsV02[0].extend({
    attempt_event_ref: LedgerRefV02,
    parent_run_owner_lease_id: MachineIdScalarV02,
    logical_operation_idempotency_key: HashV02,
    resolved_operation_input_hash: HashV02,
    recovery_policy_hash: HashV02,
    process_runtime_ceiling_ms: safeInteger.positive(),
  }).strict(),
  LeaseIssuedPayloadOptionsV02[1].extend({
    attempt_event_ref: LedgerRefV02,
    parent_run_owner_lease_id: MachineIdScalarV02,
    logical_operation_idempotency_key: HashV02,
    resolved_operation_input_hash: HashV02,
    recovery_policy_hash: HashV02,
    process_runtime_ceiling_ms: safeInteger.positive(),
  }).strict(),
]);

export const LeaseIssuedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("lease.issued"),
  payload: LeaseIssuedPayloadV04,
}).superRefine((event, ctx) => {
  const payload = event.payload as LeaseIssuedPayloadChecks;
  if (event.source !== "policy-enforcement-point") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "lease.issued must use source 'policy-enforcement-point'" });
  }
  if (event.authority_ref === null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "lease.issued requires authority" });
  }
  if ((payload.phase === "compensation") !== (payload.compensation_ref !== null)) {
    ctx.addIssue({ code: "custom", path: ["payload", "compensation_ref"], message: "compensation reference must be present exactly in compensation phase" });
  }
  if (Date.parse(payload.issued_at) >= Date.parse(payload.expires_at)) {
    ctx.addIssue({ code: "custom", path: ["payload", "expires_at"], message: "lease interval must be non-empty" });
  }
});

const TaskActionAdmittedPayloadOptionsV02 = v02.TaskActionAdmittedEventV02.shape.payload.options as unknown as [
  z.ZodObject<z.ZodRawShape>,
  z.ZodObject<z.ZodRawShape>,
];

const TaskActionAdmittedPayloadV04 = z.discriminatedUnion("action_approval_class", [
  TaskActionAdmittedPayloadOptionsV02[0].extend({
    attempt_event_ref: LedgerRefV02,
    parent_run_owner_lease_id: MachineIdScalarV02,
    logical_operation_idempotency_key: HashV02,
    resolved_operation_input_hash: HashV02,
    recovery_policy_hash: HashV02,
    process_runtime_ceiling_ms: safeInteger.positive(),
  }).strict(),
  TaskActionAdmittedPayloadOptionsV02[1].extend({
    attempt_event_ref: LedgerRefV02,
    parent_run_owner_lease_id: MachineIdScalarV02,
    logical_operation_idempotency_key: HashV02,
    resolved_operation_input_hash: HashV02,
    recovery_policy_hash: HashV02,
    process_runtime_ceiling_ms: safeInteger.positive(),
  }).strict(),
]);

export const TaskActionAdmittedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("task.action-admitted"),
  payload: TaskActionAdmittedPayloadV04,
}).superRefine((event, ctx) => {
  const payload = event.payload as TaskActionAdmittedPayloadChecks;
  if (event.source !== "policy-enforcement-point") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "task.action-admitted must use source 'policy-enforcement-point'" });
  }
  if (event.authority_ref === null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "task.action-admitted requires authority" });
  }
  payload.waiver_gate_use_checks.forEach((check, index) => {
    if (!ledgerRefsEqual(check.use_clock_ref, payload.admission_clock_ref)) {
      ctx.addIssue({
        code: "custom",
        path: ["payload", "waiver_gate_use_checks", index, "use_clock_ref"],
        message: "waiver use clock must equal the action admission clock",
      });
    }
  });
});

export const ToolCallAdmittedEventV04 = withV04Version(v02.ToolCallAdmittedEventV02);
export const ArtifactWriteAdmittedEventV04 = withV04Version(v02.ArtifactWriteAdmittedEventV02);

const RuntimeLimitRefV04 = z.enum([
  "max-loop-attempts",
  "max-elapsed-ms",
  "max-tool-calls",
  "max-output-bytes",
  "max-tokens",
  "max-cost",
  "max-process-runtime",
  "max-workers",
]);

const RuntimeLimitViolationV04 = strictObject({
  limit_ref: RuntimeLimitRefV04,
  consumed: safeInteger.nonnegative(),
  requested: safeInteger.positive(),
  ceiling: safeInteger.nonnegative(),
}).superRefine((violation, ctx) => {
  const next = checkedAdd(violation.consumed, violation.requested);
  if (next === null) {
    ctx.addIssue({ code: "custom", path: ["requested"], message: "prospective limit addition must not overflow" });
    return;
  }
  if (next <= violation.ceiling) {
    ctx.addIssue({ code: "custom", path: ["requested"], message: "violation must cross its ceiling" });
  }
});

const CanonicalRuntimeLimitViolationsV04 = z.array(RuntimeLimitViolationV04).min(1).superRefine((violations, ctx) => {
  for (let index = 1; index < violations.length; index += 1) {
    if (v02.compareRuntimeUtf8BytesV02(violations[index - 1]!.limit_ref, violations[index]!.limit_ref) >= 0) {
      ctx.addIssue({ code: "custom", path: [index, "limit_ref"], message: "violations must be unique and sorted by UTF-8 limit_ref bytes" });
    }
  }
});

export const LimitAdmissionBlockedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("limit.admission-blocked"),
  payload: strictObject({
    request_id: MachineIdScalarV02,
    task_ref: HumanIdScalarV02,
    phase: z.enum(["work", "compensation"]),
    compensation_ref: HumanIdScalarV02.nullable(),
    request_kind: z.enum(["loop-attempt", "action", "tool-call", "artifact-write", "adapter-budget", "process-start"]),
    request_hash: HashV02,
    violations: CanonicalRuntimeLimitViolationsV04,
  }),
}).superRefine((event, ctx) => {
  if (event.source !== "policy-enforcement-point") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "limit.admission-blocked must use source 'policy-enforcement-point'" });
  }
  if (event.authority_ref === null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "limit.admission-blocked requires authority" });
  }
  if ((event.payload.phase === "compensation") !== (event.payload.compensation_ref !== null)) {
    ctx.addIssue({ code: "custom", path: ["payload", "compensation_ref"], message: "compensation reference must be present exactly in compensation phase" });
  }
});

export const TaskExecutionStartedEventV04 = withV04Version(v02.TaskExecutionStartedEventV02);

export const TaskExecutionCompletedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("task.execution-completed"),
  payload: strictObject({
    ...v02.TaskExecutionCompletedEventV02.shape.payload.shape,
    attempt_event_ref: LedgerRefV02,
    process_runtime_ms: safeInteger.nonnegative(),
    loop_attempts_after: safeInteger.positive(),
    task_executions_after: safeInteger.positive(),
    workers_after: safeInteger.nonnegative(),
  }),
}).superRefine((event, ctx) => {
  if (event.source !== "adapter") ctx.addIssue({ code: "custom", path: ["source"], message: "task.execution-completed must use source 'adapter'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "task.execution-completed must have null authority_ref" });
});

export const TaskProgressFactRecordedEventV04 = withV04Version(v02.TaskProgressFactRecordedEventV02);

export const TaskExecutionFailedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("task.execution-failed"),
  payload: strictObject({
    ...v02.TaskExecutionFailedEventV02.shape.payload.shape,
    attempt_event_ref: LedgerRefV02,
    process_runtime_ms: safeInteger.nonnegative(),
    loop_attempts_after: safeInteger.positive(),
    task_executions_after: safeInteger.positive(),
    workers_after: safeInteger.nonnegative(),
  }),
}).superRefine((event, ctx) => {
  if (event.source !== "adapter") ctx.addIssue({ code: "custom", path: ["source"], message: "task.execution-failed must use source 'adapter'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "task.execution-failed must have null authority_ref" });
});

export const TaskActionOutcomeUnknownEventV04 = withV04Version(v02.TaskActionOutcomeUnknownEventV02);

export const TaskExecutionNonEntryAcknowledgedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("task.execution-non-entry-acknowledged"),
  payload: strictObject({
    action_id: MachineIdScalarV02,
    task_ref: HumanIdScalarV02,
    admission_ref: LedgerRefV02,
    attempt_event_ref: LedgerRefV02,
    adapter_invocation_id: MachineIdScalarV02,
    adapter_ref: HumanIdScalarV02,
    adapter_version_hash: HashV02,
    fence_epoch: safeInteger.nonnegative(),
    host_identity_hash: HashV02,
    boot_id_hash: HashV02,
    unit_name_hash: HashV02,
    cgroup_path_hash: HashV02,
    acknowledgement_observation_hash: HashV02,
  }),
}).superRefine((event, ctx) => {
  if (event.source !== "adapter") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "task.execution-non-entry-acknowledged must use source 'adapter'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "task.execution-non-entry-acknowledged must not name authority" });
  }
});

const TaskActionOutcomeReconciledPayloadV04 = z.discriminatedUnion("reconciliation_status", [
  strictObject({
    ...v02.TaskActionOutcomeReconciledEventV02.shape.payload.shape,
    reconciliation_status: z.literal("outcome-remains-unknown"),
  }),
  strictObject({
    action_id: MachineIdScalarV02,
    task_ref: HumanIdScalarV02,
    admission_ref: LedgerRefV02,
    reconciliation_status: z.literal("proven-non-start"),
    attempt_event_ref: LedgerRefV02,
    adapter_invocation_id: MachineIdScalarV02,
    adapter_ref: HumanIdScalarV02,
    adapter_version_hash: HashV02,
    non_entry_ack_event_ref: LedgerRefV02,
    process_cannot_continue_ref: LedgerRefV02,
    fence_epoch: safeInteger.nonnegative(),
  }),
]);

export const TaskActionOutcomeReconciledEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("task.action-outcome-reconciled"),
  payload: TaskActionOutcomeReconciledPayloadV04,
}).superRefine((event, ctx) => {
  if (event.source !== "integrity") ctx.addIssue({ code: "custom", path: ["source"], message: "task.action-outcome-reconciled must use source 'integrity'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "task.action-outcome-reconciled must have null authority_ref" });
});

export const ArtifactRecordedEventV04 = withV04Version(v02.ArtifactRecordedEventV02);
export const RecordRedactionDerivativeRecordedEventV04 = withV04Version(v02.RecordRedactionDerivativeRecordedEventV02);
export const RecordCustodyStateRecordedEventV04 = withV04Version(v02.RecordCustodyStateRecordedEventV02);
export const RecordExportDecisionRecordedEventV04 = withV04Version(v02.RecordExportDecisionRecordedEventV02);

export const EffectOutcomeEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("effect.outcome"),
  payload: strictObject({
    ...v02.EffectOutcomeEventV02.shape.payload.shape,
    reconciliation_event_ref: LedgerRefV02.nullable(),
  }),
}).superRefine((event, ctx) => {
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "effect.outcome must not name authority" });
  }
  if (event.payload.outcome === "committed") {
    if (event.source !== "adapter") ctx.addIssue({ code: "custom", path: ["source"], message: "committed effect outcomes must use source 'adapter'" });
    if (event.payload.reconciliation_event_ref !== null) {
      ctx.addIssue({ code: "custom", path: ["payload", "reconciliation_event_ref"], message: "committed effects must not carry a reconciliation event" });
    }
  }
  if (event.payload.outcome === "unknown") {
    if (event.source !== "integrity") ctx.addIssue({ code: "custom", path: ["source"], message: "unknown effect outcomes must use source 'integrity'" });
    if (event.payload.reconciliation_event_ref !== null) {
      ctx.addIssue({ code: "custom", path: ["payload", "reconciliation_event_ref"], message: "unknown effects must not carry a reconciliation event" });
    }
  }
  if (event.payload.outcome === "not-committed") {
    if (event.source === "adapter") {
      if (event.payload.reconciliation_event_ref !== null) {
        ctx.addIssue({ code: "custom", path: ["payload", "reconciliation_event_ref"], message: "adapter-authored non-commit outcomes must not carry a reconciliation event" });
      }
    } else if (event.source === "integrity") {
      if (event.payload.reconciliation_event_ref === null) {
        ctx.addIssue({ code: "custom", path: ["payload", "reconciliation_event_ref"], message: "integrity-authored non-commit outcomes require a reconciliation event" });
      } else if (
        event.payload.evidence_refs.length !== 1
        || !ledgerRefsEqual(event.payload.evidence_refs[0]!, event.payload.reconciliation_event_ref)
      ) {
        ctx.addIssue({ code: "custom", path: ["payload", "evidence_refs"], message: "integrity-authored non-commit outcomes must bind exactly one matching reconciliation evidence ref" });
      }
    } else {
      ctx.addIssue({ code: "custom", path: ["source"], message: "not-committed effect outcomes must use source 'adapter' or 'integrity'" });
    }
  }
});

export const TaskActionSettledEventV04 = withV04Version(v02.TaskActionSettledEventV02);
export const LoopAttemptCompletedEventV04 = withV04Version(v02.LoopAttemptCompletedEventV02);
export const TaskProgressObservedEventV04 = withV04Version(v02.TaskProgressObservedEventV02);
export const RunTerminalFreezeEnteredEventV04 = withV04Version(v02.RunTerminalFreezeEnteredEventV02);
export const RunTerminalFreezeRevisedEventV04 = withV04Version(v02.RunTerminalFreezeRevisedEventV02);
export const RunCompensationRequestedEventV04 = withV04Version(v02.RunCompensationRequestedEventV02);
export const RunCompensationRequestRevisedEventV04 = withV04Version(v02.RunCompensationRequestRevisedEventV02);
export const RunCompensationPhaseEnteredEventV04 = withV04Version(v02.RunCompensationPhaseEnteredEventV02);
export const RunCompensationCandidateEscalatedEventV04 = withV04Version(v02.RunCompensationCandidateEscalatedEventV02);
export const CompensationSettledEventV04 = withV04Version(v02.CompensationSettledEventV02);
export const RunTerminalSealedEventV04 = withV04Version(v02.RunTerminalSealedEventV02);

export const RunStartedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("run.started"),
  payload: strictObject({ executor_profile_hash: HashV02 }),
}).superRefine((event, ctx) => {
  if (event.source !== "kernel") ctx.addIssue({ code: "custom", path: ["source"], message: "run.started must use source 'kernel'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.started must not name authority" });
});

const RunPausedPayloadV04 = z.discriminatedUnion("requested_by", [
  strictObject({
    requested_by: z.literal("operator"),
    reason_code: z.literal("operator-request"),
    request_event_ref: LedgerRefV02,
    attempt_event_ref: LedgerRefV02,
    quiescent_boundary_sequence: safeInteger.positive(),
    quiescent_boundary_head_hash: HashV02,
    previous_fence_epoch: safeInteger.nonnegative(),
    fence_epoch: safeInteger.positive(),
    invalidated_owner_lease_refs: NonEmptyCanonicalLedgerRefsV04,
  }),
  strictObject({
    requested_by: z.literal("policy"),
    reason_code: z.literal("policy-hold"),
    request_event_ref: LedgerRefV02,
    attempt_event_ref: LedgerRefV02,
    quiescent_boundary_sequence: safeInteger.positive(),
    quiescent_boundary_head_hash: HashV02,
    previous_fence_epoch: safeInteger.nonnegative(),
    fence_epoch: safeInteger.positive(),
    invalidated_owner_lease_refs: NonEmptyCanonicalLedgerRefsV04,
  }),
]);

export const RunPausedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("run.paused"),
  payload: RunPausedPayloadV04,
}).superRefine((event, ctx) => {
  const expectedSource = event.payload.requested_by === "operator" ? "operator" : "policy-enforcement-point";
  if (event.source !== expectedSource) ctx.addIssue({ code: "custom", path: ["source"], message: "run.paused source must match requested_by" });
  if (event.authority_ref === null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.paused requires requester authority" });
  if (
    event.payload.previous_fence_epoch >= Number.MAX_SAFE_INTEGER
    || event.payload.fence_epoch !== event.payload.previous_fence_epoch + 1
  ) {
    ctx.addIssue({ code: "custom", path: ["payload", "fence_epoch"], message: "run.paused must bind an exact single-step fence advance" });
  }
});

export const RunQuarantinedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("run.quarantined"),
  payload: strictObject({
    reason_code: z.enum(["unmatched-observation", "authority-breach", "capture-gap"]),
    evidence_refs: CanonicalLedgerRefsV04,
  }),
}).superRefine((event, ctx) => {
  if (event.source !== "integrity") ctx.addIssue({ code: "custom", path: ["source"], message: "run.quarantined must use source 'integrity'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.quarantined must not name authority" });
});

export const ProcessTerminationAttemptedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("process.termination-attempted"),
  payload: strictObject({
    trigger: z.enum(["abort", "quarantine", "reconciliation"]),
    trigger_event_ref: LedgerRefV02,
    action_admission_event_ref: LedgerRefV02,
    adapter_invocation_id: MachineIdScalarV02,
    host_identity_hash: HashV02,
    boot_id_hash: HashV02,
    unit_name_hash: HashV02,
    cgroup_path_hash: HashV02,
    termination_request_hash: HashV02,
    termination_observation_hash: HashV02,
    observed_outcome: z.enum(["terminated", "not-terminated", "unknown"]),
  }),
}).superRefine((event, ctx) => {
  if (event.source !== "adapter") ctx.addIssue({ code: "custom", path: ["source"], message: "process.termination-attempted must use source 'adapter'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "process.termination-attempted must not name authority" });
});

export const IntegrityObservationRejectedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("integrity.observation-rejected"),
  payload: strictObject({
    reason_code: z.enum(["unmatched-observation", "authority-breach", "capture-gap"]),
    observation_hash: HashV02,
    adapter_invocation_id: MachineIdScalarV02.nullable(),
    claimed_action_id: MachineIdScalarV02.nullable(),
  }),
}).superRefine((event, ctx) => {
  if (event.source !== "integrity") ctx.addIssue({ code: "custom", path: ["source"], message: "integrity.observation-rejected must use source 'integrity'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "integrity.observation-rejected must not name authority" });
  if (event.payload.reason_code === "capture-gap" && event.payload.adapter_invocation_id === null) {
    ctx.addIssue({ code: "custom", path: ["payload", "adapter_invocation_id"], message: "capture-gap requires an adapter invocation" });
  }
  if (
    event.payload.reason_code !== "capture-gap"
    && event.payload.adapter_invocation_id === null
    && event.payload.claimed_action_id === null
  ) {
    ctx.addIssue({ code: "custom", path: ["payload"], message: "unmatched-observation and authority-breach require an invocation or claimed action" });
  }
});

export const ControlPauseRequestedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("control.pause-requested"),
  payload: z.discriminatedUnion("requested_by", [
    strictObject({
      request_id: MachineIdScalarV02,
      requested_by: z.literal("operator"),
      reason_code: z.literal("operator-request"),
      attempt_event_ref: LedgerRefV02,
      run_owner_lease_ref: LedgerRefV02,
      request_clock_ref: LedgerRefV02,
      fence_epoch: safeInteger.nonnegative(),
    }),
    strictObject({
      request_id: MachineIdScalarV02,
      requested_by: z.literal("policy"),
      reason_code: z.literal("policy-hold"),
      attempt_event_ref: LedgerRefV02,
      run_owner_lease_ref: LedgerRefV02,
      request_clock_ref: LedgerRefV02,
      fence_epoch: safeInteger.nonnegative(),
    }),
  ]),
}).superRefine((event, ctx) => {
  const expectedSource = event.payload.requested_by === "operator" ? "operator" : "policy-enforcement-point";
  if (event.source !== expectedSource) {
    ctx.addIssue({ code: "custom", path: ["source"], message: "control.pause-requested source must match requested_by" });
  }
  if (event.authority_ref === null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "control.pause-requested requires authority" });
  }
});

export const RecoveryResumeRequestedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("recovery.resume-requested"),
  payload: z.discriminatedUnion("mode", [
    strictObject({
      request_id: MachineIdScalarV02,
      mode: z.literal("ordinary"),
      resume_nonce_hash: HashV02,
      previous_attempt_event_ref: LedgerRefV02,
      source_boundary_sequence: safeInteger.positive(),
      source_boundary_head_hash: HashV02,
      source_manifest_hash: HashV02,
      repository_state_hash: HashV02,
      plan_hash: HashV02,
      input_hash: HashV02,
      recovery_policy_hash: HashV02,
      authority_envelope_hash: HashV02,
      request_clock_ref: LedgerRefV02,
      target_action_admission_ref: z.null(),
      compensation_phase_event_ref: z.null(),
    }),
    strictObject({
      request_id: MachineIdScalarV02,
      mode: z.literal("reconciliation-only"),
      resume_nonce_hash: HashV02,
      previous_attempt_event_ref: LedgerRefV02,
      source_boundary_sequence: safeInteger.positive(),
      source_boundary_head_hash: HashV02,
      source_manifest_hash: HashV02,
      repository_state_hash: HashV02,
      plan_hash: HashV02,
      input_hash: HashV02,
      recovery_policy_hash: HashV02,
      authority_envelope_hash: HashV02,
      request_clock_ref: LedgerRefV02,
      target_action_admission_ref: LedgerRefV02,
      compensation_phase_event_ref: z.null(),
    }),
    strictObject({
      request_id: MachineIdScalarV02,
      mode: z.literal("compensation-continuation"),
      resume_nonce_hash: HashV02,
      previous_attempt_event_ref: LedgerRefV02,
      source_boundary_sequence: safeInteger.positive(),
      source_boundary_head_hash: HashV02,
      source_manifest_hash: HashV02,
      repository_state_hash: HashV02,
      plan_hash: HashV02,
      input_hash: HashV02,
      recovery_policy_hash: HashV02,
      authority_envelope_hash: HashV02,
      request_clock_ref: LedgerRefV02,
      target_action_admission_ref: z.null(),
      compensation_phase_event_ref: LedgerRefV02,
    }),
  ]),
}).superRefine((event, ctx) => {
  if (event.source !== "operator") ctx.addIssue({ code: "custom", path: ["source"], message: "recovery.resume-requested must use source 'operator'" });
  if (event.authority_ref === null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "recovery.resume-requested requires authenticated human authority" });
});

export const ExecutionAttemptStartedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("execution.attempt-started"),
  payload: strictObject({
    attempt_id: MachineIdScalarV02,
    attempt_ordinal: safeInteger.positive(),
    mode: z.enum(["ordinary", "reconciliation-only", "compensation-continuation"]),
    previous_attempt_event_ref: LedgerRefV02.nullable(),
    resume_request_event_ref: LedgerRefV02.nullable(),
    resume_nonce_hash: HashV02.nullable(),
    source_boundary_sequence: safeInteger.positive(),
    source_boundary_head_hash: HashV02,
    source_manifest_hash: HashV02,
    repository_state_hash: HashV02,
    plan_hash: HashV02,
    input_hash: HashV02,
    recovery_policy_hash: HashV02,
    authority_envelope_hash: HashV02,
    run_owner_lease_id: MachineIdScalarV02,
    issued_clock_ref: LedgerRefV02,
    deadline_elapsed_ms: safeInteger.positive(),
    boot_id_hash: HashV02,
    monotonic_clock_id: MachineIdScalarV02,
    previous_fence_epoch: safeInteger.nonnegative(),
    fence_epoch: safeInteger.nonnegative(),
  }),
}).superRefine((event, ctx) => {
  if (event.source !== "kernel") ctx.addIssue({ code: "custom", path: ["source"], message: "execution.attempt-started must use source 'kernel'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "execution.attempt-started must not name authority" });
  const initialAttempt = event.payload.attempt_ordinal === 1;
  const hasResumeTriplet = event.payload.previous_attempt_event_ref !== null
    && event.payload.resume_request_event_ref !== null
    && event.payload.resume_nonce_hash !== null;
  if (initialAttempt) {
    if (
      event.payload.previous_attempt_event_ref !== null
      || event.payload.resume_request_event_ref !== null
      || event.payload.resume_nonce_hash !== null
      || event.payload.previous_fence_epoch !== 0
      || event.payload.fence_epoch !== 0
    ) {
      ctx.addIssue({ code: "custom", path: ["payload"], message: "initial attempt must start with null recovery refs and fence zero" });
    }
  } else {
    if (!hasResumeTriplet) {
      ctx.addIssue({ code: "custom", path: ["payload"], message: "recovery attempts require the exact prior attempt, resume request, and nonce bindings" });
    }
    if (
      event.payload.previous_fence_epoch >= Number.MAX_SAFE_INTEGER
      || event.payload.fence_epoch !== event.payload.previous_fence_epoch + 1
    ) {
      ctx.addIssue({ code: "custom", path: ["payload", "fence_epoch"], message: "recovery attempts must advance the prior fence by exactly one" });
    }
  }
});

export const OwnershipLeaseAcquiredEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("ownership.lease-acquired"),
  payload: z.discriminatedUnion("scope", [
    strictObject({
      owner_lease_id: MachineIdScalarV02,
      scope: z.literal("task"),
      scope_ref: HumanIdScalarV02,
      parent_run_owner_lease_id: MachineIdScalarV02,
      attempt_event_ref: LedgerRefV02,
      issued_clock_ref: LedgerRefV02,
      deadline_elapsed_ms: safeInteger.positive(),
      boot_id_hash: HashV02,
      monotonic_clock_id: MachineIdScalarV02,
      fence_epoch: safeInteger.nonnegative(),
      heartbeat_limit: safeInteger.positive(),
    }),
    strictObject({
      owner_lease_id: MachineIdScalarV02,
      scope: z.literal("integrator"),
      scope_ref: MachineIdScalarV02,
      parent_run_owner_lease_id: MachineIdScalarV02,
      attempt_event_ref: LedgerRefV02,
      issued_clock_ref: LedgerRefV02,
      deadline_elapsed_ms: safeInteger.positive(),
      boot_id_hash: HashV02,
      monotonic_clock_id: MachineIdScalarV02,
      fence_epoch: safeInteger.nonnegative(),
      heartbeat_limit: safeInteger.positive(),
    }),
  ]),
}).superRefine((event, ctx) => {
  if (event.source !== "policy-enforcement-point") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "ownership.lease-acquired must use source 'policy-enforcement-point'" });
  }
  if (event.authority_ref === null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "ownership.lease-acquired requires current authority" });
  }
});

export const OwnershipLeaseHeartbeatRecordedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("ownership.lease-heartbeat-recorded"),
  payload: strictObject({
    owner_lease_event_ref: LedgerRefV02,
    heartbeat_ordinal: safeInteger.positive(),
    observation_clock_ref: LedgerRefV02,
    previous_deadline_elapsed_ms: safeInteger.nonnegative(),
    deadline_elapsed_ms: safeInteger.positive(),
    boot_id_hash: HashV02,
    monotonic_clock_id: MachineIdScalarV02,
    fence_epoch: safeInteger.nonnegative(),
  }),
}).superRefine((event, ctx) => {
  if (event.source !== "kernel") ctx.addIssue({ code: "custom", path: ["source"], message: "ownership.lease-heartbeat-recorded must use source 'kernel'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "ownership.lease-heartbeat-recorded must not name authority" });
  if (event.payload.deadline_elapsed_ms <= event.payload.previous_deadline_elapsed_ms) {
    ctx.addIssue({ code: "custom", path: ["payload", "deadline_elapsed_ms"], message: "heartbeat must extend the prior deadline" });
  }
});

export const OwnershipLeaseReleasedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("ownership.lease-released"),
  payload: strictObject({
    owner_lease_event_ref: LedgerRefV02,
    release_clock_ref: LedgerRefV02,
    reason: z.enum(["completed", "pause", "abort", "revoked", "superseded"]),
    fence_epoch: safeInteger.nonnegative(),
  }),
}).superRefine((event, ctx) => {
  if (event.source !== "kernel") ctx.addIssue({ code: "custom", path: ["source"], message: "ownership.lease-released must use source 'kernel'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "ownership.lease-released must not name authority" });
});

export const RunCompactionRecordedEventV04 = RuntimeEventEnvelopeV04.extend({
  event_type: z.literal("run.compaction-recorded"),
  payload: strictObject({
    summary_id: MachineIdScalarV02,
    summary_record_path: RelativeRunPathScalarV02,
    summary_record_hash: HashV02,
    summary_content_path: RelativeRunPathScalarV02,
    summary_content_hash: HashV02,
    summary_size_bytes: safeInteger.positive(),
    attempt_event_ref: LedgerRefV02,
    integrator_lease_event_ref: LedgerRefV02,
    source_first_event_ref: LedgerRefV02,
    source_last_event_ref: LedgerRefV02,
    source_prefix_sequence: safeInteger.positive(),
    source_prefix_head_hash: HashV02,
    pre_context_hash: HashV02,
    post_context_hash: HashV02,
  }),
}).superRefine((event, ctx) => {
  if (event.source !== "kernel") ctx.addIssue({ code: "custom", path: ["source"], message: "run.compaction-recorded must use source 'kernel'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.compaction-recorded must not name authority" });
  const expectedRecordPath = `summaries/records/${event.payload.summary_id}.json`;
  const expectedContentPath = `summaries/content/${event.payload.summary_id}.bin`;
  if (event.payload.summary_record_path !== expectedRecordPath) {
    ctx.addIssue({ code: "custom", path: ["payload", "summary_record_path"], message: "summary record path must match the exact fixed summaries/records/<summary-id>.json form" });
  }
  if (event.payload.summary_content_path !== expectedContentPath) {
    ctx.addIssue({ code: "custom", path: ["payload", "summary_content_path"], message: "summary content path must match the exact fixed summaries/content/<summary-id>.bin form" });
  }
});

export const RuntimeEventTypesV04 = [
  ...v02.RuntimeEventTypesV02,
  "run.started",
  "run.paused",
  "run.quarantined",
  "process.termination-attempted",
  "integrity.observation-rejected",
  "task.execution-non-entry-acknowledged",
  "control.pause-requested",
  "recovery.resume-requested",
  "execution.attempt-started",
  "ownership.lease-acquired",
  "ownership.lease-heartbeat-recorded",
  "ownership.lease-released",
  "run.compaction-recorded",
] as const;

export const RuntimeEventV04 = z.discriminatedUnion("event_type", [
  RunInitializedEventV04,
  RunClockObservedEventV04,
  RunFenceAdvancedEventV04,
  ControlAbortRequestedEventV04,
  GateResultRequiredEventV04,
  GateResultRecordedEventV04,
  EvaluationResultRequiredEventV04,
  EvaluationResultRecordedEventV04,
  AuthorityHumanAuthorizationRecordedEventV04,
  AuthorityEnvelopeRecordedEventV04,
  ApprovalRecommendationRecordedEventV04,
  PolicyDecisionRecordedEventV04,
  AuthorityWaiverRecordedEventV04,
  AuthorityGrantRevokedEventV04,
  EvidenceRecordedEventV04,
  ObservationManualRecordedEventV04,
  ClaimRecordedEventV04,
  FindingRecordedEventV04,
  WaiverRecordedEventV04,
  LeaseIssuedEventV04,
  TaskActionAdmittedEventV04,
  ToolCallAdmittedEventV04,
  ArtifactWriteAdmittedEventV04,
  LimitAdmissionBlockedEventV04,
  TaskExecutionStartedEventV04,
  TaskExecutionCompletedEventV04,
  TaskProgressFactRecordedEventV04,
  TaskExecutionFailedEventV04,
  TaskActionOutcomeUnknownEventV04,
  TaskExecutionNonEntryAcknowledgedEventV04,
  TaskActionOutcomeReconciledEventV04,
  ArtifactRecordedEventV04,
  RecordRedactionDerivativeRecordedEventV04,
  RecordCustodyStateRecordedEventV04,
  RecordExportDecisionRecordedEventV04,
  EffectOutcomeEventV04,
  TaskActionSettledEventV04,
  LoopAttemptCompletedEventV04,
  TaskProgressObservedEventV04,
  RunTerminalFreezeEnteredEventV04,
  RunTerminalFreezeRevisedEventV04,
  RunCompensationRequestedEventV04,
  RunCompensationRequestRevisedEventV04,
  RunCompensationPhaseEnteredEventV04,
  RunCompensationCandidateEscalatedEventV04,
  CompensationSettledEventV04,
  RunTerminalSealedEventV04,
  RunStartedEventV04,
  RunPausedEventV04,
  RunQuarantinedEventV04,
  ProcessTerminationAttemptedEventV04,
  IntegrityObservationRejectedEventV04,
  ControlPauseRequestedEventV04,
  RecoveryResumeRequestedEventV04,
  ExecutionAttemptStartedEventV04,
  OwnershipLeaseAcquiredEventV04,
  OwnershipLeaseHeartbeatRecordedEventV04,
  OwnershipLeaseReleasedEventV04,
  RunCompactionRecordedEventV04,
]);

export type RuntimeSchemaInventoryV04Value = z.infer<typeof RuntimeSchemaInventoryV04>;
export type RuntimeExecutionPolicyV03Value = z.infer<typeof RuntimeExecutionPolicyV03>;
export type ResolvedRunPlanV03Value = z.infer<typeof ResolvedRunPlanV03>;
export type RuntimeEventV04Value = z.infer<typeof RuntimeEventV04>;

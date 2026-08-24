import { z } from "zod";

import * as v02 from "./runtime.js";

type WithV03Version<S extends z.ZodRawShape> = Omit<S, "schema_version"> & {
  schema_version: z.ZodLiteral<"0.3">;
};

function withV03Version<
  S extends z.ZodRawShape & { schema_version: z.ZodType },
  C extends z.core.$ZodObjectConfig,
>(schema: z.ZodObject<S, C>): z.ZodObject<WithV03Version<S>, C> {
  const composable = schema as unknown as z.ZodObject<
    Omit<S, "schema_version"> & { schema_version: z.ZodUnknown },
    C
  >;
  return composable.safeExtend({ schema_version: z.literal("0.3") } as never) as z.ZodObject<WithV03Version<S>, C>;
}

export const RuntimeSchemaInventoryV03 = z.object({
  ...v02.RuntimeSchemaInventoryV02.shape,
  ledger_event: z.literal("0.3"),
}).strict();

const RunInitializedPayloadV03 = z.object({
  ...v02.RunInitializedEventV02.shape.payload.shape,
  runtime_schema_versions: RuntimeSchemaInventoryV03,
}).strict();

export const RunInitializedEventV03 = z.object({
  ...v02.RunInitializedEventV02.shape,
  schema_version: z.literal("0.3"),
  payload: RunInitializedPayloadV03,
}).strict().superRefine((event, ctx) => {
  if (event.source !== "kernel") ctx.addIssue({ code: "custom", path: ["source"], message: "run.initialized must use source 'kernel'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.initialized must not name authority" });
  if (event.sequence !== 1) ctx.addIssue({ code: "custom", path: ["sequence"], message: "run.initialized must be sequence 1" });
  if (event.previous_event_hash !== null) ctx.addIssue({ code: "custom", path: ["previous_event_hash"], message: "run.initialized must not name a previous event" });
});

export const RunClockObservedEventV03 = withV03Version(v02.RunClockObservedEventV02);
export const RunFenceAdvancedEventV03 = withV03Version(v02.RunFenceAdvancedEventV02);
export const ControlAbortRequestedEventV03 = withV03Version(v02.ControlAbortRequestedEventV02);
export const GateResultRequiredEventV03 = withV03Version(v02.GateResultRequiredEventV02);
export const GateResultRecordedEventV03 = withV03Version(v02.GateResultRecordedEventV02);
export const EvaluationResultRequiredEventV03 = withV03Version(v02.EvaluationResultRequiredEventV02);
export const EvaluationResultRecordedEventV03 = withV03Version(v02.EvaluationResultRecordedEventV02);
export const AuthorityHumanAuthorizationRecordedEventV03 = withV03Version(v02.AuthorityHumanAuthorizationRecordedEventV02);
export const AuthorityEnvelopeRecordedEventV03 = withV03Version(v02.AuthorityEnvelopeRecordedEventV02);
export const ApprovalRecommendationRecordedEventV03 = withV03Version(v02.ApprovalRecommendationRecordedEventV02);
export const PolicyDecisionRecordedEventV03 = withV03Version(v02.PolicyDecisionRecordedEventV02);
export const AuthorityWaiverRecordedEventV03 = withV03Version(v02.AuthorityWaiverRecordedEventV02);
export const AuthorityGrantRevokedEventV03 = withV03Version(v02.AuthorityGrantRevokedEventV02);
export const EvidenceRecordedEventV03 = withV03Version(v02.EvidenceRecordedEventV02);
export const ObservationManualRecordedEventV03 = withV03Version(v02.ObservationManualRecordedEventV02);
export const ClaimRecordedEventV03 = withV03Version(v02.ClaimRecordedEventV02);
export const FindingRecordedEventV03 = withV03Version(v02.FindingRecordedEventV02);
export const WaiverRecordedEventV03 = withV03Version(v02.WaiverRecordedEventV02);
export const LeaseIssuedEventV03 = withV03Version(v02.LeaseIssuedEventV02);
export const TaskActionAdmittedEventV03 = withV03Version(v02.TaskActionAdmittedEventV02);
export const ToolCallAdmittedEventV03 = withV03Version(v02.ToolCallAdmittedEventV02);
export const ArtifactWriteAdmittedEventV03 = withV03Version(v02.ArtifactWriteAdmittedEventV02);
export const LimitAdmissionBlockedEventV03 = withV03Version(v02.LimitAdmissionBlockedEventV02);
export const TaskExecutionStartedEventV03 = withV03Version(v02.TaskExecutionStartedEventV02);
export const TaskExecutionCompletedEventV03 = withV03Version(v02.TaskExecutionCompletedEventV02);
export const TaskProgressFactRecordedEventV03 = withV03Version(v02.TaskProgressFactRecordedEventV02);
export const TaskExecutionFailedEventV03 = withV03Version(v02.TaskExecutionFailedEventV02);
export const TaskActionOutcomeUnknownEventV03 = withV03Version(v02.TaskActionOutcomeUnknownEventV02);
export const TaskActionOutcomeReconciledEventV03 = withV03Version(v02.TaskActionOutcomeReconciledEventV02);
export const ArtifactRecordedEventV03 = withV03Version(v02.ArtifactRecordedEventV02);
export const RecordRedactionDerivativeRecordedEventV03 = withV03Version(v02.RecordRedactionDerivativeRecordedEventV02);
export const RecordCustodyStateRecordedEventV03 = withV03Version(v02.RecordCustodyStateRecordedEventV02);
export const RecordExportDecisionRecordedEventV03 = withV03Version(v02.RecordExportDecisionRecordedEventV02);
export const EffectOutcomeEventV03 = withV03Version(v02.EffectOutcomeEventV02);
export const TaskActionSettledEventV03 = withV03Version(v02.TaskActionSettledEventV02);
export const LoopAttemptCompletedEventV03 = withV03Version(v02.LoopAttemptCompletedEventV02);
export const TaskProgressObservedEventV03 = withV03Version(v02.TaskProgressObservedEventV02);
export const RunTerminalFreezeEnteredEventV03 = withV03Version(v02.RunTerminalFreezeEnteredEventV02);
export const RunTerminalFreezeRevisedEventV03 = withV03Version(v02.RunTerminalFreezeRevisedEventV02);
export const RunCompensationRequestedEventV03 = withV03Version(v02.RunCompensationRequestedEventV02);
export const RunCompensationRequestRevisedEventV03 = withV03Version(v02.RunCompensationRequestRevisedEventV02);
export const RunCompensationPhaseEnteredEventV03 = withV03Version(v02.RunCompensationPhaseEnteredEventV02);
export const RunCompensationCandidateEscalatedEventV03 = withV03Version(v02.RunCompensationCandidateEscalatedEventV02);
export const CompensationSettledEventV03 = withV03Version(v02.CompensationSettledEventV02);
export const RunTerminalSealedEventV03 = withV03Version(v02.RunTerminalSealedEventV02);

const RuntimeEventEnvelopeV02Shape = v02.RunClockObservedEventV02.shape;
const RuntimeEventEnvelopeV03 = z.object({
  schema_version: z.literal("0.3"),
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
}).strict();

const HashV03 = v02.RunInitializedEventV02.shape.payload.shape.plan_hash;
const MachineIdV03 = v02.RunClockObservedEventV02.shape.payload.shape.clock_id;
const CanonicalLedgerRefsV03 = z.array(v02.LedgerRefV02).min(1).superRefine((refs, ctx) => {
  for (let index = 1; index < refs.length; index += 1) {
    const previous = refs[index - 1]!;
    const current = refs[index]!;
    if (previous.ledger_sequence > current.ledger_sequence
      || (previous.ledger_sequence === current.ledger_sequence && previous.event_hash >= current.event_hash)) {
      ctx.addIssue({ code: "custom", path: [index], message: "ledger references must be unique and sorted" });
    }
  }
});

export const RunStartedEventV03 = RuntimeEventEnvelopeV03.extend({
  event_type: z.literal("run.started"),
  payload: z.object({ executor_profile_hash: HashV03 }).strict(),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "kernel") ctx.addIssue({ code: "custom", path: ["source"], message: "run.started must use source 'kernel'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.started must not name authority" });
});

export const RunPausedEventV03 = RuntimeEventEnvelopeV03.extend({
  event_type: z.literal("run.paused"),
  payload: z.discriminatedUnion("requested_by", [
    z.object({ requested_by: z.literal("operator"), reason_code: z.literal("operator-request"), request_event_ref: v02.LedgerRefV02 }).strict(),
    z.object({ requested_by: z.literal("policy"), reason_code: z.literal("policy-hold"), request_event_ref: v02.LedgerRefV02 }).strict(),
  ]),
}).strict().superRefine((event, ctx) => {
  const expectedSource = event.payload.requested_by === "operator" ? "operator" : "policy-enforcement-point";
  if (event.source !== expectedSource) ctx.addIssue({ code: "custom", path: ["source"], message: "run.paused source must match requested_by" });
  if (event.authority_ref === null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.paused requires requester authority" });
});

export const RunQuarantinedEventV03 = RuntimeEventEnvelopeV03.extend({
  event_type: z.literal("run.quarantined"),
  payload: z.object({
    reason_code: z.enum(["unmatched-observation", "authority-breach", "capture-gap"]),
    evidence_refs: CanonicalLedgerRefsV03,
  }).strict(),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "integrity") ctx.addIssue({ code: "custom", path: ["source"], message: "run.quarantined must use source 'integrity'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.quarantined must not name authority" });
});

export const ProcessTerminationAttemptedEventV03 = RuntimeEventEnvelopeV03.extend({
  event_type: z.literal("process.termination-attempted"),
  payload: z.object({
    trigger: z.enum(["abort", "quarantine"]),
    trigger_event_ref: v02.LedgerRefV02,
    adapter_invocation_id: MachineIdV03,
    observed_outcome: z.enum(["terminated", "not-terminated", "unknown"]),
  }).strict(),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "adapter") ctx.addIssue({ code: "custom", path: ["source"], message: "process.termination-attempted must use source 'adapter'" });
  if (event.authority_ref !== null) ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "process.termination-attempted must not name authority" });
});

export const RuntimeEventTypesV03 = [
  ...v02.RuntimeEventTypesV02,
  "run.started",
  "run.paused",
  "run.quarantined",
  "process.termination-attempted",
] as const;

export const RuntimeEventV03 = z.discriminatedUnion("event_type", [
  RunInitializedEventV03,
  RunClockObservedEventV03,
  RunFenceAdvancedEventV03,
  ControlAbortRequestedEventV03,
  GateResultRequiredEventV03,
  GateResultRecordedEventV03,
  EvaluationResultRequiredEventV03,
  EvaluationResultRecordedEventV03,
  AuthorityHumanAuthorizationRecordedEventV03,
  AuthorityEnvelopeRecordedEventV03,
  ApprovalRecommendationRecordedEventV03,
  PolicyDecisionRecordedEventV03,
  AuthorityWaiverRecordedEventV03,
  AuthorityGrantRevokedEventV03,
  EvidenceRecordedEventV03,
  ObservationManualRecordedEventV03,
  ClaimRecordedEventV03,
  FindingRecordedEventV03,
  WaiverRecordedEventV03,
  LeaseIssuedEventV03,
  TaskActionAdmittedEventV03,
  ToolCallAdmittedEventV03,
  ArtifactWriteAdmittedEventV03,
  LimitAdmissionBlockedEventV03,
  TaskExecutionStartedEventV03,
  TaskExecutionCompletedEventV03,
  TaskProgressFactRecordedEventV03,
  TaskExecutionFailedEventV03,
  TaskActionOutcomeUnknownEventV03,
  TaskActionOutcomeReconciledEventV03,
  ArtifactRecordedEventV03,
  RecordRedactionDerivativeRecordedEventV03,
  RecordCustodyStateRecordedEventV03,
  RecordExportDecisionRecordedEventV03,
  EffectOutcomeEventV03,
  TaskActionSettledEventV03,
  LoopAttemptCompletedEventV03,
  TaskProgressObservedEventV03,
  RunTerminalFreezeEnteredEventV03,
  RunTerminalFreezeRevisedEventV03,
  RunCompensationRequestedEventV03,
  RunCompensationRequestRevisedEventV03,
  RunCompensationPhaseEnteredEventV03,
  RunCompensationCandidateEscalatedEventV03,
  CompensationSettledEventV03,
  RunTerminalSealedEventV03,
  RunStartedEventV03,
  RunPausedEventV03,
  RunQuarantinedEventV03,
  ProcessTerminationAttemptedEventV03,
]);

export type RuntimeSchemaInventoryV03Value = z.infer<typeof RuntimeSchemaInventoryV03>;
export type RuntimeEventV03Value = z.infer<typeof RuntimeEventV03>;

import { deriveControlPlaneBudgetV02 } from "../compiler/control-plane-budget-v02.js";
import { ResolvedRunPlanV02, type ResolvedRunPlanV02Value } from "./runtime.js";

export type RuntimeAdapterProfileIdV03 =
  | "s41-captured-codex-cli-v01"
  | "s41-captured-claude-code-cli-v01";

type RuntimeAdapterProfileV03 = Readonly<{
  profile_id: RuntimeAdapterProfileIdV03;
  engine: ResolvedRunPlanV02Value["adapter_plan"]["engine"];
  command: string;
  max_process_runtime_ms: number;
}>;

export type RuntimeExecutionPolicyValueV03 = Readonly<{
  profile_id: "runtime-execution-controls-v04-s41-1";
  charge_profile_id: "control-plane-charge-ceilings-v04-s41-1";
  max_process_runtime_ms: number;
  max_execution_attempts: number;
  run_owner_acquisition_max: number;
  task_owner_acquisition_max: number;
  integrator_acquisition_max: number;
  owner_lease_duration_ms: number;
  heartbeat_interval_ms: number;
  run_heartbeat_event_max: number;
  task_heartbeat_event_max: number;
  integrator_heartbeat_event_max: number;
  run_owner_release_max: number;
  task_owner_release_max: number;
  integrator_release_max: number;
  max_compaction_events: number;
  max_summary_records: number;
  max_summary_content_bytes: number;
}>;

export type CapturedRuntimeProfileRegistryV03 = Readonly<{
  registry_id: "s41-captured-runtime-profile-registry-v01";
  readonly __captured_runtime_profile_registry_v03: unique symbol;
}>;

export type RuntimeExecutionPolicyDerivationV03 = Readonly<{
  runtime_execution_policy: RuntimeExecutionPolicyValueV03;
  required_control_plane_output_bytes: number;
}>;

export type RuntimeExecutionPolicyDerivationResultV03 =
  | Readonly<{ ok: true; value: RuntimeExecutionPolicyDerivationV03 }>
  | Readonly<{ ok: false; reason: "INVALID_V03_RUNTIME_EXECUTION_POLICY" }>;

const INVALID_POLICY = Object.freeze({
  ok: false,
  reason: "INVALID_V03_RUNTIME_EXECUTION_POLICY",
} as const);
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const PRIMARY_EVENT_MAX_BYTES = 131_072n;
const SUMMARY_RECORD_MAX_BYTES = 262_144n;
const capturedRegistryBrands = new WeakSet<object>();
const CAPTURED_RUNTIME_PROFILE_REGISTRY_V03 = Object.freeze({
  registry_id: "s41-captured-runtime-profile-registry-v01",
}) as CapturedRuntimeProfileRegistryV03;
capturedRegistryBrands.add(CAPTURED_RUNTIME_PROFILE_REGISTRY_V03);

const RUNTIME_ADAPTER_PROFILES_V03: Readonly<Record<RuntimeAdapterProfileIdV03, RuntimeAdapterProfileV03>> =
  Object.freeze({
    "s41-captured-codex-cli-v01": Object.freeze({
      profile_id: "s41-captured-codex-cli-v01",
      engine: "codex_cli",
      command: "codex exec --json",
      max_process_runtime_ms: 30_000,
    }),
    "s41-captured-claude-code-cli-v01": Object.freeze({
      profile_id: "s41-captured-claude-code-cli-v01",
      engine: "claude_code_cli",
      command: "claude -p --output-format stream-json --include-hook-events",
      max_process_runtime_ms: 30_000,
    }),
  });

function safeBigInt(value: number): bigint | null {
  return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
}

function safeNumber(value: bigint): number | null {
  return value >= 0n && value <= MAX_SAFE ? Number(value) : null;
}

function ceilDivide(dividend: bigint, divisor: bigint): bigint | null {
  return dividend >= 0n && divisor > 0n ? (dividend + divisor - 1n) / divisor : null;
}

function registeredProfile(profileId: unknown): RuntimeAdapterProfileV03 | null {
  if (typeof profileId !== "string" || !Object.hasOwn(RUNTIME_ADAPTER_PROFILES_V03, profileId)) {
    return null;
  }
  return RUNTIME_ADAPTER_PROFILES_V03[profileId as RuntimeAdapterProfileIdV03];
}

function deriveRuntimeExecutionPolicyV03(
  plan: ResolvedRunPlanV02Value,
  profileId: unknown,
): RuntimeExecutionPolicyDerivationResultV03 {
  const profile = registeredProfile(profileId);
  if (
    profile === null
    || plan.adapter_plan.engine !== profile.engine
    || plan.adapter_plan.command !== profile.command
  ) return INVALID_POLICY;

  const retryMaxByTask = new Map<string, bigint>();
  for (const task of plan.tasks) retryMaxByTask.set(task.id, 0n);
  for (const rule of plan.retry_policy.rules) {
    const maximum = safeBigInt(rule.max_task_executions);
    if (maximum === null) return INVALID_POLICY;
    const current = retryMaxByTask.get(rule.task_ref);
    if (current === undefined) return INVALID_POLICY;
    if (maximum > current) retryMaxByTask.set(rule.task_ref, maximum);
  }

  let actionAttempts = 0n;
  for (const task of plan.tasks) {
    const maximum = retryMaxByTask.get(task.id);
    if (maximum === undefined || maximum < 1n) return INVALID_POLICY;
    actionAttempts += maximum;
    if (actionAttempts > MAX_SAFE) return INVALID_POLICY;
  }

  const compensationCount = safeBigInt(plan.compensations.length);
  const loopAttemptLimit = safeBigInt(plan.limit_policy.max_loop_attempts);
  const globalElapsedLimit = safeBigInt(plan.limit_policy.max_elapsed_ms);
  const globalOutputLimit = safeBigInt(plan.limit_policy.max_output_bytes);
  const controlReserve = safeBigInt(plan.limit_policy.control_plane_output_reserve_bytes);
  const recoveryOutputReserve = safeBigInt(plan.recovery_policy.reserve.max_output_bytes ?? 0);
  const profileProcessLimit = safeBigInt(profile.max_process_runtime_ms);
  if (
    compensationCount === null
    || loopAttemptLimit === null
    || loopAttemptLimit < 1n
    || globalElapsedLimit === null
    || globalOutputLimit === null
    || controlReserve === null
    || recoveryOutputReserve === null
    || profileProcessLimit === null
  ) return INVALID_POLICY;

  const executionAttemptLimit = 1n + (2n * actionAttempts) + (2n * compensationCount) + 8n;
  if (executionAttemptLimit > MAX_SAFE) return INVALID_POLICY;

  const maxProcessRuntime = globalElapsedLimit < profileProcessLimit
    ? globalElapsedLimit
    : profileProcessLimit;
  const ownerLeaseDuration = maxProcessRuntime < 30_000n ? maxProcessRuntime : 30_000n;
  if (ownerLeaseDuration < 2n) return INVALID_POLICY;
  const heartbeatInterval = ownerLeaseDuration / 3n > 1n ? ownerLeaseDuration / 3n : 1n;
  if (heartbeatInterval >= ownerLeaseDuration) return INVALID_POLICY;

  const qRun = ceilDivide(globalElapsedLimit, heartbeatInterval);
  const qTask = ceilDivide(maxProcessRuntime, heartbeatInterval);
  if (qRun === null || qTask === null) return INVALID_POLICY;

  const runHeartbeats = executionAttemptLimit * qRun;
  const taskHeartbeats = actionAttempts * qTask;
  const integratorHeartbeats = executionAttemptLimit * qRun;
  const workOutputLimit = globalOutputLimit - controlReserve - recoveryOutputReserve;
  if (
    runHeartbeats > MAX_SAFE
    || taskHeartbeats > MAX_SAFE
    || integratorHeartbeats > MAX_SAFE
    || workOutputLimit <= 0n
  ) return INVALID_POLICY;

  const maxProcessRuntimeNumber = safeNumber(maxProcessRuntime);
  const executionAttemptLimitNumber = safeNumber(executionAttemptLimit);
  const actionAttemptsNumber = safeNumber(actionAttempts);
  const ownerLeaseDurationNumber = safeNumber(ownerLeaseDuration);
  const heartbeatIntervalNumber = safeNumber(heartbeatInterval);
  const runHeartbeatsNumber = safeNumber(runHeartbeats);
  const taskHeartbeatsNumber = safeNumber(taskHeartbeats);
  const integratorHeartbeatsNumber = safeNumber(integratorHeartbeats);
  const loopAttemptLimitNumber = safeNumber(loopAttemptLimit);
  const summaryContentNumber = safeNumber(workOutputLimit < 65_536n ? workOutputLimit : 65_536n);
  if (
    maxProcessRuntimeNumber === null
    || executionAttemptLimitNumber === null
    || actionAttemptsNumber === null
    || ownerLeaseDurationNumber === null
    || heartbeatIntervalNumber === null
    || runHeartbeatsNumber === null
    || taskHeartbeatsNumber === null
    || integratorHeartbeatsNumber === null
    || loopAttemptLimitNumber === null
    || summaryContentNumber === null
  ) return INVALID_POLICY;

  const runtimeExecutionPolicy: RuntimeExecutionPolicyValueV03 = {
    profile_id: "runtime-execution-controls-v04-s41-1",
    charge_profile_id: "control-plane-charge-ceilings-v04-s41-1",
    max_process_runtime_ms: maxProcessRuntimeNumber,
    max_execution_attempts: executionAttemptLimitNumber,
    run_owner_acquisition_max: executionAttemptLimitNumber,
    task_owner_acquisition_max: actionAttemptsNumber,
    integrator_acquisition_max: executionAttemptLimitNumber,
    owner_lease_duration_ms: ownerLeaseDurationNumber,
    heartbeat_interval_ms: heartbeatIntervalNumber,
    run_heartbeat_event_max: runHeartbeatsNumber,
    task_heartbeat_event_max: taskHeartbeatsNumber,
    integrator_heartbeat_event_max: integratorHeartbeatsNumber,
    run_owner_release_max: executionAttemptLimitNumber,
    task_owner_release_max: actionAttemptsNumber,
    integrator_release_max: executionAttemptLimitNumber,
    max_compaction_events: loopAttemptLimitNumber,
    max_summary_records: loopAttemptLimitNumber,
    max_summary_content_bytes: summaryContentNumber,
  };

  const v02Budget = deriveControlPlaneBudgetV02(plan);
  if (!v02Budget.ok) return INVALID_POLICY;

  const resumeRequests = executionAttemptLimit - 1n;
  const subordinateAcquisitions = actionAttempts + executionAttemptLimit;
  const heartbeats = runHeartbeats + taskHeartbeats + integratorHeartbeats;
  const releases = actionAttempts + (2n * executionAttemptLimit);
  const addedNonClockEvents = resumeRequests
    + executionAttemptLimit
    + subordinateAcquisitions
    + heartbeats
    + releases
    + executionAttemptLimit
    + loopAttemptLimit;
  const addedClockEvents = resumeRequests
    + executionAttemptLimit
    + subordinateAcquisitions
    + heartbeats
    + releases
    + executionAttemptLimit;
  const requiredControlBytes = BigInt(v02Budget.value.required_control_plane_output_bytes)
    + ((addedNonClockEvents + addedClockEvents) * PRIMARY_EVENT_MAX_BYTES)
    + (loopAttemptLimit * SUMMARY_RECORD_MAX_BYTES);
  const requiredControlBytesNumber = safeNumber(requiredControlBytes);
  if (requiredControlBytesNumber === null || requiredControlBytes > controlReserve) return INVALID_POLICY;

  return {
    ok: true,
    value: {
      runtime_execution_policy: runtimeExecutionPolicy,
      required_control_plane_output_bytes: requiredControlBytesNumber,
    },
  };
}

export function deriveRuntimeExecutionPolicyForRegisteredAdapterV03(
  input: unknown,
): RuntimeExecutionPolicyDerivationResultV03 {
  const parsed = ResolvedRunPlanV02.safeParse(input);
  if (!parsed.success) return INVALID_POLICY;
  const plan = parsed.data;
  const profileId: RuntimeAdapterProfileIdV03 = plan.adapter_plan.engine === "codex_cli"
    ? "s41-captured-codex-cli-v01"
    : "s41-captured-claude-code-cli-v01";
  return deriveRuntimeExecutionPolicyV03(plan, profileId);
}

export function captureRuntimeProfileRegistryV03(): CapturedRuntimeProfileRegistryV03 {
  return CAPTURED_RUNTIME_PROFILE_REGISTRY_V03;
}

export function isCapturedRuntimeProfileRegistryV03(
  input: unknown,
): input is CapturedRuntimeProfileRegistryV03 {
  return typeof input === "object" && input !== null && capturedRegistryBrands.has(input);
}

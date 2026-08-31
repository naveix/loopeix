import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

const privateFiles = Object.freeze([
  "src/schema/runtime-v04.ts",
  "src/schema/runtime-plan-v03.ts",
  "src/run/project-plan-v03.ts",
  "src/run/runtime-ledger-v04.ts",
  "src/run/runtime-state-reducer-v04.ts",
  "src/run/runtime-manifest-v04.ts",
  "src/run/runtime-limit-accounting-v04.ts",
  "src/run/runtime-summary-v04.ts",
  "src/run/runtime-terminal-v04.ts",
  "src/run/runtime-recovery-authorization-v04.ts",
  "src/run/runtime-pause-authorization-v04.ts",
  "src/run/runtime-recovery-v04.ts",
  "src/run/runtime-clock-observation-v04.ts",
  "src/run/runtime-file-store-v04.ts",
  "src/run/runtime-write-session-v04.ts",
  "src/run/runtime-control-write-v04.ts",
  "src/run/runtime-non-entry-write-v04.ts",
  "src/run/runtime-revocation-write-v04.ts",
  "src/run/runtime-terminal-write-v04.ts",
  "src/run/runtime-compensation-write-v04.ts",
  "src/run/runtime-status-v04.ts",
  "src/run/runtime-directory-v04.ts",
]);

const publicForbiddenSymbols = Object.freeze([
  "captureRuntimeRecoveryRequestV04",
  "inspectCapturedRuntimeRecoveryRequestV04",
  "consumeCapturedRuntimeRecoveryRequestV04",
  "captureRuntimePauseRequestV04",
  "inspectCapturedRuntimePauseRequestV04",
  "consumeCapturedRuntimePauseRequestV04",
  "pauseRuntimeWriteSessionV04",
  "continuePendingPauseRuntimeWriteSessionV04",
  "captureRuntimeAbortRequestV04",
  "abortRuntimeControlV04",
  "continuePendingAbortRuntimeControlV04",
  "writeRuntimeNonEntryReconciliationV04",
  "writeRuntimeTerminalV04",
  "writeRuntimeCompensationV04",
  "compactRuntimeWriteSessionV04",
  "buildRuntimeTerminalProjectionV04",
  "evaluateRuntimeTerminalV04",
  "captureRuntimeFileStoreV04",
  "captureRuntimeClockSourceV04",
  "observeRuntimeClockV04",
  "consumeRuntimeClockObservationV04",
  "openRuntimeFileStoreSessionV04",
  "resumeRuntimeWriteSessionV04",
  "captureRuntimeAuthorityRevocationV04",
  "revokeRuntimeAuthorityV04",
  "continuePendingRuntimeAuthorityRevocationV04",
  "projectRuntimeStatusV04",
  "inspectRuntimeDirectoryV04",
]);

function text(root, path) {
  const file = resolve(root, path);
  return existsSync(file) ? readFileSync(file, "utf8") : null;
}

function requireSnippet(violations, path, source, snippet, label) {
  if (source === null || !source.includes(snippet)) violations.add(`${label}:${path}`);
}

function exactAuthorizationKeys(source) {
  if (source === null) return [];
  const start = source.indexOf("const RuntimeRecoveryAuthorizationInputV04 = z.object({");
  const end = source.indexOf("}).strict();", start);
  if (start < 0 || end < 0) return [];
  return [...source.slice(start, end).matchAll(/^  ([a-z_]+):/gmu)].map((match) => match[1]);
}

function sourceSlice(source, startMarker, endMarker) {
  if (source === null) return null;
  const start = source.indexOf(startMarker);
  const end = start < 0 ? -1 : source.indexOf(endMarker, start);
  return start < 0 || end < 0 ? null : source.slice(start, end);
}

export function runS41RecoveryBoundaryCheck({ rootDir = repositoryRoot } = {}) {
  const root = resolve(rootDir);
  const violations = new Set();
  for (const path of privateFiles) {
    if (!existsSync(resolve(root, path))) violations.add(`missing-s41-file:${path}`);
  }

  const index = text(root, "src/index.ts") ?? "";
  for (const path of privateFiles) {
    const stem = path.slice(path.lastIndexOf("/") + 1, -3);
    if (index.includes(stem)) violations.add(`public-root-private-module:${stem}`);
  }
  for (const symbol of publicForbiddenSymbols) {
    if (index.includes(symbol)) violations.add(`public-root-private-symbol:${symbol}`);
  }

  const packageText = text(root, "package.json");
  if (packageText === null) violations.add("missing-package-json");
  else {
    const metadata = JSON.parse(packageText);
    const exportsText = JSON.stringify(metadata.exports ?? {});
    if (exportsText.includes("./run/") || exportsText.includes("runtime-v04")
      || exportsText.includes("runtime-recovery") || exportsText.includes("runtime-write-session")) {
      violations.add("public-package-private-subpath");
    }
  }

  const authPath = "src/run/runtime-recovery-authorization-v04.ts";
  const auth = text(root, authPath);
  const authKeys = exactAuthorizationKeys(auth);
  const expectedAuthKeys = [
    "trust_context", "authorization_proof", "validated_plan", "ledger", "manifest",
    "repository_observation", "request",
  ];
  if (authKeys.join("\0") !== expectedAuthKeys.join("\0")) {
    violations.add(`authorization-input-keys:${authPath}:${authKeys.join(",")}`);
  }
  if (auth?.includes('"./runtime-recovery-v04.js"')) {
    violations.add(`authorization-dependency-or-consumption:${authPath}`);
  }
  requireSnippet(violations, authPath, auth, "new WeakMap<", "authorization-not-opaque");
  requireSnippet(violations, authPath, auth, "verifyHumanAuthorizationProofV02", "authorization-proof-not-verified");
  requireSnippet(violations, authPath, auth, "RISK_TIER_RANK[proof.approved_risk_tier] < RISK_TIER_RANK.T1", "authorization-risk-floor-missing");
  requireSnippet(violations, authPath, auth, "consumeCapturedRuntimeRecoveryRequestV04", "recovery-authorization-not-one-use");
  requireSnippet(violations, authPath, auth, "capturedRecoveryRequests.delete(capability)", "recovery-authorization-consumption-not-destructive");

  const pauseAuthPath = "src/run/runtime-pause-authorization-v04.ts";
  const pauseAuth = text(root, pauseAuthPath);
  requireSnippet(violations, pauseAuthPath, pauseAuth, "new WeakMap<", "pause-authorization-not-opaque");
  requireSnippet(violations, pauseAuthPath, pauseAuth, "verifyHumanAuthorizationProofV02", "pause-authorization-proof-not-verified");
  requireSnippet(violations, pauseAuthPath, pauseAuth, "consumeCapturedRuntimePauseRequestV04", "pause-authorization-not-one-use");
  requireSnippet(violations, pauseAuthPath, pauseAuth, "capturedPauseRequests.delete(capability)", "pause-authorization-consumption-not-destructive");

  const recoveryPath = "src/run/runtime-recovery-v04.ts";
  const recovery = text(root, recoveryPath);
  requireSnippet(violations, recoveryPath, recovery, "inspectCapturedRuntimeRecoveryRequestV04", "executable-recovery-capability-missing");
  requireSnippet(violations, recoveryPath, recovery, "export function projectRuntimeRecoveryAdviceV04", "recovery-advice-separation-missing");
  requireSnippet(violations, recoveryPath, recovery, "reconciliationAuthorized", "reconciliation-authorization-gate-missing");

  const clockPath = "src/run/runtime-clock-observation-v04.ts";
  const clock = text(root, clockPath);
  requireSnippet(violations, clockPath, clock, "new WeakMap<", "runtime-clock-not-opaque");
  requireSnippet(violations, clockPath, clock, "consumeRuntimeClockObservationV04", "runtime-clock-not-one-use");
  requireSnippet(violations, clockPath, clock, "RUNTIME_CLOCK_REGRESSION", "runtime-clock-regression-check-missing");

  const writerPath = "src/run/runtime-write-session-v04.ts";
  const writer = text(root, writerPath);
  const attemptCommitBlock = sourceSlice(writer, "async function commitAttempt(", "async function freshResume(");
  const requestCommitBlock = sourceSlice(writer, "async function freshResume(", "async function continuePending(");
  const attemptCommitCalls = attemptCommitBlock === null ? 0 : [...attemptCommitBlock.matchAll(/await commitRuntimeFileStoreSessionV04\(/gu)].length;
  const requestCommitCalls = requestCommitBlock === null ? 0 : [...requestCommitBlock.matchAll(/await commitRuntimeFileStoreSessionV04\(/gu)].length;
  if (attemptCommitCalls !== 1 || requestCommitCalls !== 1) {
    violations.add(`recovery-two-commit-sites:${writerPath}:${requestCommitCalls}+${attemptCommitCalls}`);
  }
  requireSnippet(violations, writerPath, writer, "binding.approved_risk_tier", "recovery-risk-propagation-missing");
  requireSnippet(violations, writerPath, writer, "consumeCapturedRuntimeRecoveryRequestV04(input.captured_request)", "recovery-capability-consumption-missing");
  requireSnippet(violations, writerPath, writer, 'classification: "REQUEST_COMMITTED_ATTEMPT_NOT_COMMITTED"', "request-only-durability-classification-missing");
  requireSnippet(violations, writerPath, writer, "summary: null", "pending-summary-authority-not-removed");
  requireSnippet(violations, writerPath, writer, "finally {", "recovery-lock-cleanup-missing");
  requireSnippet(violations, writerPath, writer, "commitRuntimeCompactionFileStoreSessionV04", "compaction-transaction-missing");
  requireSnippet(violations, writerPath, writer, 'classification: "REQUEST_COMMITTED_PAUSE_NOT_COMMITTED"', "pause-partial-durability-classification-missing");
  requireSnippet(violations, writerPath, writer, "consumeCapturedRuntimePauseRequestV04", "pause-capability-consumption-missing");

  const controlPath = "src/run/runtime-control-write-v04.ts";
  const control = text(root, controlPath);
  requireSnippet(violations, controlPath, control, "new WeakMap<", "abort-authorization-not-opaque");
  requireSnippet(violations, controlPath, control, "verifyHumanAuthorizationProofV02", "abort-authorization-proof-not-verified");
  requireSnippet(violations, controlPath, control, "RISK_TIER_RANK[proof.approved_risk_tier] < RISK_TIER_RANK.T4", "abort-authorization-risk-floor-missing");
  requireSnippet(violations, controlPath, control, "capturedAbortRequests.delete(value)", "abort-authorization-consumption-not-destructive");
  requireSnippet(violations, controlPath, control, "consumeRuntimeClockObservationV04", "abort-clock-consumption-missing");
  requireSnippet(violations, controlPath, control, '"REQUEST_COMMITTED_ABORT_NOT_COMMITTED"', "abort-partial-durability-classification-missing");

  const nonEntryPath = "src/run/runtime-non-entry-write-v04.ts";
  const nonEntry = text(root, nonEntryPath);
  requireSnippet(violations, nonEntryPath, nonEntry, "new WeakMap<", "non-entry-evidence-not-opaque");
  requireSnippet(violations, nonEntryPath, nonEntry, "consumeCapturedRuntimeNonEntryAcknowledgementV04", "non-entry-ack-consumption-missing");
  requireSnippet(violations, nonEntryPath, nonEntry, "consumeCapturedRuntimeTerminationEvidenceV04", "non-entry-termination-consumption-missing");
  requireSnippet(violations, nonEntryPath, nonEntry, 'trigger: "reconciliation"', "non-entry-reconciliation-trigger-missing");
  requireSnippet(violations, nonEntryPath, nonEntry, "commitRuntimeFileStoreSessionV04", "non-entry-durable-commit-missing");

  const revocationPath = "src/run/runtime-revocation-write-v04.ts";
  const revocation = text(root, revocationPath);
  requireSnippet(violations, revocationPath, revocation, "new WeakMap<", "revocation-authorization-not-opaque");
  requireSnippet(violations, revocationPath, revocation, "consumeRuntimeClockObservationV04", "revocation-clock-consumption-missing");
  requireSnippet(violations, revocationPath, revocation, "consumeCapturedRevocation(", "revocation-authorization-consumption-missing");
  requireSnippet(violations, revocationPath, revocation, "commitRuntimeRecordFileStoreSessionV04", "revocation-durable-record-commit-missing");
  requireSnippet(violations, revocationPath, revocation, "produceAuthorityRevocationRecordV02", "revocation-record-production-missing");
  requireSnippet(violations, revocationPath, revocation, "continuePendingRuntimeAuthorityRevocationV04", "revocation-fence-continuation-missing");
  requireSnippet(violations, revocationPath, revocation, 'reason: "authority-revoked"', "revocation-fence-reason-missing");
  requireSnippet(violations, revocationPath, revocation, 'classification: "REVOCATION_COMMITTED_FENCE_NOT_COMMITTED"', "revocation-partial-classification-missing");

  for (const [path, label] of [
    ["src/run/runtime-terminal-write-v04.ts", "terminal-write"],
    ["src/run/runtime-compensation-write-v04.ts", "compensation-write"],
  ]) {
    const source = text(root, path);
    requireSnippet(violations, path, source, "isRuntimeTerminalProjectionV04", `${label}-projection-brand-check-missing`);
    requireSnippet(violations, path, source, "evaluateRuntimeTerminalV04", `${label}-evaluator-selection-missing`);
    requireSnippet(violations, path, source, "consumeRuntimeClockObservationV04", `${label}-clock-consumption-missing`);
    requireSnippet(violations, path, source, "commitRuntimeFileStoreSessionV04", `${label}-durable-commit-missing`);
  }

  const terminalPath = "src/run/runtime-terminal-v04.ts";
  const terminal = text(root, terminalPath);
  requireSnippet(violations, terminalPath, terminal, "RuntimeEventSchemaV02.safeParse(candidate)", "terminal-event-projection-validation-missing");
  requireSnippet(violations, terminalPath, terminal, "projectionSources.get(projection)", "terminal-projection-brand-check-missing");
  if (terminal?.includes("as unknown as readonly RuntimeEventV02Value[]")) {
    violations.add(`terminal-cross-family-event-cast:${terminalPath}`);
  }

  const storePath = "src/run/runtime-file-store-v04.ts";
  const store = text(root, storePath);
  for (const snippet of ["O_NOFOLLOW", "O_EXCL", "O_APPEND", "OUTCOME_UNKNOWN", "RUNTIME_FILE_STORE_POISONED"]) {
    requireSnippet(violations, storePath, store, snippet, `file-store-primitive-missing:${snippet}`);
  }

  const directoryPath = "src/run/runtime-directory-v04.ts";
  const directory = text(root, directoryPath);
  requireSnippet(violations, directoryPath, directory, "captured.value.metadata.mode", "directory-actual-mode-missing");
  requireSnippet(violations, directoryPath, directory, "manifestRead.mode !== 384", "directory-manifest-mode-missing");
  requireSnippet(violations, directoryPath, directory, "mode: actualMode", "directory-actual-mode-missing");
  requireSnippet(violations, directoryPath, directory, "mode: memberRead.mode", "directory-actual-mode-missing");

  const recoverCommandPath = "src/commands/run/recover.ts";
  const recoverCommand = text(root, recoverCommandPath);
  for (const forbidden of [
    "__setRunRecoverV04AppendProviderForTest",
    "resumeRuntimeWriteSessionV04",
    "RECOVERY_APPEND_",
    "resume: Flags.boolean",
  ]) {
    if (recoverCommand?.includes(forbidden)) {
      violations.add(`packaged-recover-mutation-surface:${recoverCommandPath}:${forbidden}`);
    }
  }
  requireSnippet(
    violations,
    recoverCommandPath,
    recoverCommand,
    "Packaged S41 remains read-only",
    "packaged-recover-read-only-contract-missing",
  );

  const capturePath = "src/io/runtime-file-capture-v02.ts";
  const capture = text(root, capturePath);
  requireSnippet(violations, capturePath, capture, 'error.code === "ENOENT"', "anchored-not-found-detection-missing");
  requireSnippet(violations, capturePath, capture, 'failure("RUNTIME_FILE_NOT_FOUND")', "anchored-not-found-result-missing");

  const dispatchPath = "src/run/runtime-effect-dispatch-broker-v01.ts";
  const dispatch = text(root, dispatchPath);
  requireSnippet(violations, dispatchPath, dispatch, 'error: "DISPATCH_LEASE_EXPIRED"', "dispatch-expiry-enforcement-missing");
  requireSnippet(violations, dispatchPath, dispatch, "event.sequence > admission.sequence", "dispatch-expiry-clock-order-missing");
  requireSnippet(violations, dispatchPath, dispatch, "observedAt >= expiresAt", "dispatch-expiry-inclusive-boundary-missing");

  const schemaPath = "src/schema/runtime-v04.ts";
  const schema = text(root, schemaPath);
  requireSnippet(violations, schemaPath, schema, 'z.enum(["abort", "quarantine", "reconciliation"])', "reconciliation-termination-trigger-missing");
  const eventTypeStart = schema?.indexOf("export const RuntimeEventTypesV04 = [") ?? -1;
  const eventTypeEnd = eventTypeStart < 0 ? -1 : schema.indexOf("] as const;", eventTypeStart);
  const eventTypeBlock = eventTypeStart < 0 || eventTypeEnd < 0 ? null : schema.slice(eventTypeStart, eventTypeEnd);
  const predecessorSchema = text(root, "src/schema/runtime.ts");
  const predecessorStart = predecessorSchema?.indexOf("export const RuntimeEventTypesV02 = [") ?? -1;
  const predecessorEnd = predecessorStart < 0 ? -1 : predecessorSchema.indexOf("] as const;", predecessorStart);
  const predecessorBlock = predecessorStart < 0 || predecessorEnd < 0
    ? null
    : predecessorSchema.slice(predecessorStart, predecessorEnd);
  const literalCount = (block) => block === null ? 0 : [...block.matchAll(/"[^"]+"/gu)].length;
  const eventTypeCount = literalCount(predecessorBlock) + literalCount(eventTypeBlock);
  if (eventTypeCount !== 59) violations.add(`v04-event-type-count:${schemaPath}:${eventTypeCount}`);
  for (const eventType of [
    "control.pause-requested", "recovery.resume-requested", "execution.attempt-started",
    "ownership.lease-acquired", "ownership.lease-heartbeat-recorded",
    "ownership.lease-released", "run.compaction-recorded",
  ]) {
    requireSnippet(violations, schemaPath, eventTypeBlock, `"${eventType}"`, `v04-event-type-missing:${eventType}`);
  }
  for (const selector of [
    'resolved_run_plan: z.literal("0.3")', 'ledger_event: z.literal("0.4")',
    'run_manifest: z.literal("0.4")', 'summary_artifact: z.literal("0.1")',
  ]) {
    requireSnippet(violations, schemaPath, schema, selector, `v04-inventory-selector-missing:${selector}`);
  }

  const ledgerPath = "src/run/runtime-ledger-v04.ts";
  const ledger = text(root, ledgerPath);
  requireSnippet(violations, ledgerPath, ledger, 'termination.payload.trigger !== "reconciliation"', "reconciliation-termination-binding-missing");
  requireSnippet(violations, ledgerPath, ledger, "termination.payload.trigger_event_ref", "reconciliation-trigger-ref-binding-missing");

  const forbiddenHostImport = /(?:from\s+|import\s+)["'](?:node:)?(?:child_process|net|http|https|http2|tls|dgram|worker_threads)["']/u;
  for (const path of privateFiles) {
    const source = text(root, path);
    if (source !== null && forbiddenHostImport.test(source)) violations.add(`forbidden-s41-host-import:${path}`);
    if (source !== null && /\bprocess\.env\b/u.test(source)) violations.add(`forbidden-s41-ambient-env:${path}`);
    if (source !== null && /(?:^|[^a-z])(?:vps|systemd|systemctl)(?:$|[^a-z])/imu.test(source)) {
      violations.add(`forbidden-s41-host-control:${path}`);
    }
    if (source !== null && /from\s+["'][^"']*(?:tests|ForTest)/u.test(source)) {
      violations.add(`production-test-helper-import:${path}`);
    }
  }

  return Object.freeze({ violations: Object.freeze([...violations].sort()) });
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = runS41RecoveryBoundaryCheck();
  if (result.violations.length > 0) {
    process.stderr.write(`${result.violations.join("\n")}\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write("S41 recovery boundary check passed\n");
  }
}

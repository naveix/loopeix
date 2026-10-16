import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runS41RecoveryBoundaryCheck } from "./check-s41-recovery-boundary.mjs";

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const temporaryRoots = [];

function cloneTree() {
  const root = mkdtempSync(resolve(tmpdir(), "loopeix-s41-boundary-"));
  temporaryRoots.push(root);
  cpSync(resolve(repositoryRoot, "src"), resolve(root, "src"), { recursive: true });
  cpSync(resolve(repositoryRoot, "package.json"), resolve(root, "package.json"));
  return root;
}

function write(root, path, contents) {
  const target = resolve(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, contents);
}

function replace(root, path, before, after) {
  const current = readFileSync(resolve(root, path), "utf8");
  assert.ok(current.includes(before), `mutation precondition missing: ${path}: ${before}`);
  write(root, path, current.replace(before, after));
}

function replaceEvery(root, path, before, after) {
  const current = readFileSync(resolve(root, path), "utf8");
  assert.ok(current.includes(before), `mutation precondition missing: ${path}: ${before}`);
  write(root, path, current.replaceAll(before, after));
}

function append(root, path, contents) {
  write(root, path, `${readFileSync(resolve(root, path), "utf8")}\n${contents}\n`);
}

function expectViolation(name, mutate, expected) {
  const root = cloneTree();
  mutate(root);
  const result = runS41RecoveryBoundaryCheck({ rootDir: root });
  assert.ok(result.violations.some((violation) => violation.includes(expected)),
    `${name}: expected ${expected}; received:\n${result.violations.join("\n")}`);
  process.stderr.write(`s41-boundary-self-test-ok:${name}\n`);
}

try {
  const baseline = runS41RecoveryBoundaryCheck({ rootDir: repositoryRoot });
  assert.deepEqual(baseline.violations, [], `baseline must pass:\n${baseline.violations.join("\n")}`);
  process.stderr.write("s41-boundary-self-test-ok:baseline\n");

  expectViolation("root-export", (root) => append(root, "src/index.ts", 'export * from "./run/runtime-write-session-v04.js";'), "public-root-private-module");
  expectViolation("package-subpath", (root) => {
    const path = resolve(root, "package.json");
    const metadata = JSON.parse(readFileSync(path, "utf8"));
    metadata.exports["./run/runtime-v04"] = "./dist/run/runtime-write-session-v04.js";
    writeFileSync(path, `${JSON.stringify(metadata, null, 2)}\n`);
  }, "public-package-private-subpath");
  expectViolation("authorization-extra-key", (root) => replace(root, "src/run/runtime-recovery-authorization-v04.ts", "  request: RuntimeRecoveryRequestIntentV04,", "  owner_status: z.unknown(),\n  request: RuntimeRecoveryRequestIntentV04,"), "authorization-input-keys");
  expectViolation("authorization-cycle", (root) => append(root, "src/run/runtime-recovery-authorization-v04.ts", 'import "./runtime-recovery-v04.js";'), "authorization-dependency-or-consumption");
  expectViolation("recovery-consumer-removed", (root) => replaceEvery(root, "src/run/runtime-recovery-authorization-v04.ts", "consumeCapturedRuntimeRecoveryRequestV04", "removedCapturedRuntimeRecoveryRequestConsumerV04"), "recovery-authorization-not-one-use");
  expectViolation("raw-advice-removed", (root) => replace(root, "src/run/runtime-recovery-v04.ts", "export function projectRuntimeRecoveryAdviceV04", "function removedRuntimeRecoveryAdviceV04"), "recovery-advice-separation-missing");
  expectViolation("clock-consumer-removed", (root) => replaceEvery(root, "src/run/runtime-clock-observation-v04.ts", "consumeRuntimeClockObservationV04", "removedRuntimeClockObservationConsumerV04"), "runtime-clock-not-one-use");
  expectViolation("pause-consumer-removed", (root) => replaceEvery(root, "src/run/runtime-pause-authorization-v04.ts", "consumeCapturedRuntimePauseRequestV04", "removedCapturedRuntimePauseRequestConsumerV04"), "pause-authorization-not-one-use");
  expectViolation("abort-risk-downgrade", (root) => replace(root, "src/run/runtime-control-write-v04.ts", "RISK_TIER_RANK[proof.approved_risk_tier] < RISK_TIER_RANK.T4", "RISK_TIER_RANK[proof.approved_risk_tier] < RISK_TIER_RANK.T1"), "abort-authorization-risk-floor-missing");
  expectViolation("non-entry-ack-consumer-removed", (root) => replaceEvery(root, "src/run/runtime-non-entry-write-v04.ts", "consumeCapturedRuntimeNonEntryAcknowledgementV04", "removedCapturedRuntimeNonEntryAcknowledgementV04"), "non-entry-ack-consumption-missing");
  expectViolation("revocation-opacity-removed", (root) => replaceEvery(root, "src/run/runtime-revocation-write-v04.ts", "new WeakMap<", "removedWeakMap<"), "revocation-authorization-not-opaque");
  expectViolation("revocation-consumer-removed", (root) => replaceEvery(root, "src/run/runtime-revocation-write-v04.ts", "consumeCapturedRevocation(", "removedCapturedRevocation("), "revocation-authorization-consumption-missing");
  expectViolation("revocation-clock-consumer-removed", (root) => replaceEvery(root, "src/run/runtime-revocation-write-v04.ts", "consumeRuntimeClockObservationV04", "removedRuntimeClockObservationV04"), "revocation-clock-consumption-missing");
  expectViolation("revocation-durable-commit-removed", (root) => replaceEvery(root, "src/run/runtime-revocation-write-v04.ts", "commitRuntimeRecordFileStoreSessionV04", "removedRuntimeRecordFileStoreCommitV04"), "revocation-durable-record-commit-missing");
  expectViolation("revocation-record-producer-removed", (root) => replaceEvery(root, "src/run/runtime-revocation-write-v04.ts", "produceAuthorityRevocationRecordV02", "removedAuthorityRevocationRecordProducerV02"), "revocation-record-production-missing");
  expectViolation("revocation-fence-continuation-removed", (root) => replaceEvery(root, "src/run/runtime-revocation-write-v04.ts", "continuePendingRuntimeAuthorityRevocationV04", "removedPendingRuntimeAuthorityRevocationV04"), "revocation-fence-continuation-missing");
  expectViolation("revocation-fence-reason-removed", (root) => replaceEvery(root, "src/run/runtime-revocation-write-v04.ts", 'reason: "authority-revoked"', 'reason: "pause-request"'), "revocation-fence-reason-missing");
  expectViolation("revocation-partial-classification-removed", (root) => replaceEvery(root, "src/run/runtime-revocation-write-v04.ts", 'classification: "REVOCATION_COMMITTED_FENCE_NOT_COMMITTED"', 'classification: "NOT_COMMITTED"'), "revocation-partial-classification-missing");
  expectViolation("terminal-projection-check-removed", (root) => replaceEvery(root, "src/run/runtime-terminal-write-v04.ts", "isRuntimeTerminalProjectionV04", "removedRuntimeTerminalProjectionCheckV04"), "terminal-write-projection-brand-check-missing");
  expectViolation("compensation-clock-consumer-removed", (root) => replaceEvery(root, "src/run/runtime-compensation-write-v04.ts", "consumeRuntimeClockObservationV04", "removedRuntimeCompensationClockConsumerV04"), "compensation-write-clock-consumption-missing");
  expectViolation("second-commit-removed", (root) => replace(root, "src/run/runtime-write-session-v04.ts", "const requestCommit = await commitRuntimeFileStoreSessionV04(session", "const requestCommit = await removedCommitRuntimeFileStoreSessionV04(session"), "recovery-two-commit-sites");
  expectViolation("risk-downgrade", (root) => replaceEvery(root, "src/run/runtime-write-session-v04.ts", "binding.approved_risk_tier", '"T1"'), "recovery-risk-propagation-missing");
  expectViolation("no-follow-removed", (root) => replaceEvery(root, "src/run/runtime-file-store-v04.ts", "O_NOFOLLOW", "REMOVED_NO_FOLLOW"), "file-store-primitive-missing:O_NOFOLLOW");
  expectViolation("manifest-mode-trust", (root) => replace(root, "src/run/runtime-directory-v04.ts", "mode: actualMode", "mode: row.mode"), "directory-actual-mode-missing");
  expectViolation("packaged-recover-mutation-surface", (root) => append(root, "src/commands/run/recover.ts", "const flags = { resume: Flags.boolean({}) };"), "packaged-recover-mutation-surface");
  expectViolation("packaged-recover-read-only-contract-removed", (root) => replace(root, "src/commands/run/recover.ts", "Packaged S41 remains read-only", "Packaged recovery mutation enabled"), "packaged-recover-read-only-contract-missing");
  expectViolation("not-found-removed", (root) => replace(root, "src/io/runtime-file-capture-v02.ts", 'failure("RUNTIME_FILE_NOT_FOUND")', 'failure("RUNTIME_FILE_CAPTURE_FAILED")'), "anchored-not-found-result-missing");
  expectViolation("dispatch-expiry-removed", (root) => replace(root, "src/run/runtime-effect-dispatch-broker-v01.ts", 'error: "DISPATCH_LEASE_EXPIRED"', 'error: "DISPATCH_NOT_STARTED"'), "dispatch-expiry-enforcement-missing");
  expectViolation("event-family-drift", (root) => replaceEvery(root, "src/schema/runtime-v04.ts", '"run.compaction-recorded"', '"run.compaction-removed"'), "v04-event-type-missing:run.compaction-recorded");
  expectViolation("terminal-event-cast", (root) => append(root, "src/run/runtime-terminal-v04.ts", "const forbidden = [] as unknown as readonly RuntimeEventV02Value[];"), "terminal-cross-family-event-cast");
  expectViolation("reconciliation-trigger-removed", (root) => replace(root, "src/schema/runtime-v04.ts", 'z.enum(["abort", "quarantine", "reconciliation"])', 'z.enum(["abort", "quarantine"])'), "reconciliation-termination-trigger-missing");
  expectViolation("host-import", (root) => append(root, "src/run/runtime-recovery-v04.ts", 'import "node:child_process";'), "forbidden-s41-host-import");

  process.stdout.write("S41 recovery boundary self-test completed: 32/32 cases passed\n");
} finally {
  for (const root of temporaryRoots) rmSync(root, { recursive: true, force: true });
}

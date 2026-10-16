import { Args, Command, Flags } from "@oclif/core";
import { join, resolve } from "node:path";
import { planRunFromCompilePack, type PlanEngine, type PlanRunResult } from "../../run/plan.js";
import { readCompilePackV02 } from "../../compiler/read-pack-v02.js";
import { replayCompilePackV02 } from "../../compiler/replay-v02.js";
import {
  resolveVerifiedCompileStoreV02,
  verifyCompileStoreV02,
} from "../../compiler/compile-store.js";
import {
  captureOutputBytes,
  confirmV02PlanProjection,
  createV02PlannedRunWriteAuthority,
  openV02OutputAdmissionSession,
  prepareV02PlannedRunsRoot,
  scanAndAdmitOutputBytes,
  sealV02OutputAdmissionSession,
  writeV02PlannedRunOutputs,
  parseDirectChildName,
} from "../../io/output-capabilities.js";
import {
  captureStructuredFile,
  releaseCapturedStructuredFile,
} from "../../io/captured-file.js";
import {
  admitAuthorityPlanningInputV02,
  claimApprovedAuthorityRepositoryV02,
} from "../../run/authority-planning-input-v02.js";
import {
  consumePreparedPlanProjectionV02,
  preflightPlannedRunV02,
  projectPreflightedRunV02,
  type PlanProjectionResult,
} from "../../run/project-plan-v02.js";
import { allocateAndCommitPlanIdentityV02 } from "../../run/plan-id-v02.js";
import {
  deriveInvocationRepositoryRootV02,
  observeCleanRepositoryStateV02,
} from "../../run/repository-observation-v02.js";

export type V02PlanFailure = {
  ok: false;
  disposition: "hold";
  schema_version: "0.2";
  terminal_state: null;
  run_id: null;
  resolved_run_plan_hash: null;
  run_ref: null;
  reason:
    | "INVALID_AUTHORITY_PLANNING_INPUT"
    | "AUTHORITY_PLANNING_APPROVAL_MISMATCH"
    | "PLAN_BINDING_MISMATCH"
    | "PLAN_ID_COLLISION_LIMIT"
    | "DESTINATION_EXISTS"
    | "INVALID_OUTPUT_CAPTURE"
    | "OUTPUT_CAPTURE_FAILED"
    | "OUTPUT_SCAN_FAILED"
    | "OUTPUT_HASH_FAILED"
    | "SENSITIVE_OUTPUT_REJECTED"
    | "IO_DURABILITY_UNCONFIRMED"
    | "IO_HELPER_UNAVAILABLE"
    | "IO_IDENTITY_MISMATCH";
  findings: [];
  member_id?: string;
  rule_id?: string;
};

function planFailure(
  reason: V02PlanFailure["reason"],
  detail: Readonly<{ member_id: string; rule_id: string }> | null = null,
): V02PlanFailure {
  return {
    ok: false,
    disposition: "hold",
    schema_version: "0.2",
    terminal_state: null,
    run_id: null,
    resolved_run_plan_hash: null,
    run_ref: null,
    reason,
    findings: [],
    ...(detail ?? {}),
  };
}

function planFailureExit(reason: V02PlanFailure["reason"]): 1 | 4 {
  return new Set<V02PlanFailure["reason"]>([
    "INVALID_AUTHORITY_PLANNING_INPUT",
    "AUTHORITY_PLANNING_APPROVAL_MISMATCH",
    "PLAN_BINDING_MISMATCH",
    "PLAN_ID_COLLISION_LIMIT",
    "DESTINATION_EXISTS",
  ]).has(reason) ? 1 : 4;
}

export type RunPlanCommandResult = PlanRunResult | PlanProjectionResult | V02PlanFailure;

export default class RunPlan extends Command {
  static summary = "Validate a compiled pack and create a resolved run plan when its authority context is available.";
  static description =
    "Consumes a compiled pack and writes a planned run directory only after all required authority inputs are available and validated. Otherwise it returns HOLD without allocating a run identity or writing output.";
  static args = {
    pack: Args.string({ description: "compile pack directory", required: true }),
  };
  static flags = {
    engine: Flags.string({ options: ["codex", "claude"], required: true, description: "engine adapter to plan for" }),
    "approve-compiled-pack": Flags.boolean({
      description: "confirm the compiled pack was reviewed and approved for planning",
      default: false,
    }),
    "workspace-root": Flags.string({
      description: "approved workspace root (run dir = <workspace-root>/.loopeix/loops/<family>/runs/<run-id>)",
      default: process.cwd(),
    }),
    "authority-input": Flags.string({ description: "strict V02 authority-planning input JSON" }),
    "approve-authority-hash": Flags.string({ description: "acknowledge the exact authority-planning approval hash" }),
  };
  static examples = [
    "<%= config.bin %> run plan .loopeix/compiles/date-parser --engine codex --workspace-root .",
  ];
  static enableJsonFlag = true;

  public async run(): Promise<RunPlanCommandResult> {
    const { args, flags } = await this.parse(RunPlan);
    const workspaceRoot = resolve(flags["workspace-root"]);
    const directPackName = parseDirectChildName(args.pack);
    const store = directPackName === null ? null : await verifyCompileStoreV02(workspaceRoot);
    const storeState = store?.ok ? resolveVerifiedCompileStoreV02(store.store) : null;
    const v02PackPath = directPackName === null || storeState === null
      ? null
      : join(storeState.path, directPackName);
    const v02Read = v02PackPath === null ? null : await readCompilePackV02(v02PackPath);

    if (v02Read?.ok) {
      if (!flags["approve-compiled-pack"]) {
        this.error("--approve-compiled-pack is required for a confirmed V02 pack", { exit: 2 });
      }
      if (flags["authority-input"] === undefined || flags["approve-authority-hash"] === undefined) {
        this.error("confirmed V02 planning requires --authority-input and --approve-authority-hash", { exit: 2 });
      }
      const replayed = replayCompilePackV02(v02Read);
      if (!replayed.ok) {
        const result: PlanProjectionResult = {
          ok: false,
          disposition: "hold",
          schema_version: "0.2",
          terminal_state: null,
          run_id: null,
          resolved_run_plan_hash: null,
          run_ref: null,
          reason: "INVALID_COMPILE_PACK",
          findings: [],
        };
        process.exitCode = 4;
        return result;
      }
      const captured = await captureStructuredFile(resolve(flags["authority-input"]), {
        mode: "operator-approved-finite",
        max_member_bytes: 4_194_304,
        max_total_bytes: 4_194_304,
        max_heap_bytes: 67_108_864,
        max_elapsed_ms: 30_000,
        approved_by: "operator",
      });
      if (!captured.ok) {
        const result = planFailure(captured.reason === "IO_IDENTITY_MISMATCH" || captured.reason === "INVALID_INPUT_FILE"
          ? "IO_IDENTITY_MISMATCH"
          : "IO_HELPER_UNAVAILABLE");
        process.exitCode = 4;
        return result;
      }
      const snapshot = await captured.capture.snapshotBytes();
      const released = await releaseCapturedStructuredFile(captured.capture);
      if (!snapshot.ok || !released.ok) {
        const result = planFailure("IO_HELPER_UNAVAILABLE");
        process.exitCode = 4;
        return result;
      }
      const admitted = admitAuthorityPlanningInputV02(snapshot.bytes, flags["approve-authority-hash"]);
      if (!admitted.ok) {
        const result = planFailure(admitted.reason);
        if (!this.jsonEnabled()) this.log(`HOLD  ${result.reason}`);
        process.exitCode = 1;
        return result;
      }
      let observation;
      let canonicalWorkspaceRoot = workspaceRoot;
      if (replayed.replay.terminal_state === "compiled") {
        const repository = claimApprovedAuthorityRepositoryV02(admitted.approved);
        const invocationRoot = deriveInvocationRepositoryRootV02(workspaceRoot);
        if (!invocationRoot.ok || repository === null
          || repository.repository_root_ref !== invocationRoot.repository_root_ref) {
          const result = planFailure("INVALID_AUTHORITY_PLANNING_INPUT");
          process.exitCode = 1;
          return result;
        }
        canonicalWorkspaceRoot = invocationRoot.canonical_root;
        const observed = repository === null
          ? null
          : observeCleanRepositoryStateV02(canonicalWorkspaceRoot, repository);
        if (observed === null || !observed.ok) {
          const result = planFailure(observed?.reason === "IO_HELPER_UNAVAILABLE" ? "IO_HELPER_UNAVAILABLE" : "INVALID_AUTHORITY_PLANNING_INPUT");
          process.exitCode = planFailureExit(result.reason);
          return result;
        }
        observation = observed.observation;
      }
      const preflight = preflightPlannedRunV02(
        replayed.replay,
        admitted.approved,
        observation,
        { engine: flags.engine as "codex" | "claude", workspace_root: canonicalWorkspaceRoot },
      );
      if (!preflight.ok) {
        if (!this.jsonEnabled()) this.log(`HOLD  ${preflight.reason}`);
        process.exitCode = preflight.reason === "INVALID_V02_PROJECTION" || preflight.reason === "INVALID_COMPILE_PACK" ? 4 : 1;
        return preflight;
      }
      const preparedRoot = await prepareV02PlannedRunsRoot(canonicalWorkspaceRoot, preflight.loop_family);
      if (!preparedRoot.ok) {
        const result = planFailure(preparedRoot.reason === "IO_DURABILITY_UNCONFIRMED"
          ? preparedRoot.reason
          : "IO_IDENTITY_MISMATCH");
        process.exitCode = planFailureExit(result.reason);
        return result;
      }

      let sensitiveDetail: Readonly<{ member_id: string; rule_id: string }> | null = null;
      const committed: { value: Extract<PlanProjectionResult, { ok: true }> | null } = { value: null };
      const allocated = await allocateAndCommitPlanIdentityV02({
        commitCandidate: async (identity) => {
          const projected = projectPreflightedRunV02(preflight.preflight, identity);
          if (!projected.ok) {
            return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The planned-run projection is invalid." };
          }
          const projectionSnapshot = consumePreparedPlanProjectionV02(projected.prepared);
          if (projectionSnapshot === null) {
            return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The planned-run projection is invalid." };
          }
          const confirmed = confirmV02PlanProjection(projectionSnapshot.output_descriptor);
          if (!confirmed.ok) return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: confirmed.message };
          const opened = openV02OutputAdmissionSession(confirmed.projection, "planned-run");
          if (!opened.ok) return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: opened.message };
          for (const name of opened.session.allowed_members) {
            const member = projectionSnapshot.members.find((candidate) => candidate.name === name);
            if (member === undefined) {
              return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The planned-run output inventory is incomplete." };
            }
            const capturedMember = captureOutputBytes(opened.session, name, member.bytes);
            if (!capturedMember.ok) {
              return {
                ok: false,
                reason: capturedMember.reason === "OUTPUT_CAPTURE_FAILED" ? capturedMember.reason : "INVALID_OUTPUT_CAPTURE",
                message: capturedMember.message,
              };
            }
            const output = scanAndAdmitOutputBytes(capturedMember.capture);
            if (!output.ok) {
              if (output.reason === "SENSITIVE_OUTPUT_REJECTED") {
                sensitiveDetail = { member_id: output.member_id, rule_id: output.rule_id };
                return { ok: false, reason: output.reason, message: "Sensitive generated output was rejected." };
              }
              return {
                ok: false,
                reason: output.reason === "COMPILED_OUTPUT_TOO_LARGE" ? "INVALID_OUTPUT_CAPTURE" : output.reason,
                message: output.message,
              };
            }
          }
          const sealed = sealV02OutputAdmissionSession(opened.session);
          if (!sealed.ok) return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: sealed.message };
          const authority = createV02PlannedRunWriteAuthority(
            confirmed.projection,
            preparedRoot.root,
            sealed.output_set,
          );
          if (!authority.ok || authority.authority.purpose !== "planned-run") {
            return {
              ok: false,
              reason: authority.ok || authority.reason !== "INVALID_INPUT_ROOT" ? "INVALID_OUTPUT_CAPTURE" : "IO_IDENTITY_MISMATCH",
              message: authority.ok ? "The planned-run authority is invalid." : authority.message,
            };
          }
          const written = await writeV02PlannedRunOutputs(authority.authority);
          if (!written.ok) return { ok: false, reason: written.reason, message: written.message };
          committed.value = {
            ok: true,
            disposition: "planned",
            schema_version: "0.2",
            run_id: written.run_id,
            resolved_run_plan_hash: written.resolved_run_plan_hash,
            run_ref: written.run_ref,
            reason: null,
            findings: [],
          };
          return { ok: true, run_id: written.run_id };
        },
      });
      if (!allocated.ok || committed.value === null) {
        const reason = allocated.ok ? "INVALID_OUTPUT_CAPTURE" : allocated.reason;
        const result = planFailure(reason, reason === "SENSITIVE_OUTPUT_REJECTED" ? sensitiveDetail : null);
        if (!this.jsonEnabled()) this.log(`HOLD  ${result.reason}`);
        process.exitCode = planFailureExit(result.reason);
        return result;
      }
      if (!this.jsonEnabled()) {
        this.log(`PLANNED  ${committed.value.run_id}`);
        this.log(`Run ref: ${committed.value.run_ref}`);
        this.log(`Resolved plan hash: ${committed.value.resolved_run_plan_hash}`);
      }
      process.exitCode = 0;
      return committed.value;
    }

    if (flags["authority-input"] !== undefined || flags["approve-authority-hash"] !== undefined) {
      this.error("authority-planning flags are valid only for a confirmed V02 pack", { exit: 2 });
    }
    const result = planRunFromCompilePack({
      packDir: args.pack,
      workspaceRoot,
      engine: flags.engine as PlanEngine,
      approved: flags["approve-compiled-pack"],
    });

    if (!this.jsonEnabled()) {
      if (result.ok) {
        this.log(`PLANNED  ${result.run_id}`);
        this.log(`Run dir: ${result.run_dir}`);
        this.log(`Resolved plan: ${result.paths?.resolved_run_plan}`);
      } else {
        this.log(`HOLD  ${result.terminal_state}`);
        if (result.message !== undefined) this.log(`  - ${result.message}`);
      }
    }

    if (!result.ok) process.exitCode = 1;
    return result;
  }
}

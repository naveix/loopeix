import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { compileV02ForTest } from "../../src/compiler/compile-v02.js";
import { COMPILE_STORE_SENTINEL_TEXT } from "../../src/compiler/compile-store.js";
import { readCompilePackV02 } from "../../src/compiler/read-pack-v02.js";
import { replayCompilePackV02 } from "../../src/compiler/replay-v02.js";
import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import { admitAuthorityPlanningInputV02 } from "../../src/run/authority-planning-input-v02.js";
import { projectPlannedRunV02 } from "../../src/run/project-plan-v02.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("S35 cross-lane compiler-to-planner projection", () => {
  it("preserves captured identity through exact replay and propagates compiler HOLD without allocating a run", async () => {
    const workspace = mkdtempSync(join(tmpdir(), "loopeix-s35-cross-lane-"));
    roots.push(workspace);
    const store = join(workspace, ".loopeix", "compiles");
    mkdirSync(store, { recursive: true });
    writeFileSync(join(store, ".gitignore"), COMPILE_STORE_SENTINEL_TEXT, { mode: 0o600 });
    const compiled = await compileV02ForTest({
      prompt: "Fix the parser and prove the correction.",
      workspace_root: workspace,
    }, {
      now: () => 501,
      randomBytes: () => Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]),
    });
    expect(compiled).toMatchObject({
      ok: false,
      disposition: "hold",
      reason: "PROJECT_BINDING_REQUIRED",
    });
    if (compiled.pack_ref === null) throw new Error("expected contracted HOLD pack");
    const packRoot = join(store, compiled.pack_ref);
    const read = await readCompilePackV02(packRoot);
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    const replayed = replayCompilePackV02(read);
    expect(replayed.ok).toBe(true);
    if (!replayed.ok) return;

    const repository = {
      repository_root_ref: "repository_cross_lane_01",
      object_format: "sha1" as const,
      base_ref: {
        kind: "git-ref" as const,
        canonical_ref_name: "refs/heads/main",
        object_id: { algorithm: "sha1" as const, value: "a".repeat(40) },
        identity_hash: "",
      },
      transition_mode: "read-only" as const,
    };
    repository.base_ref.identity_hash = hashCanonical({
      purpose: "repository-base-ref-v02",
      repository_root_ref: repository.repository_root_ref,
      object_format: repository.object_format,
      kind: repository.base_ref.kind,
      canonical_ref_name: repository.base_ref.canonical_ref_name,
      object_id: repository.base_ref.object_id,
    });
    const input = {
      schema_version: "0.2" as const,
      authority_planning_input_id: "authority_cross_lane_01",
      compile_pack_manifest_hash: hashRawBytes(readFileSync(join(packRoot, "pack-manifest.json"))),
      forbidden_outcomes: ["data loss"],
      delegation_mode: "none" as const,
      role_assignments: [{
        role_ref: "operator",
        actor_ref: "operator_cross_lane_01",
        actor_kind: "operator" as const,
        stable_identity_hash: `sha256:${"b".repeat(64)}`,
      }],
      human_exception_destination: {
        operator_role_ref: "operator",
        operator_actor_ref: "operator_cross_lane_01",
        operator_stable_identity_hash: `sha256:${"b".repeat(64)}`,
      },
      repository,
      policy_digest: `sha256:${"c".repeat(64)}`,
      approval_hash: "",
    };
    input.approval_hash = hashCanonical({
      purpose: "authority-planning-input-v02",
      schema_version: input.schema_version,
      authority_planning_input_id: input.authority_planning_input_id,
      compile_pack_manifest_hash: input.compile_pack_manifest_hash,
      forbidden_outcomes: input.forbidden_outcomes,
      delegation_mode: input.delegation_mode,
      role_assignments: input.role_assignments,
      human_exception_destination: input.human_exception_destination,
      repository: input.repository,
      policy_digest: input.policy_digest,
    });
    const authority = admitAuthorityPlanningInputV02(
      Buffer.from(JSON.stringify(input)),
      input.approval_hash,
    );
    expect(authority.ok).toBe(true);
    if (!authority.ok) return;
    expect(projectPlannedRunV02(replayed.replay, authority.approved)).toEqual({
      ok: false,
      disposition: "hold",
      schema_version: "0.2",
      terminal_state: "hold-project-binding-required",
      run_id: null,
      resolved_run_plan_hash: null,
      run_ref: null,
      reason: "PROJECT_BINDING_REQUIRED",
      findings: [],
    });
  });
});

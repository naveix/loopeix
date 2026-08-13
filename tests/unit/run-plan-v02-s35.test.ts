import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  read: { ok: true, manifest: { terminal_state: "compiled" } } as unknown,
  admission: { ok: true, approved: Object.freeze({ approval_hash: `sha256:${"1".repeat(64)}` }) } as unknown,
  projection: {
    ok: false, disposition: "hold", schema_version: "0.2", terminal_state: null,
    run_id: null, resolved_run_plan_hash: null, run_ref: null,
    reason: "INVALID_V02_PROJECTION", findings: [],
  } as unknown,
}));

const outputState = vi.hoisted(() => ({
  written: {
    ok: true as const,
    run_id: "run_test_0011223344556677",
    resolved_run_plan_hash: `sha256:${"9".repeat(64)}`,
    run_ref: ".loopeix/loops/minimal-loop/runs/run_test_0011223344556677",
  },
}));

vi.mock("../../src/compiler/compile-store.js", () => ({
  verifyCompileStoreV02: vi.fn(async () => ({ ok: true, store: Object.freeze({}) })),
  resolveVerifiedCompileStoreV02: vi.fn(() => ({ path: "/captured/compile-store", device: "1", inode: "2" })),
}));

vi.mock("../../src/compiler/read-pack-v02.js", () => ({
  readCompilePackV02: vi.fn(async () => state.read),
}));

vi.mock("../../src/compiler/replay-v02.js", () => ({
  replayCompilePackV02: vi.fn(() => ({ ok: true, disposition: "replayed", replay: Object.freeze({}), reason: null, findings: [] })),
}));

vi.mock("../../src/io/captured-file.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/io/captured-file.js")>();
  return {
    ...actual,
    captureStructuredFile: vi.fn(async () => ({
      ok: true,
      capture: { snapshotBytes: vi.fn(async () => ({ ok: true, bytes: new Uint8Array([123, 125]) })) },
    })),
    releaseCapturedStructuredFile: vi.fn(async () => ({ ok: true })),
  };
});

vi.mock("../../src/io/output-capabilities.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/io/output-capabilities.js")>();
  return {
    ...actual,
    prepareV02PlannedRunsRoot: vi.fn(async () => ({ ok: true, root: Object.freeze({}) })),
    confirmV02PlanProjection: vi.fn(() => ({ ok: true, projection: Object.freeze({}) })),
    openV02OutputAdmissionSession: vi.fn(() => ({
      ok: true,
      session: Object.freeze({ allowed_members: ["resolved-run-plan.json"] }),
    })),
    captureOutputBytes: vi.fn(() => ({ ok: true, capture: Object.freeze({}) })),
    scanAndAdmitOutputBytes: vi.fn(() => ({ ok: true, output: Object.freeze({}) })),
    sealV02OutputAdmissionSession: vi.fn(() => ({ ok: true, output_set: Object.freeze({}) })),
    createV02PlannedRunWriteAuthority: vi.fn(() => ({
      ok: true,
      authority: Object.freeze({ purpose: "planned-run" }),
    })),
    writeV02PlannedRunOutputs: vi.fn(async () => outputState.written),
  };
});

vi.mock("../../src/run/authority-planning-input-v02.js", () => ({
  admitAuthorityPlanningInputV02: vi.fn(() => state.admission),
  claimApprovedAuthorityRepositoryV02: vi.fn(() => ({ repository_root_ref: "repository_test_01" })),
}));

vi.mock("../../src/run/repository-observation-v02.js", () => ({
  deriveInvocationRepositoryRootV02: vi.fn((root: string) => ({
    ok: true,
    canonical_root: root,
    repository_root_ref: "repository_test_01",
  })),
  observeCleanRepositoryStateV02: vi.fn(() => ({
    ok: true,
    observation: Object.freeze({ repository_state_hash: `sha256:${"3".repeat(64)}` }),
  })),
}));

vi.mock("../../src/run/project-plan-v02.js", () => ({
  projectPlannedRunV02: vi.fn(() => state.projection),
  preflightPlannedRunV02: vi.fn(() => state.projection),
  projectPreflightedRunV02: vi.fn((_preflight, identity) => {
    outputState.written.run_id = identity.run_id;
    outputState.written.run_ref = `.loopeix/loops/minimal-loop/runs/${identity.run_id}`;
    return {
      ok: true, disposition: "prepared", schema_version: "0.2",
      run_id: identity.run_id, prepared: Object.freeze({}), reason: null, findings: [],
    };
  }),
  consumePreparedPlanProjectionV02: vi.fn(() => ({
    intake_brief: {}, resolved_run_plan: {},
    output_descriptor: {
      kind: "plan", schema_version: "0.2", source_pack_root_hash: `sha256:${"8".repeat(64)}`,
      run_id: "run_test_0011223344556677", output_budget_bytes: 33_554_432,
      loop_family: "minimal-loop", workspace_root_hash: `sha256:${"7".repeat(64)}`, engine: "codex",
    },
    members: [{ name: "resolved-run-plan.json", bytes: new Uint8Array([123, 125, 10]) }],
  })),
}));

import RunPlan, { type RunPlanCommandResult } from "../../src/commands/run/plan.js";
import { captureStructuredFile } from "../../src/io/captured-file.js";
import { writeV02PlannedRunOutputs } from "../../src/io/output-capabilities.js";
import { preflightPlannedRunV02 } from "../../src/run/project-plan-v02.js";

const repoRoot = join(import.meta.dirname, "..", "..");
const roots: string[] = [];

afterEach(() => {
  vi.clearAllMocks();
  state.read = { ok: true, manifest: { terminal_state: "compiled" } };
  state.admission = { ok: true, approved: Object.freeze({ approval_hash: `sha256:${"1".repeat(64)}` }) };
  state.projection = {
    ok: false, disposition: "hold", schema_version: "0.2", terminal_state: null,
    run_id: null, resolved_run_plan_hash: null, run_ref: null,
    reason: "INVALID_V02_PROJECTION", findings: [],
  };
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function workspace(): string {
  const value = mkdtempSync(join(tmpdir(), "loopeix-run-plan-v02-")); roots.push(value); return value;
}

async function run(argv: string[]): Promise<{ result: RunPlanCommandResult; exit: number }> {
  const previous = process.exitCode; process.exitCode = 0;
  const log = vi.spyOn(RunPlan.prototype, "log").mockImplementation(() => {});
  const logJson = vi.spyOn(RunPlan.prototype as never, "logJson" as never).mockImplementation((() => {}) as never);
  try {
    const result = await RunPlan.run(argv, repoRoot) as RunPlanCommandResult;
    return { result, exit: Number(process.exitCode ?? 0) };
  } finally { log.mockRestore(); logJson.mockRestore(); process.exitCode = previous; }
}

describe("S35 V02 run plan boundary", () => {
  it("requires both authority arguments only after confirmed V02 selection", async () => {
    const root = workspace();
    await expect(RunPlan.run([
      "compile_test_0011223344556677", "--engine", "codex", "--approve-compiled-pack", "--workspace-root", root,
    ], repoRoot)).rejects.toThrow(/requires --authority-input and --approve-authority-hash/u);
    expect(captureStructuredFile).not.toHaveBeenCalled();
    expect(readdirSync(root)).toEqual([]);
  });

  it("propagates authority approval mismatch with null identity fields and no writes", async () => {
    const root = workspace();
    state.admission = { ok: false, reason: "AUTHORITY_PLANNING_APPROVAL_MISMATCH", message: "mismatch" };
    const output = await run([
      "compile_test_0011223344556677", "--engine", "codex", "--approve-compiled-pack",
      "--workspace-root", root, "--authority-input", join(root, "authority.json"),
      "--approve-authority-hash", `sha256:${"2".repeat(64)}`,
    ]);
    expect(output).toMatchObject({
      exit: 1,
      result: { reason: "AUTHORITY_PLANNING_APPROVAL_MISMATCH", run_id: null, resolved_run_plan_hash: null, run_ref: null },
    });
    expect(preflightPlannedRunV02).not.toHaveBeenCalled();
    expect(readdirSync(root)).toEqual([]);
  });

  it("forwards genuine admitted handles and remains fail-closed before plan identity", async () => {
    const root = workspace();
    const output = await run([
      "compile_test_0011223344556677", "--engine", "claude", "--approve-compiled-pack",
      "--workspace-root", root, "--authority-input", join(root, "authority.json"),
      "--approve-authority-hash", `sha256:${"1".repeat(64)}`,
    ]);
    expect(output).toMatchObject({
      exit: 4,
      result: { reason: "INVALID_V02_PROJECTION", run_id: null, resolved_run_plan_hash: null, run_ref: null },
    });
    expect(preflightPlannedRunV02).toHaveBeenCalledOnce();
    expect(readdirSync(root)).toEqual([]);
  });

  it("rejects authority flags for a non-V02 pack before the legacy planner", async () => {
    state.read = { ok: false, reason: "INVALID_COMPILE_PACK", message: "not V02" };
    await expect(RunPlan.run([
      "legacy-pack", "--engine", "codex", "--approve-compiled-pack", "--workspace-root", workspace(),
      "--authority-input", "authority.json", "--approve-authority-hash", `sha256:${"1".repeat(64)}`,
    ], repoRoot)).rejects.toThrow(/valid only for a confirmed V02 pack/u);
    expect(captureStructuredFile).not.toHaveBeenCalled();
  });

  it("commits a preflighted candidate and exposes only writer-derived success identity", async () => {
    const root = workspace();
    state.projection = {
      ok: true, disposition: "preflighted", schema_version: "0.2", loop_family: "minimal-loop",
      preflight: Object.freeze({ loop_family: "minimal-loop" }), reason: null, findings: [],
    };
    const output = await run([
      "compile_test_0011223344556677", "--engine", "codex", "--approve-compiled-pack",
      "--workspace-root", root, "--authority-input", join(root, "authority.json"),
      "--approve-authority-hash", `sha256:${"1".repeat(64)}`,
    ]);
    expect(output).toEqual({ exit: 0, result: {
      ok: true, disposition: "planned", schema_version: "0.2",
      run_id: outputState.written.run_id,
      resolved_run_plan_hash: outputState.written.resolved_run_plan_hash,
      run_ref: outputState.written.run_ref,
      reason: null, findings: [],
    } });
    expect(writeV02PlannedRunOutputs).toHaveBeenCalledOnce();
  });
});

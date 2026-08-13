import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { hashRawBytes } from "../../src/hash.js";

const state = vi.hoisted(() => ({ consumed: null as unknown }));

vi.mock("../../src/run/capture-planned-v02.js", () => ({
  capturePlannedRunV02: vi.fn(async () => ({ ok: true, captured: Object.freeze({ run_id: "run_report_01" }) })),
  consumeCapturedPlannedRunV02: vi.fn(() => state.consumed),
}));

vi.mock("../../src/run/present-planned-v02.js", () => ({
  presentPlannedRunV02: vi.fn(() => ({
    controls: [
      { category: "goal", control_ref: "goal", label: "Goal", value: '{"statement":"Ship safely"}' },
      { category: "proof-boundary", control_ref: "authority-subject", label: "Authority", value: '{"policy_digest":"sha256:test"}' },
    ],
  })),
}));

import { buildPlanReportV02ForTest } from "../../src/report/build-plan-v02.js";
import { parsePlanReportInputV02 } from "../../src/report/plan-input.js";

const roots: string[] = [];
const rendererBundle = {
  renderer_bundle_id: `renderer_${"1".repeat(32)}`,
  renderer_bundle_hash: `sha256:${"2".repeat(64)}`,
};

function bytes(text: string): Uint8Array { return new TextEncoder().encode(text); }

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "loopeix-report-plan-v02-"));
  roots.push(value);
  chmodSync(value, 0o700);
  const planBytes = bytes('{"schema_version":"0.2"}\n');
  const manifestBytes = bytes('{"schema_version":"0.2","kind":"manifest"}\n');
  const generatedBytes = bytes("schema_version: '0.2'\n");
  state.consumed = {
    plan: {
      run_id: "run_report_01",
      compile_pack_manifest_hash: hashRawBytes(manifestBytes),
    },
    member_bytes: new Map([
      ["resolved-run-plan.json", planBytes],
      ["compile-pack-manifest.json", manifestBytes],
      ["generated.loop.yaml", generatedBytes],
    ]),
  };
  return value;
}

afterEach(() => {
  vi.clearAllMocks();
  for (const value of roots.splice(0)) rmSync(value, { recursive: true, force: true });
});

describe("S35 V02 planned-report producer", () => {
  it("rejects an invalid installed renderer before lock or output creation", async () => {
    const directory = root();
    await expect(buildPlanReportV02ForTest(directory, null)).resolves.toMatchObject({
      ok: false,
      reason: "PLAN_REPORT_RENDERER_INVALID",
    });
    expect(readdirSync(directory)).toEqual([]);
  });

  it("writes Markdown, HTML, then the strict input commit marker through the atomic writer", async () => {
    const directory = root();
    const result = await buildPlanReportV02ForTest(directory, rendererBundle);
    expect(result).toMatchObject({ ok: true, reason: null, run_id: "run_report_01" });
    expect(readdirSync(directory).sort()).toEqual(["plan-report-input.json", "plan-report.html", "plan-report.md"]);
    expect(existsSync(join(directory, "plan-report.lock"))).toBe(false);
    const markdown = readFileSync(join(directory, "plan-report.md"), "utf8");
    const html = readFileSync(join(directory, "plan-report.html"), "utf8");
    const input = JSON.parse(readFileSync(join(directory, "plan-report-input.json"), "utf8")) as Record<string, unknown>;
    expect(markdown).toContain("NOT EXECUTED");
    expect(markdown).toContain("NOT ENFORCED");
    expect(html).toContain("UNSUPPORTED_EXECUTION_PROFILE");
    expect(input.markdown_hash).toBe(hashRawBytes(bytes(markdown)));
    expect(input.html_hash).toBe(hashRawBytes(bytes(html)));
    expect(parsePlanReportInputV02(input).ok).toBe(true);
  });

  it("replaces an existing complete report set and preserves malformed lock custody", async () => {
    const directory = root();
    for (const name of ["plan-report.md", "plan-report.html", "plan-report-input.json"]) {
      writeFileSync(join(directory, name), "stale", { mode: 0o600 });
    }
    expect((await buildPlanReportV02ForTest(directory, rendererBundle)).ok).toBe(true);
    writeFileSync(join(directory, "plan-report.lock"), "busy", { mode: 0o600 });
    await expect(buildPlanReportV02ForTest(directory, rendererBundle)).resolves.toMatchObject({
      ok: false,
      reason: "REPORT_BUILD_STALE_LOCK",
    });
    expect(readFileSync(join(directory, "plan-report.lock"), "utf8")).toBe("busy");
    expect(readdirSync(directory).sort()).toEqual([
      "plan-report-input.json", "plan-report.html", "plan-report.lock", "plan-report.md",
    ]);
  });

  it("recovers an unchanged complete generation from a strict dead-owner lock", async () => {
    const directory = root();
    const built = await buildPlanReportV02ForTest(directory, rendererBundle);
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const names = ["plan-report.md", "plan-report.html", "plan-report-input.json"] as const;
    const original = new Map(names.map((name) => [name, readFileSync(join(directory, name))]));
    const input = JSON.parse(original.get("plan-report-input.json")!.toString("utf8")) as Record<string, string>;
    const members = names.map((name) => ({ name, hash: hashRawBytes(original.get(name)!) }));
    const entropy = "a".repeat(32);
    writeFileSync(join(directory, "plan-report.lock"), `${JSON.stringify({
      version: "0.1",
      invocation_id: `prw_${entropy}`,
      pid: 2_147_483_647,
      process_start_identity: "dead-owner-start",
      started_at: "2026-08-12T10:00:00.000Z",
      source: {
        run_id: "run_report_01",
        resolved_run_plan_hash: input.resolved_run_plan_hash,
        compile_pack_manifest_hash: input.compile_pack_manifest_hash,
        generated_loop_hash: input.generated_loop_hash,
        report_projection_version: "0.1",
        renderer_bundle_id: rendererBundle.renderer_bundle_id,
        renderer_bundle_hash: rendererBundle.renderer_bundle_hash,
      },
      committed_before: members,
      target: { generation_id: built.generation_id, members },
      temp_names: names.map((name) => `${name}.${entropy}.tmp`),
    })}\n`, { mode: 0o600 });

    const kill = vi.spyOn(process, "kill").mockImplementation(((pid: number) => {
      if (pid === 2_147_483_647) throw Object.assign(new Error("no such process"), { code: "ESRCH" });
      return true;
    }) as typeof process.kill);
    try {
      await expect(buildPlanReportV02ForTest(directory, rendererBundle)).resolves.toMatchObject({ ok: true });
    } finally {
      kill.mockRestore();
    }
    expect(existsSync(join(directory, "plan-report.lock"))).toBe(false);
    for (const name of names) expect(readFileSync(join(directory, name))).toEqual(original.get(name));
  });
});

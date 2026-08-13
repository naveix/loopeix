import { chmodSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { capturePlannedRunV02, consumeCapturedPlannedRunV02 } from "../../src/run/capture-planned-v02.js";

const roots: string[] = [];
const CORE = [
  "work-item.json", "binding-input.json", "intake-record.json", "catalog-resolution.json",
  "compilation-record.json", "compile-pack-manifest.json", "generated.loop.yaml",
  "intake-brief.json", "resolved-run-plan.json",
] as const;

function rootWithPlan(plan: unknown, extra: readonly string[] = []): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-captured-plan-v02-")));
  roots.push(root);
  for (const name of [...CORE, ...extra]) {
    writeFileSync(join(root, name), name === "resolved-run-plan.json" ? JSON.stringify(plan) : "{}", { mode: 0o600 });
    chmodSync(join(root, name), 0o600);
  }
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("S35 shared V02 planned-run capture", () => {
  it("excludes V01 before V02 directory classification", async () => {
    await expect(capturePlannedRunV02(rootWithPlan({ schema_version: "0.1" }, ["unexpected.txt"]))).resolves.toMatchObject({
      ok: false,
      reason: "NOT_V02_PLANNED_RUN",
    });
  });

  it("gives V02 layout contamination precedence over strict plan validation", async () => {
    await expect(capturePlannedRunV02(rootWithPlan({ schema_version: "0.2" }, ["ledger.jsonl"]))).resolves.toMatchObject({
      ok: false,
      reason: "V02_RUN_LAYOUT_CONTAMINATED",
    });
  });

  it("rejects an invalid V02 plan on an exact core layout", async () => {
    await expect(capturePlannedRunV02(rootWithPlan({ schema_version: "0.2", execution_profile: "bounded-v02" }))).resolves.toMatchObject({
      ok: false,
      reason: "INVALID_V02_PLAN",
    });
  });

  it("rejects missing roots and forged capture handles", async () => {
    await expect(capturePlannedRunV02("/path/that/does/not/exist")).resolves.toMatchObject({
      ok: false,
      reason: "INVALID_INPUT_ROOT",
    });
    expect(consumeCapturedPlannedRunV02({ run_id: "run_forged_01" } as never)).toBeNull();
  });
});

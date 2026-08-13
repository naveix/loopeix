import { afterEach, describe, expect, it, vi } from "vitest";
import Compile from "../../src/commands/compile.js";
import SpecNew from "../../src/commands/spec/new.js";

const REPOSITORY_ROOT = new URL("../../", import.meta.url).pathname;

afterEach(() => {
  vi.restoreAllMocks();
});

describe("S35 spec new --from-prompt delegation", () => {
  it("forwards the complete authorized surface to the compile command", async () => {
    const result = { ok: true, marker: "delegated" };
    const run = vi.spyOn(Compile, "run").mockResolvedValue(result as never);

    await expect(SpecNew.run([
      "--from-prompt", "Fix the parser",
      "--workspace-root", "/workspace",
      "--bindings", "/inputs/bindings.json",
      "--out", "/outputs/fix.loop.yaml",
      "--include-internal",
      "--json",
    ], REPOSITORY_ROOT)).resolves.toBe(result);

    expect(run).toHaveBeenCalledTimes(1);
    expect(run.mock.calls[0]?.[0]).toEqual([
      "--prompt", "Fix the parser",
      "--workspace-root", "/workspace",
      "--bindings", "/inputs/bindings.json",
      "--out", "/outputs/fix.loop.yaml",
      "--include-internal",
      "--json",
    ]);
  });

  it("omits absent optional flags instead of inventing defaults", async () => {
    const run = vi.spyOn(Compile, "run").mockResolvedValue({ ok: false } as never);
    await SpecNew.run(["--from-prompt", "Clarify this request"], REPOSITORY_ROOT);
    expect(run.mock.calls[0]?.[0]).toEqual(["--prompt", "Clarify this request"]);
  });

  it("rejects the legacy --item authoring path as usage-invalid", async () => {
    const run = vi.spyOn(Compile, "run").mockResolvedValue({ ok: true } as never);
    await expect(SpecNew.run([
      "--from-prompt", "Fix the parser",
      "--item", "safe-bugfix",
    ], REPOSITORY_ROOT)).rejects.toThrow(/Nonexistent flag: --item/u);
    expect(run).not.toHaveBeenCalled();
  });
});

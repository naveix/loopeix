import { describe, expect, it } from "vitest";
import { parseJsonlEvents, runEngine } from "../../src/index.js";

describe("parseJsonlEvents", () => {
  it("parses valid JSONL lines and skips blank + non-JSON lines", () => {
    const events = parseJsonlEvents('{"a":1}\n\n  \nnot json\n{"b":2}\n');
    expect(events).toEqual([{ a: 1 }, { b: 2 }]);
  });
  it("returns [] for empty input", () => {
    expect(parseJsonlEvents("")).toEqual([]);
    expect(parseJsonlEvents("\n \n")).toEqual([]);
  });
});

describe("S37 direct engine API boundary", () => {
  it.each(["codex_cli", "claude_code_cli"] as const)("never spawns %s as a general agent", (engine) => {
    expect(runEngine(engine, "must never execute", { cwd: "/" })).toEqual({
      engine,
      rawEvents: [],
      exit_code: -1,
      timed_out: false,
      stderr: `${engine} general-agent execution is prohibited in S37`,
      blocked_reason: "GENERAL_AGENT_PROHIBITED",
    });
  });
});

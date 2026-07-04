import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ClaudeAdapter, CodexAdapter, type AdapterResult, type Capability } from "../../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const ae = join(here, "..", "fixtures", "adapter-events");
const loadJsonl = (p: string): unknown[] =>
  readFileSync(p, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l));

const codexRaw = loadJsonl(join(ae, "codex", "s1-codex-exec-json.redacted.jsonl"));
const claudeRaw = loadJsonl(join(ae, "claude-code", "s1-claude-stream-json.redacted.jsonl"));

const gapLevel = (r: AdapterResult, cap: Capability): string | undefined =>
  r.capture_gaps.find((g) => g.capability === cap)?.level;
const kinds = (r: AdapterResult): string[] => r.events.map((e) => e.kind);

describe("Codex adapter (real redacted s1 sample)", () => {
  const r = new CodexAdapter().normalize(codexRaw);
  it("normalizes every event — nothing unmapped", () => {
    expect(r.unmapped_raw_types).toEqual([]);
  });
  it("emits run lifecycle + message + usage", () => {
    expect(kinds(r)).toEqual(expect.arrayContaining(["run.started", "message", "run.completed", "usage"]));
  });
  it("maps a non-fatal `error` item to notice, not error", () => {
    expect(r.events.some((e) => e.kind === "notice")).toBe(true);
    expect(r.events.some((e) => e.kind === "error")).toBe(false);
  });
  it("declares command/mcp capture as FULL; file_changes as PARTIAL (M2 adversarial fix: shell rm/mv invisible)", () => {
    expect(gapLevel(r, "shell_command_execution")).toBe("full");
    // file_changes is partial: Codex engine self-report; shell-level mutations (rm/mv via Bash)
    // produce only a command event — no file_change item. Engine admissions still convict;
    // absence cannot acquit. (Changed from "full" in M2 adversarial fix-pass.)
    expect(gapLevel(r, "file_changes")).toBe("partial");
    expect(gapLevel(r, "mcp_activity")).toBe("full");
  });
});

describe("Claude adapter (real redacted s1 sample)", () => {
  const r = new ClaudeAdapter().normalize(claudeRaw);
  it("normalizes every event — nothing unmapped", () => {
    expect(r.unmapped_raw_types).toEqual([]);
  });
  it("emits hook events + run lifecycle + message", () => {
    expect(r.events.filter((e) => e.kind === "hook").length).toBeGreaterThan(0);
    expect(kinds(r)).toEqual(expect.arrayContaining(["run.started", "message", "run.completed", "usage"]));
  });
  it("declares command/file capture as PARTIAL (inferred from tool_use)", () => {
    expect(gapLevel(r, "shell_command_execution")).toBe("partial");
    expect(gapLevel(r, "file_changes")).toBe("partial");
  });
});

describe("parity — same loop, honestly-different capture fidelity", () => {
  const cx = new CodexAdapter().normalize(codexRaw);
  const cl = new ClaudeAdapter().normalize(claudeRaw);
  it("both run non-interactively (full), but command/file fidelity differs and is NOT faked equal", () => {
    expect(gapLevel(cx, "noninteractive_run")).toBe("full");
    expect(gapLevel(cl, "noninteractive_run")).toBe("full");
    expect(gapLevel(cx, "shell_command_execution")).toBe("full");
    expect(gapLevel(cl, "shell_command_execution")).toBe("partial");
    // F4 (M2 adversarial fix): Codex file_changes is now PARTIAL — engine self-report;
    // shell-level mutations (rm/mv via Bash) produce no file_change item.
    // Engine admissions still convict at any level; absence cannot acquit.
    expect(gapLevel(cx, "file_changes")).toBe("partial");
    expect(gapLevel(cl, "file_changes")).toBe("partial");
  });
  it("both reach a normalized run.completed", () => {
    expect(kinds(cx)).toContain("run.completed");
    expect(kinds(cl)).toContain("run.completed");
  });
});

describe("parity fixtures are ASSERTED (not inert)", () => {
  const parity = join(here, "..", "fixtures", "parity", "simple-loop");
  const expected = JSON.parse(readFileSync(join(parity, "expected-normalized-event-sequence.json"), "utf8")) as {
    codex_cli: { kinds: Record<string, number>; unmapped_raw_types: string[] };
    claude_code_cli: { kinds: Record<string, number>; unmapped_raw_types: string[] };
  };
  const gapExp = JSON.parse(readFileSync(join(parity, "capture-gap-expectations.json"), "utf8")) as {
    codex_cli: Record<string, string>;
    claude_code_cli: Record<string, string>;
  };
  const countKinds = (r: AdapterResult): Record<string, number> =>
    r.events.reduce<Record<string, number>>((a, e) => {
      a[e.kind] = (a[e.kind] ?? 0) + 1;
      return a;
    }, {});

  it("codex parity events normalize to the expected sequence", () => {
    const r = new CodexAdapter().normalize(loadJsonl(join(parity, "codex-events.redacted.jsonl")));
    expect(countKinds(r)).toEqual(expected.codex_cli.kinds);
    expect(r.unmapped_raw_types).toEqual(expected.codex_cli.unmapped_raw_types);
  });
  it("claude parity events normalize to the expected sequence", () => {
    const r = new ClaudeAdapter().normalize(loadJsonl(join(parity, "claude-events.redacted.jsonl")));
    expect(countKinds(r)).toEqual(expected.claude_code_cli.kinds);
    expect(r.unmapped_raw_types).toEqual(expected.claude_code_cli.unmapped_raw_types);
  });
  it("capture gaps match the expectations file, per engine", () => {
    const cx = new CodexAdapter().normalize(loadJsonl(join(parity, "codex-events.redacted.jsonl")));
    const cl = new ClaudeAdapter().normalize(loadJsonl(join(parity, "claude-events.redacted.jsonl")));
    for (const [cap, lvl] of Object.entries(gapExp.codex_cli)) expect(gapLevel(cx, cap as Capability)).toBe(lvl);
    for (const [cap, lvl] of Object.entries(gapExp.claude_code_cli)) expect(gapLevel(cl, cap as Capability)).toBe(lvl);
  });
});

describe("Codex evidence-bearing payloads (Claims Check M2)", () => {
  it("command_execution carries command/exit_code/status but NEVER aggregated_output", () => {
    const r = new CodexAdapter().normalize([
      {
        type: "item.completed",
        item: { id: "i1", type: "command_execution", command: "pnpm test", aggregated_output: "SECRET-ish blob", exit_code: 1, status: "failed" },
      },
    ]);
    expect(r.events[0]?.payload).toEqual({ item_type: "command_execution", command: "pnpm test", exit_code: 1, status: "failed" });
  });

  it("file_change carries changes[{path,kind}] and drops malformed entries instead of inventing them", () => {
    const r = new CodexAdapter().normalize([
      {
        type: "item.completed",
        item: {
          id: "i2",
          type: "file_change",
          status: "completed",
          changes: [{ path: "tests/unit/a.test.ts", kind: "delete" }, { kind: "update" }, "garbage", { path: "src/b.ts" }],
        },
      },
    ]);
    expect(r.events[0]?.payload).toEqual({
      item_type: "file_change",
      status: "completed",
      changes: [{ path: "tests/unit/a.test.ts", kind: "delete" }, { path: "src/b.ts" }],
    });
  });

  it("agent_message text is NOT carried into the normalized payload (no free text in the ledger)", () => {
    const r = new CodexAdapter().normalize([
      { type: "item.completed", item: { id: "i3", type: "agent_message", text: "Done — 34/34 tests passing" } },
    ]);
    expect(r.events[0]?.payload).toEqual({ item_type: "agent_message" });
  });
});

describe("adapter edge cases", () => {
  it("Codex tolerates unknown event types (forward-compat)", () => {
    const r = new CodexAdapter().normalize([{ type: "future.event", foo: 1 }]);
    expect(r.unmapped_raw_types).toContain("future.event");
  });
  it("Codex turn.failed → error kind, and NO run.completed", () => {
    const r = new CodexAdapter().normalize([
      { type: "thread.started", thread_id: "t" },
      { type: "turn.started" },
      { type: "turn.failed", error: { message: "boom" } },
    ]);
    expect(r.events.some((e) => e.kind === "error")).toBe(true);
    expect(r.events.some((e) => e.kind === "run.completed")).toBe(false);
  });
  it("Codex multi-turn → exactly ONE run.completed, one usage per turn", () => {
    const r = new CodexAdapter().normalize([
      { type: "thread.started", thread_id: "t" },
      { type: "turn.started" },
      { type: "turn.completed", usage: {} },
      { type: "turn.started" },
      { type: "turn.completed", usage: {} },
    ]);
    expect(r.events.filter((e) => e.kind === "run.completed")).toHaveLength(1);
    expect(r.events.filter((e) => e.kind === "usage")).toHaveLength(2);
  });
  it("Claude usage.available is false when the result carries no usage (no fabrication)", () => {
    const r = new ClaudeAdapter().normalize([{ type: "result", subtype: "success", is_error: false }]);
    expect(r.events.find((e) => e.kind === "usage")?.payload["available"]).toBe(false);
  });
});

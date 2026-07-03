import { spawnSync } from "node:child_process";
import type { EngineId } from "../adapters/index.js";

/**
 * Engine invocation (the one part of the run-execution layer that shells out to a live CLI).
 * Loopeix uses the Codex/Claude CLIs' OWN auth — it never passes or holds an API key. Both are
 * invoked non-interactively with empty stdin (the `</dev/null` the captures required, or `codex exec`
 * hangs waiting on stdin), read-only/ephemeral/bounded-budget where the CLI supports it, and their
 * JSONL stdout is parsed into raw events for the adapter to normalize.
 */

export interface EngineRunResult {
  engine: EngineId;
  rawEvents: unknown[];
  exit_code: number;
  timed_out: boolean;
  stderr: string;
}

export interface EngineOptions {
  cwd?: string;
  timeoutMs?: number;
  maxBudgetUsd?: number;
}

export function parseJsonlEvents(text: string): unknown[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .flatMap((l) => {
      try {
        return [JSON.parse(l)];
      } catch {
        return [];
      }
    });
}

function engineCommand(engine: EngineId, prompt: string, opts: EngineOptions): { bin: string; args: string[] } {
  const budget = Number.isFinite(opts.maxBudgetUsd) && (opts.maxBudgetUsd as number) > 0 ? (opts.maxBudgetUsd as number) : 0.1;
  if (engine === "codex_cli") {
    // `--` forces `prompt` to be positional: a prompt beginning with `-` (e.g.
    // `--sandbox danger-full-access`) CANNOT be reparsed as a flag that overrides `--sandbox read-only`.
    return {
      bin: "codex",
      args: ["exec", "--json", "--ephemeral", "--sandbox", "read-only", "--skip-git-repo-check", "--", prompt],
    };
  }
  // Claude: `prompt` is the value of `-p` (not reinterpretable as a flag); flags follow.
  return {
    bin: "claude",
    args: [
      "-p",
      prompt,
      "--output-format",
      "stream-json",
      "--verbose",
      "--include-hook-events",
      "--no-session-persistence",
      "--max-budget-usd",
      String(budget),
    ],
  };
}

/** Invoke an engine CLI with empty stdin and capture its JSONL events. Never throws on non-zero exit. */
export function runEngine(engine: EngineId, prompt: string, opts: EngineOptions = {}): EngineRunResult {
  const { bin, args } = engineCommand(engine, prompt, opts);
  const res = spawnSync(bin, args, {
    input: "", // empty stdin = immediate EOF (the `</dev/null` the CLIs need to not hang)
    encoding: "utf8",
    timeout: opts.timeoutMs ?? 300_000,
    cwd: opts.cwd,
    maxBuffer: 64 * 1024 * 1024,
  });
  return {
    engine,
    rawEvents: parseJsonlEvents(res.stdout ?? ""),
    exit_code: res.status ?? -1,
    timed_out: (res.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT" || res.signal === "SIGTERM",
    stderr: res.stderr ?? "",
  };
}

import type { EngineId } from "../adapters/index.js";
import { prohibitS37GeneralAgentSpawnV02 } from "./pre-spawn-capability-broker-v02.js";

/** Engine event parsing plus the S37 non-spawning compatibility boundary. */

export interface EngineRunResult {
  engine: EngineId;
  rawEvents: unknown[];
  exit_code: number;
  timed_out: boolean;
  stderr: string;
  blocked_reason?: "GENERAL_AGENT_PROHIBITED";
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

/**
 * Extract the engine's FINAL structured message text from the RAW event stream (Claims Check M2).
 * This is the ONLY input the verdict engine's assertion recognizer reads — the text never enters
 * the ledger (normalized payloads carry no free text; see adapters). Codex: the last
 * `item.completed` agent_message's `text`. Claude: the `result` event's `result` string.
 * Returns undefined when the engine emitted no final text — the recognizer then simply has
 * nothing to recognize (no fabrication).
 */
export function extractFinalMessageText(engine: EngineId, rawEvents: readonly unknown[]): string | undefined {
  let final: string | undefined;
  for (const raw of rawEvents) {
    if (typeof raw !== "object" || raw === null) continue;
    const e = raw as Record<string, unknown>;
    if (engine === "codex_cli") {
      if (e["type"] !== "item.completed") continue;
      const item = e["item"];
      if (typeof item !== "object" || item === null) continue;
      const it = item as Record<string, unknown>;
      if (it["type"] === "agent_message" && typeof it["text"] === "string") final = it["text"];
    } else if (e["type"] === "result" && typeof e["result"] === "string") {
      final = e["result"];
    }
  }
  return final;
}

/**
 * S37 compatibility boundary. General engine execution is prohibited until a
 * later sprint can route every effect through the common enforcement point.
 * The function remains exported for API compatibility but never spawns.
 */
export function runEngine(engine: EngineId, _prompt: string, _opts: EngineOptions = {}): EngineRunResult {
  const blocked = prohibitS37GeneralAgentSpawnV02(engine);
  return {
    engine,
    rawEvents: [],
    exit_code: -1,
    timed_out: false,
    stderr: blocked.detail,
    blocked_reason: "GENERAL_AGENT_PROHIBITED",
  };
}

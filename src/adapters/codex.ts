import type { AdapterResult, CaptureGap, EngineAdapter, NormalizedEvent, NormalizedKind } from "./types.js";

/** Codex `item.completed` item.type → normalized kind. Unknown item types are collected in
 *  `unmapped_raw_types` (never silently dropped), so research can refine without breaking. */
const ITEM_KIND: Record<string, NormalizedKind> = {
  agent_message: "message",
  reasoning: "reasoning",
  command_execution: "command", // status ∈ in_progress|completed|failed|declined
  file_change: "file_change", // { changes: [{path, kind: add|delete|update}], status }
  mcp_tool_call: "tool_call",
  collab_tool_call: "tool_call", // multi-agent spawn/send/wait/close
  web_search: "tool_call",
  todo_list: "notice",
  // Item-level "error" items are NON-fatal (Warning/ConfigWarning/DeprecationNotice/ModelRerouted).
  // Real failures are the top-level `error` event or `turn.failed`. So normalize to "notice".
  error: "notice",
};

/** Codex capture matrix. Codex exposes command_execution / file_change / mcp_tool_call items
 *  directly (full), where Claude only infers them from tool_use (partial). */
const CODEX_GAPS: readonly CaptureGap[] = [
  { capability: "noninteractive_run", level: "full", note: "codex exec headless run." },
  { capability: "streamed_json_events", level: "full", note: "codex exec --json JSONL event stream." },
  { capability: "final_structured_output", level: "full", note: "--output-schema constrained final response." },
  { capability: "shell_command_execution", level: "full", note: "command_execution items are emitted in the event stream." },
  { capability: "file_changes", level: "full", note: "file_change/patch items are emitted in the event stream." },
  { capability: "tool_approvals", level: "partial", note: "sandbox denials surface as error items; explicit approval binding is partial." },
  { capability: "mcp_activity", level: "full", note: "mcp_tool_call items are emitted." },
  { capability: "browser_actions", level: "partial", note: "only via tool items; require browser evidence." },
  { capability: "subagent_lifecycle", level: "partial", note: "not distinctly emitted in exec JSON in this version." },
  { capability: "token_context_usage", level: "full", note: "usage on turn.completed." },
];

/** Normalize Codex `codex exec --json` JSONL events. */
export class CodexAdapter implements EngineAdapter {
  readonly engine = "codex_cli" as const;

  normalize(rawEvents: readonly unknown[]): AdapterResult {
    const events: NormalizedEvent[] = [];
    const unmapped = new Set<string>();
    let lastTopType = "";

    const emit = (kind: NormalizedKind, raw_type: string, payload: Record<string, unknown>): void => {
      events.push({ source: this.engine, kind, raw_type, payload });
    };

    for (const raw of rawEvents) {
      if (typeof raw !== "object" || raw === null) continue;
      const e = raw as Record<string, unknown>;
      const type = String(e["type"] ?? "");
      lastTopType = type;

      switch (type) {
        case "thread.started":
          emit("run.started", type, {});
          break;
        case "turn.started":
          break; // internal boundary; not evidence
        case "item.started":
        case "item.updated":
          break; // superseded by item.completed (item.updated is only todo_list progress)
        case "item.completed": {
          const item = e["item"];
          const itemType =
            typeof item === "object" && item !== null ? String((item as Record<string, unknown>)["type"] ?? "") : "";
          const kind = ITEM_KIND[itemType];
          if (kind) emit(kind, `item.completed:${itemType}`, { item_type: itemType });
          else unmapped.add(`item.completed:${itemType}`);
          break;
        }
        case "turn.completed":
          // Codex emits one turn.completed PER model turn (usage = cumulative thread total).
          // Do NOT emit run.completed here, or a multi-turn run would "end" repeatedly — a single
          // run.completed is derived at stream end (below).
          emit("usage", type, { available: "usage" in e, source: "turn.completed" });
          break;
        case "turn.failed":
        case "error":
          emit("error", type, {});
          break;
        default:
          if (type) unmapped.add(type);
      }
    }

    // Codex has no `thread.completed`; the run ends when the stream ends. Emit exactly one
    // run.completed, and only if the final turn completed successfully (a failed/errored final
    // turn already emitted an `error` and must not be reported as completed).
    if (lastTopType === "turn.completed") emit("run.completed", "stream.end", {});

    return {
      engine: this.engine,
      events,
      capture_gaps: [...CODEX_GAPS],
      unmapped_raw_types: [...unmapped].sort(),
    };
  }
}

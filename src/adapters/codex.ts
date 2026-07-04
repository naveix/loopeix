import type { AdapterResult, CaptureGap, EngineAdapter, NormalizedEvent, NormalizedKind } from "./types.js";

/** Codex `item.completed` item.type → normalized kind. Unknown item types are collected in
 *  `unmapped_raw_types` (never silently dropped), so research can refine without breaking.
 *
 *  EVIDENCE-BEARING PAYLOADS (Claims Check M2): adjudicable fields are carried through
 *  normalization for the verdict engine: `command_execution` → { command, exit_code, status };
 *  `file_change` → { status, changes: [{ path, kind }] } with kind ∈ add|delete|update.
 *  `aggregated_output` is deliberately NOT carried (unbounded, potentially secret-bearing);
 *  message text is likewise not carried (see ClaudeAdapter).
 *  NOTE: file_change capture is declared PARTIAL (engine self-report; shell-level mutations via
 *  bare `rm`/`mv` produce no file_change item). Admitted events still convict (doctrine: presence
 *  convicts), but absence cannot acquit — see CODEX_GAPS below. */
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

/** Codex capture matrix.
 *  `shell_command_execution` is FULL (command_execution items carry command text + exit code).
 *  `file_changes` is PARTIAL: Codex emits file_change items for agent-initiated edits, but
 *  shell-level mutations (e.g. `rm`, `mv` run via Bash) produce only a command_execution item
 *  with no corresponding file_change — so the file-change record is engine self-report, not an
 *  independent filesystem diff. An engine admission still convicts (doctrine: presence convicts),
 *  but absence cannot acquit — hence partial, not full. */
const CODEX_GAPS: readonly CaptureGap[] = [
  { capability: "noninteractive_run", level: "full", note: "codex exec headless run." },
  { capability: "streamed_json_events", level: "full", note: "codex exec --json JSONL event stream." },
  { capability: "final_structured_output", level: "full", note: "--output-schema constrained final response." },
  { capability: "shell_command_execution", level: "full", note: "command_execution items are emitted in the event stream." },
  { capability: "file_changes", level: "partial", note: "engine self-report; shell-level mutations invisible (no file_change item for bare shell rm/mv)." },
  { capability: "tool_approvals", level: "partial", note: "sandbox denials surface as error items; explicit approval binding is partial." },
  { capability: "mcp_activity", level: "full", note: "mcp_tool_call items are emitted." },
  { capability: "browser_actions", level: "partial", note: "only via tool items; require browser evidence." },
  { capability: "subagent_lifecycle", level: "partial", note: "not distinctly emitted in exec JSON in this version." },
  { capability: "token_context_usage", level: "full", note: "usage on turn.completed." },
];

/** Adjudicable fields carried through for evidence-bearing item types (see header note). */
function itemPayload(itemType: string, item: Record<string, unknown>): Record<string, unknown> {
  const payload: Record<string, unknown> = { item_type: itemType };
  if (itemType === "command_execution") {
    if (typeof item["command"] === "string") payload["command"] = item["command"];
    if (typeof item["exit_code"] === "number") payload["exit_code"] = item["exit_code"];
    if (typeof item["status"] === "string") payload["status"] = item["status"];
  } else if (itemType === "file_change") {
    if (typeof item["status"] === "string") payload["status"] = item["status"];
    const raw = Array.isArray(item["changes"]) ? item["changes"] : [];
    payload["changes"] = raw.flatMap((c) => {
      if (typeof c !== "object" || c === null) return [];
      const cc = c as Record<string, unknown>;
      if (typeof cc["path"] !== "string") return [];
      return [{ path: cc["path"], ...(typeof cc["kind"] === "string" ? { kind: cc["kind"] } : {}) }];
    });
  }
  return payload;
}

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
          if (kind) emit(kind, `item.completed:${itemType}`, itemPayload(itemType, (item ?? {}) as Record<string, unknown>));
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

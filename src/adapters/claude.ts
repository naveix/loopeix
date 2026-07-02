import type { AdapterResult, CaptureGap, EngineAdapter, NormalizedEvent, NormalizedKind } from "./types.js";

const COMMAND_TOOLS = new Set(["Bash"]);
const FILE_TOOLS = new Set(["Edit", "Write", "MultiEdit", "NotebookEdit"]);

/** Claude Code capture matrix (adapter-observability-matrix.md). */
const CLAUDE_GAPS: readonly CaptureGap[] = [
  { capability: "noninteractive_run", level: "full", note: "claude -p headless run." },
  { capability: "streamed_json_events", level: "full", note: "--output-format stream-json." },
  { capability: "final_structured_output", level: "full", note: "--json-schema constrained output." },
  { capability: "shell_command_execution", level: "partial", note: "Inferred from Bash tool_use + PostToolUse hooks; require command/filesystem evidence for strong claims." },
  { capability: "file_changes", level: "partial", note: "Inferred from Edit/Write tool_use + hooks; verify with filesystem hashes." },
  { capability: "tool_approvals", level: "partial", note: "permission_denials + permissionMode in result/init; no per-call approval binding in the stream." },
  { capability: "mcp_activity", level: "partial", note: "mcp_servers listed in init config (redacted); MCP tool calls appear as tool_use." },
  { capability: "browser_actions", level: "partial", note: "Only via tool_use events; require browser evidence for browser claims." },
  { capability: "subagent_lifecycle", level: "partial", note: "TaskCreated/TaskCompleted hook events when --include-hook-events." },
  { capability: "token_context_usage", level: "full", note: "usage + total_cost_usd in the result event." },
];

/** Normalize Claude Code `--output-format stream-json` events (schema-runtime-contract + research). */
export class ClaudeAdapter implements EngineAdapter {
  readonly engine = "claude_code_cli" as const;

  normalize(rawEvents: readonly unknown[]): AdapterResult {
    const events: NormalizedEvent[] = [];
    const unmapped = new Set<string>();

    const emit = (kind: NormalizedKind, raw_type: string, payload: Record<string, unknown>): void => {
      events.push({ source: this.engine, kind, raw_type, payload });
    };

    for (const raw of rawEvents) {
      if (typeof raw !== "object" || raw === null) continue;
      const e = raw as Record<string, unknown>;
      const type = String(e["type"] ?? "");

      switch (type) {
        case "system": {
          const subtype = String(e["subtype"] ?? "");
          if (subtype === "init") {
            emit("run.started", "system:init", {
              engine_version: e["claude_code_version"] ?? null,
              permission_mode: e["permissionMode"] ?? null,
            });
          } else if (subtype.startsWith("hook")) {
            // The real CLI (v2.1.198) emits subtype `hook_started` and `hook_response`
            // (not the single `hook_event` some docs list); `hook_event` is the FIELD that
            // carries PreToolUse/PostToolUse/etc. `outcome`/`exit_code` appear on responses.
            emit("hook", `system:${subtype}`, {
              hook_event: e["hook_event"] ?? null,
              hook_name: e["hook_name"] ?? null,
              outcome: e["outcome"] ?? null,
              exit_code: e["exit_code"] ?? null,
            });
          } else if (subtype === "api_retry") {
            emit("notice", "system:api_retry", { notice: "api_retry", error_status: e["error_status"] ?? null });
          } else if (subtype === "plugin_install") {
            emit("notice", "system:plugin_install", { notice: "plugin_install", status: e["status"] ?? null });
          } else {
            unmapped.add(`system:${subtype}`);
          }
          break;
        }
        case "assistant": {
          const message = e["message"];
          const content =
            typeof message === "object" && message !== null && Array.isArray((message as Record<string, unknown>)["content"])
              ? ((message as Record<string, unknown>)["content"] as unknown[])
              : [];
          for (const block of content) {
            if (typeof block !== "object" || block === null) continue;
            const b = block as Record<string, unknown>;
            const btype = String(b["type"] ?? "");
            if (btype === "text") {
              // Record that a message occurred + its length; the raw text is stored (redacted) as an artifact, not in the ledger payload.
              emit("message", "assistant.text", { text_len: typeof b["text"] === "string" ? (b["text"] as string).length : 0 });
            } else if (btype === "tool_use") {
              const name = String(b["name"] ?? "");
              if (COMMAND_TOOLS.has(name)) emit("command", "assistant.tool_use", { tool: name });
              else if (FILE_TOOLS.has(name)) emit("file_change", "assistant.tool_use", { tool: name });
              else emit("tool_call", "assistant.tool_use", { tool: name });
            } else {
              unmapped.add(`assistant.content:${btype}`);
            }
          }
          break;
        }
        case "result": {
          emit("run.completed", "result", {
            subtype: e["subtype"] ?? null,
            is_error: e["is_error"] ?? null,
            stop_reason: e["stop_reason"] ?? null,
            num_turns: e["num_turns"] ?? null,
          });
          emit("usage", "result", { available: "usage" in e || "total_cost_usd" in e, source: "result" });
          break;
        }
        case "user":
          // tool_result outcomes (Bash/Edit/Write results) arrive as `user` events. V1 does not
          // normalize them — command/file capture is declared `partial` — so they are recorded as
          // unmapped rather than fabricated into verified command/file evidence.
          unmapped.add("user");
          break;
        case "stream_event":
          // Superseded by the assembled `assistant` event; intentionally not re-normalized.
          break;
        default:
          if (type) unmapped.add(type);
      }
    }

    return {
      engine: this.engine,
      events,
      capture_gaps: [...CLAUDE_GAPS],
      unmapped_raw_types: [...unmapped].sort(),
    };
  }
}

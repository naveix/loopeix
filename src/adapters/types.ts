/**
 * Engine adapter contract (architecture-plan.md §Adapter Layer, adapter-observability-matrix.md).
 *
 * An adapter turns a raw engine event stream (Codex `codex exec --json` JSONL, or Claude
 * `claude -p --output-format stream-json`) into NORMALIZED events plus an explicit list of
 * CAPTURE GAPS. It must not invent observations: anything the engine does not expose is
 * declared a gap, never emitted as a verified event.
 */

export type EngineId = "codex_cli" | "claude_code_cli";

/** Normalized event taxonomy shared across engines. `kind` is what Loopeix reasons about;
 *  `raw_type` preserves the original engine event type for traceability. */
export type NormalizedKind =
  | "run.started"
  | "reasoning"
  | "message"
  | "command" // a shell command execution
  | "file_change" // a file edit/write/patch
  | "tool_call" // a generic tool or MCP invocation
  | "hook" // an engine hook-lifecycle event (secondary evidence)
  | "usage" // token/cost/turn summary
  | "notice" // an informational engine notice (not an error)
  | "error"
  | "run.completed";

export interface NormalizedEvent {
  source: EngineId;
  kind: NormalizedKind;
  /** The original engine event type, e.g. "item.completed" / "assistant". */
  raw_type: string;
  /** Normalized, already-redacted payload. Never contains secrets or volatile ids. Evidence-bearing
   *  kinds (command / file_change) carry the engine-reported command text, exit code, and
   *  workspace-relative file paths — the verdict engine's deciding fields (Claims Check M2);
   *  free-text message/output content is never carried. */
  payload: Record<string, unknown>;
}

/** Capability keys mirror the observability matrix rows. */
export type Capability =
  | "noninteractive_run"
  | "streamed_json_events"
  | "final_structured_output"
  | "shell_command_execution"
  | "file_changes"
  | "tool_approvals"
  | "mcp_activity"
  | "browser_actions"
  | "subagent_lifecycle"
  | "token_context_usage";

export type CaptureLevel = "full" | "partial" | "none";

export interface CaptureGap {
  capability: Capability;
  level: CaptureLevel;
  /** Why this level — what the adapter can and cannot see for this capability. */
  note: string;
}

export interface AdapterResult {
  engine: EngineId;
  events: NormalizedEvent[];
  /** Per the matrix: declared capabilities, especially the partial/none ones. */
  capture_gaps: CaptureGap[];
  /** Engine event types seen but not mapped to a NormalizedKind (forward-compat; never dropped silently). */
  unmapped_raw_types: string[];
}

export interface EngineAdapter {
  readonly engine: EngineId;
  /** Parse a raw engine event stream (already JSON-parsed) into normalized events + gaps. */
  normalize(rawEvents: readonly unknown[]): AdapterResult;
}

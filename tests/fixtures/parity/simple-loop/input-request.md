# Parity input request

A trivial cross-engine parity probe used to demonstrate that the same loop normalizes across
the Codex and Claude Code adapters while preserving each engine's capture-gap differences.

Prompt: `Reply with exactly the word: ok`

The captured `codex-events.redacted.jsonl` and `claude-events.redacted.jsonl` are the real,
redacted event streams (see `../../adapter-events/README.md` for capture commands + redaction).
`expected-normalized-event-sequence.json` and `capture-gap-expectations.json` state what the
adapters must produce.

#!/bin/bash
# T0 docile persona: a careful first-time user following the documented flow exactly.
# Every step's exit code is recorded for the oracle; output is captured verbatim.
set -u
OUT=/app/out
WORKSPACE=/app/work
mkdir -p "$OUT" "$WORKSPACE"

loopeix doctor >"$OUT/doctor.txt" 2>&1
echo "exit_doctor=$?" >>"$OUT/exits.env"

loopeix run start /opt/fixtures/seal-loop.yaml \
  --engine codex \
  --events-file /opt/fixtures/snitch-events.jsonl \
  --seal /opt/fixtures/snitch-brief.yaml \
  --workspace "$WORKSPACE" >"$OUT/run.txt" 2>&1
echo "exit_run=$?" >>"$OUT/exits.env"

RUN_DIR=$(echo "$WORKSPACE"/.loopeix/runs/*)
echo "run_dir=$RUN_DIR" >>"$OUT/exits.env"

loopeix verify "$RUN_DIR/receipt.json" --run-dir "$RUN_DIR" >"$OUT/verify.txt" 2>&1
echo "exit_verify=$?" >>"$OUT/exits.env"

loopeix pr "$RUN_DIR" --card "$OUT/delta-card.svg" >"$OUT/pr.txt" 2>&1
echo "exit_pr=$?" >>"$OUT/exits.env"

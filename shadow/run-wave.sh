#!/bin/bash
# Wave runner (S18-B'): harbor run with the scaled-wave defaults — concurrency 6 (the 8 GB Docker
# VM ceiling from WAVE-REPORT), exception-retry 2 for the ~3% Docker bind-mount race — then an
# honest infra-retry count and curation. Harbor retries EXCEPTIONS only (a failed attempt's trial
# dir is deleted before the retry, so nothing double-counts); oracle failures are rewards, not
# exceptions, so a real finding can never be laundered by a retry. (Harbor 0.17.1 additionally
# excludes agent-timeout exception types from retry by default.)
# Usage: run-wave.sh [-a agent] [-m model] [-p path]... [-n concurrent] [-r retries] [--no-curate]
set -euo pipefail
USAGE="usage: run-wave.sh [-a agent] [-m model] [-p path]... [-n concurrent] [-r retries] [--no-curate]"
cd "$(dirname "$0")"

AGENT=oracle; MODEL=""; PATHS=(); N=6; R=2; NO_CURATE=0
usage() { echo "$USAGE" >&2; exit 1; }
while [ $# -gt 0 ]; do case "$1" in
  -a) AGENT=$2; shift 2;;
  -m) MODEL=$2; shift 2;;
  -p) PATHS+=("$2"); shift 2;;
  -n) N=$2; shift 2;;
  -r) R=$2; shift 2;;
  --no-curate) NO_CURATE=1; shift;;
  *) usage;;
esac; done

if [ "$AGENT" = "oracle" ]; then
  [ ${#PATHS[@]} -gt 0 ] || PATHS=(generated)
else
  # Live-engine guards (any non-oracle agent spends subscription usage AND mounts its OAuth
  # token into the trial containers):
  # 1. The usage-window ack must be TODAY'S date — a stale export in a shell profile must not
  #    authorise a wave weeks later. Operator: LOOPEIX_SHADOW_LIVE_OK=$(date +%F).
  TODAY=$(date +%F)
  if [ "${LOOPEIX_SHADOW_LIVE_OK:-}" != "$TODAY" ]; then
    echo "FATAL: agent '$AGENT' makes live engine calls (subscription usage + OAuth token in-container)." >&2
    echo "Operator: check the Claude/Codex usage window, then re-run with LOOPEIX_SHADOW_LIVE_OK=$TODAY (today's date; the ack expires daily)." >&2
    exit 1
  fi
  # 2. Live agents run ONLY against explicitly-passed Tier-1 task dirs. Tier-0 dirs contain
  #    adversarial missions (tamper/fuzz); a live agent there would put the OAuth token inside
  #    an adversarial container (CONTRACT §1 credential rule). No default path for live waves.
  [ ${#PATHS[@]} -gt 0 ] || { echo "FATAL: live waves need an explicit -p generated-t1 (no default)." >&2; exit 1; }
  for p in "${PATHS[@]}"; do
    case "$p" in
      generated-t1|generated-t1/*) ;;
      *) echo "FATAL: live agent '$AGENT' may only run Tier-1 task paths (generated-t1*), got '$p'." >&2; exit 1;;
    esac
  done
  # 3. Cheap-model doctrine: a live wave must pin its model explicitly — harbor's default model
  #    for the adapter is NOT guaranteed cheap.
  [ -n "$MODEL" ] || { echo "FATAL: live waves must pin a cheap model with -m (e.g. -m claude-haiku-4-5)." >&2; exit 1; }
  # 4. Auth-path preflight: subscription OAuth must not be silently outranked by a stray API key
  #    in the environment (per-token billing + a second credential inside the container).
  if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    echo "FATAL: ANTHROPIC_API_KEY is set — unset it for live waves so the subscription OAuth path (CLAUDE_FORCE_OAUTH) is the only credential in play." >&2
    exit 1
  fi
fi

# Single args array (avoids empty-array expansion under set -u on macOS bash 3.2).
HARGS=(-a "$AGENT")
if [ -n "$MODEL" ]; then HARGS+=(-m "$MODEL"); fi
for p in "${PATHS[@]}"; do HARGS+=(-p "$p"); done
echo "==> harbor run ${HARGS[*]} --n-concurrent $N --max-retries $R"

# Identify THIS run's job dir by before/after set difference, not `ls -td | head -1` (a stale or
# concurrent job dir must not be counted/curated as this wave — review finding).
BEFORE=$(mktemp); trap 'rm -f "$BEFORE"' EXIT
ls -d jobs/*/ 2>/dev/null | sort > "$BEFORE" || true

# Capture harbor's own stdout/stderr too: the "Retrying in" debug line's destination (job.log vs
# console logger) is not contractually guaranteed by harbor, so the retry count greps BOTH.
HLOG=$(mktemp); trap 'rm -f "$BEFORE" "$HLOG"' EXIT
harbor run "${HARGS[@]}" --n-concurrent "$N" --max-retries "$R" --debug --quiet 2>&1 | tee "$HLOG"

NEWJOBS=$(ls -d jobs/*/ 2>/dev/null | sort | comm -13 "$BEFORE" -)
NNEW=$(printf '%s' "$NEWJOBS" | grep -c . || true)
[ "${NNEW:-0}" = "1" ] || { echo "FATAL: expected exactly 1 new job dir, found ${NNEW:-0} ($NEWJOBS) — not curating." >&2; exit 1; }
JOB=${NEWJOBS%/}

RETRIED=$(cat "$JOB/job.log" "$HLOG" 2>/dev/null | grep -c "Retrying in" || true); RETRIED=${RETRIED:-0}
# Exhausted-retry trials remain as exception dirs (no reward.txt) — count them as ground truth
# the curator will also flag. The retry count is ADVISORY (depends on a harbor debug log line);
# the exception count is authoritative.
EXH=$(find "$JOB" -mindepth 2 -maxdepth 2 -name "exception.txt" | wc -l | tr -d ' ')
# Expected trial count = task dirs under the paths this wave ran — lets the curator fail gates
# on a partial wave instead of passing on whatever completed.
EXPECT=0
for p in "${PATHS[@]}"; do
  c=$(find "$p" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
  EXPECT=$((EXPECT + c))
done
echo "==> job: $JOB (expected trials: $EXPECT; infra retries: $RETRIED [advisory]; unrecovered exceptions: $EXH)"
[ "$NO_CURATE" = "1" ] || node curate/curate.mjs --expect "$EXPECT" "$JOB"

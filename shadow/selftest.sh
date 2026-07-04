#!/bin/bash
# Meta-test: prove the oracles FAIL when they should — the false-green holes the review caught must
# stay closed. Injects two faults into staged tasks and asserts reward 0 with the right CODE token.
# Requires Docker + Harbor + a prepared fleet. Run: bash shadow/selftest.sh
set -uo pipefail
cd "$(dirname "$0")/.."
SH=shadow

pass=0; fail=0
check() { # <desc> <task-dir> <expected-token>
  local desc="$1" task="$2" tok="$3"
  ( cd "$SH" && harbor run -a oracle -p "${task#shadow/}" --n-concurrent 1 >/dev/null 2>&1 )
  local job; job=$(ls -td "$SH"/jobs/*/ | head -1)
  local r; r=$(cat "$job"*/verifier/reward.txt 2>/dev/null)
  local out; out=$(cat "$job"*/verifier/test-stdout.txt 2>/dev/null)
  if [ "$r" = "0" ] && echo "$out" | grep -q "\[$tok\]"; then
    echo "  PASS: $desc -> reward 0 [$tok]"; pass=$((pass+1))
  else
    echo "  FAIL: $desc -> reward='$r' out='$out' (expected 0 [$tok])"; fail=$((fail+1))
  fi
}

echo "==> sampling + generating + staging a small fleet"
node "$SH/persona/sample-personas.mjs" --n 12 --seed 99 >/dev/null 2>&1
node "$SH/generate/generate-tasks.mjs" >/dev/null 2>&1
bash "$SH/prep.sh" >/dev/null 2>&1

echo "==> fault 1: spec-corpus with invalid fixtures removed must FAIL (was a false-green)"
SC=$(find "$SH/generated" -maxdepth 1 -name "*spec-corpus" | head -1)
rm -f "$SC"/environment/fixtures/specs/invalid/*.yaml
check "spec-corpus missing invalid fixtures" "$SC" "missing-fixture"

echo "==> fault 2: docs-followability with a tampered fixture removed must FAIL (was a false-green)"
DF=$(find "$SH/generated" -maxdepth 1 -name "*docs-followability" | head -1)
rm -f "$DF"/environment/fixtures/snitch.tampered-verdict.receipt.json
check "docs-followability missing tampered fixture" "$DF" "missing-fixture"

echo "==> restaging (undo faults)"
bash "$SH/prep.sh" >/dev/null 2>&1

echo "==> selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

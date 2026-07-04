#!/bin/bash
# Meta-test: prove the oracles FAIL when they should — the false-green holes the review caught must
# stay closed — and that the Tier-1 lane's reference solutions PASS their oracles offline (no
# engine calls). Injects faults into staged tasks and asserts reward 0 with the right CODE token.
# Uses .tmp persona corpora so the canonical persona/*.jsonl files are never clobbered.
# Requires Docker + Harbor. Run: bash shadow/selftest.sh
set -uo pipefail
cd "$(dirname "$0")/.."
SH=shadow

pass=0; fail=0
run_task() { # <task-dir> -> sets R (reward) and OUTV (oracle stdout)
  # Grade ONLY a job dir created by THIS invocation: a failed harbor launch must not silently
  # re-grade the previous check's job (review finding — that could false-PASS a fault check).
  local task="$1" before after job rc
  before=$(ls -d "$SH"/jobs/*/ 2>/dev/null | sort)
  ( cd "$SH" && harbor run -a oracle -p "${task#shadow/}" --n-concurrent 1 >/dev/null 2>&1 ); rc=$?
  after=$(ls -d "$SH"/jobs/*/ 2>/dev/null | sort)
  job=$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after") | head -1)
  if [ "$rc" -ne 0 ] || [ -z "$job" ]; then
    R="<harbor-launch-failed rc=$rc>"; OUTV=""
    return
  fi
  R=$(cat "$job"*/verifier/reward.txt 2>/dev/null)
  OUTV=$(cat "$job"*/verifier/test-stdout.txt 2>/dev/null)
}
check() { # <desc> <task-dir> <expected-token> — expect reward 0 with the token
  local desc="$1" task="$2" tok="$3"
  run_task "$task"
  if [ "$R" = "0" ] && echo "$OUTV" | grep -q "\[$tok\]"; then
    echo "  PASS: $desc -> reward 0 [$tok]"; pass=$((pass+1))
  else
    echo "  FAIL: $desc -> reward='$R' out='$OUTV' (expected 0 [$tok])"; fail=$((fail+1))
  fi
}
checkpass() { # <desc> <task-dir> — expect reward 1 (reference solution satisfies the oracle)
  local desc="$1" task="$2"
  run_task "$task"
  if [ "$R" = "1" ]; then
    echo "  PASS: $desc -> reward 1"; pass=$((pass+1))
  else
    echo "  FAIL: $desc -> reward='$R' out='$OUTV' (expected 1)"; fail=$((fail+1))
  fi
}

echo "==> sampling + generating + staging a small tier-0 fleet (tmp corpus)"
node "$SH/persona/sample-personas.mjs" --n 12 --seed 99 --out "$SH/persona/personas-selftest.tmp" >/dev/null 2>&1
node "$SH/generate/generate-tasks.mjs" --personas "$SH/persona/personas-selftest.tmp" >/dev/null 2>&1
echo "==> sampling + generating a small tier-1 fleet (tmp corpus, validated offline via -a oracle)"
node "$SH/persona/sample-personas.mjs" --tiers 1 --n 4 --seed 42 --out "$SH/persona/personas-t1-selftest.tmp" >/dev/null 2>&1
node "$SH/generate/generate-tasks.mjs" --personas "$SH/persona/personas-t1-selftest.tmp" >/dev/null 2>&1
bash "$SH/prep.sh" >/dev/null 2>&1

echo "==> fault 1: spec-corpus with invalid fixtures removed must FAIL (was a false-green)"
SC=$(find "$SH/generated" -maxdepth 1 -name "*spec-corpus" | head -1)
rm -f "$SC"/environment/fixtures/specs/invalid/*.yaml
check "spec-corpus missing invalid fixtures" "$SC" "missing-fixture"

echo "==> fault 2: docs-followability with a tampered fixture removed must FAIL (was a false-green)"
DF=$(find "$SH/generated" -maxdepth 1 -name "*docs-followability" | head -1)
rm -f "$DF"/environment/fixtures/snitch.tampered-verdict.receipt.json
check "docs-followability missing tampered fixture" "$DF" "missing-fixture"

echo "==> tier-1 reference solutions must PASS their oracles (validates the T1 lane offline)"
T1DI=$(find "$SH/generated-t1" -maxdepth 1 -name "*t1-docile-install" | head -1)
T1DF=$(find "$SH/generated-t1" -maxdepth 1 -name "*t1-docs-followability" | head -1)
T1SC=$(find "$SH/generated-t1" -maxdepth 1 -name "*t1-spec-corpus" | head -1)
checkpass "t1 docile-install reference" "$T1DI"
checkpass "t1 docs-followability reference" "$T1DF"
checkpass "t1 spec-corpus reference" "$T1SC"

echo "==> fault 3: t1 persona that writes no answers must FAIL fail-closed"
printf '#!/bin/bash\ntrue\n' > "$T1DF/solution/solve.sh"
check "t1 docs-followability no answers" "$T1DF" "no-answer"

echo "==> fault 4: t1 spec-corpus with specs-mixed unstaged must FAIL as a harness fault"
rm -f "$T1SC"/environment/fixtures/specs-mixed/*.yaml
check "t1 spec-corpus missing mixed fixtures" "$T1SC" "missing-fixture"

echo "==> fault 5: t1 persona giving a wrong answer must FAIL with [wrong-answer]"
# Flip the reference solution's verdicts so exactly the graded-comparison path trips.
cat > "$T1DF/solution/solve.sh" <<'EOSOLVE'
#!/bin/bash
set -u; shopt -s nullglob
OUT=/app/out; mkdir -p "$OUT"; : > "$OUT/answers.env"
for f in /opt/fixtures/receipts-mixed/*.receipt.json; do
  if loopeix verify "$f" >/dev/null 2>&1; then v=NOT_VERIFIED; else v=VERIFIED; fi
  echo "$(basename "$f")=$v" >>"$OUT/answers.env"
done
EOSOLVE
check "t1 docs-followability inverted answers" "$T1DF" "wrong-answer"

echo "==> cleanup: regenerate + restage the CANONICAL fleets (never leave the tmp fleets staged)"
# Restoring from the tmp corpora would silently replace the operator's canonical 240/12 fleets
# with the 12/4 selftest fleets (review finding). Regenerate from the committed corpora instead.
node "$SH/generate/generate-tasks.mjs" --personas "$SH/persona/personas.jsonl" >/dev/null 2>&1
if [ -f "$SH/persona/personas-t1.jsonl" ]; then
  node "$SH/generate/generate-tasks.mjs" --personas "$SH/persona/personas-t1.jsonl" >/dev/null 2>&1
fi
bash "$SH/prep.sh" >/dev/null 2>&1

echo "==> selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

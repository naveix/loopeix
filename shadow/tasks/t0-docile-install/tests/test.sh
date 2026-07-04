#!/bin/bash
# Deterministic oracle — bash only, no network, no test-time installs.
# Reward 1 iff the documented docile flow succeeded end to end with truthful output.
set -u
mkdir -p /logs/verifier
fail() { echo "ORACLE FAIL: $1"; echo 0 > /logs/verifier/reward.txt; exit 0; }

[ -f /app/out/exits.env ] || fail "persona never ran (no exits.env)"
# shellcheck disable=SC1091
source /app/out/exits.env

[ "${exit_doctor:-1}" = "0" ] || fail "doctor exited ${exit_doctor:-unset}"
[ "${exit_run:-1}" = "0" ]    || fail "run start exited ${exit_run:-unset}"
[ "${exit_verify:-1}" = "0" ] || fail "verify exited ${exit_verify:-unset}"
[ "${exit_pr:-1}" = "0" ]     || fail "pr exited ${exit_pr:-unset}"

grep -q "VERIFIED" /app/out/verify.txt            || fail "verify output lacks VERIFIED"
grep -q "PROMISE_BROKEN" /app/out/run.txt         || fail "run output lacks the PROMISE_BROKEN verdict"
grep -q "PROMISE BROKEN" /app/out/pr.txt          || fail "PR table lacks the PROMISE BROKEN row"
grep -q "UNSUPPORTED" /app/out/run.txt            || fail "run output lacks the UNSUPPORTED verdict"
[ -s /app/out/delta-card.svg ]                    || fail "delta card SVG missing/empty"
grep -q "<svg" /app/out/delta-card.svg            || fail "delta card is not SVG"
[ -f "${run_dir:-/nonexistent}/receipt.json" ]    || fail "receipt.json missing from run dir"
[ -f "${run_dir:-/nonexistent}/ledger.jsonl" ]    || fail "ledger.jsonl missing from run dir"

echo "ORACLE PASS: docile flow end-to-end on node $(node --version)"
echo 1 > /logs/verifier/reward.txt

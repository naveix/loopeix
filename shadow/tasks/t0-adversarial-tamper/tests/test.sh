#!/bin/bash
# Deterministic oracle. Reward 1 iff the honest receipt verified AND all four forgeries
# were rejected (non-zero exit). ANY forgery that verifies (exit 0) = reward 0 = P0 (SG3).
set -u
mkdir -p /logs/verifier
fail() { echo "ORACLE FAIL: $1"; echo 0 > /logs/verifier/reward.txt; exit 0; }

[ -f /app/out/exits.env ] || fail "persona never ran"
# shellcheck disable=SC1091
source /app/out/exits.env

[ "${exit_baseline:-1}" = "0" ] || fail "honest receipt did NOT verify (exit ${exit_baseline:-unset}) — false reject"

# atk4 must have actually changed the receipt bytes, else it proves nothing.
[ "${atk4_changed:-0}" = "1" ] || fail "atk4 was vacuous (no VERIFIED claim to flip) — invalid attack, not a rejection"

for a in atk1 atk2 atk3 atk4; do
  var="exit_$a"
  code="${!var:-0}"
  [ "$code" != "0" ] || fail "FORGERY ACCEPTED: $a verified (exit 0) — false-accept, P0"
done

echo "ORACLE PASS: honest verified; atk1..atk4 all rejected (exits: $exit_atk1 $exit_atk2 $exit_atk3 $exit_atk4)"
echo 1 > /logs/verifier/reward.txt

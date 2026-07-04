#!/bin/bash
# T0 adversarial persona: seal an honest run, then forge it four ways and demand that
# `loopeix verify` reject every forgery. A forged receipt that verifies is a P0 (SG3).
set -u
OUT=/app/out
WORKSPACE=/app/work
mkdir -p "$OUT" "$WORKSPACE"

# Seal a clean, honest run first (this SHOULD verify).
loopeix run start /opt/fixtures/seal-loop.yaml \
  --engine codex \
  --events-file /opt/fixtures/clean-events.jsonl \
  --seal /opt/fixtures/clean-brief.yaml \
  --workspace "$WORKSPACE" >"$OUT/seal.txt" 2>&1
RUN_DIR=$(echo "$WORKSPACE"/.loopeix/runs/*)
echo "run_dir=$RUN_DIR" >"$OUT/exits.env"

# Baseline: the honest receipt must verify (exit 0).
loopeix verify "$RUN_DIR/receipt.json" --run-dir "$RUN_DIR" >"$OUT/baseline.txt" 2>&1
echo "exit_baseline=$?" >>"$OUT/exits.env"

# Attack 1 — flip a verdict inside the signed receipt body.
A=/app/atk1; mkdir -p "$A"; cp -r "$RUN_DIR"/. "$A"/
sed -i 's/UNEVALUATED/KEPT/g; s/UNSUPPORTED/VERIFIED/g' "$A/receipt.json"
loopeix verify "$A/receipt.json" --run-dir "$A" >"$OUT/atk1.txt" 2>&1
echo "exit_atk1=$?" >>"$OUT/exits.env"

# Attack 2 — edit the ledger after sealing (break the hash chain).
B=/app/atk2; mkdir -p "$B"; cp -r "$RUN_DIR"/. "$B"/
sed -i 's/payments/paymentz/g' "$B/ledger.jsonl"
loopeix verify "$B/receipt.json" --run-dir "$B" >"$OUT/atk2.txt" 2>&1
echo "exit_atk2=$?" >>"$OUT/exits.env"

# Attack 3 — truncate the receipt JSON (malformed).
C=/app/atk3; mkdir -p "$C"; cp -r "$RUN_DIR"/. "$C"/
head -c 200 "$RUN_DIR/receipt.json" > "$C/receipt.json"
loopeix verify "$C/receipt.json" --run-dir "$C" >"$OUT/atk3.txt" 2>&1
echo "exit_atk3=$?" >>"$OUT/exits.env"

# Attack 4 — downgrade a VERIFIED claim to a CONTRADICTED lie (genuine byte change; must fail
# both the invariant count and the signature). Guard: the edit must actually change the bytes,
# else the "attack" is vacuous and the oracle records it as INVALID, not as a rejection.
D=/app/atk4; mkdir -p "$D"; cp -r "$RUN_DIR"/. "$D"/
jq '(.claims[] | select(.verdict=="VERIFIED") | .verdict) = "CONTRADICTED"' "$RUN_DIR/receipt.json" > "$D/receipt.json" 2>>"$OUT/atk4.txt"
if cmp -s "$RUN_DIR/receipt.json" "$D/receipt.json"; then
  echo "atk4_changed=0" >>"$OUT/exits.env"   # vacuous — no VERIFIED claim to flip
else
  echo "atk4_changed=1" >>"$OUT/exits.env"
fi
loopeix verify "$D/receipt.json" --run-dir "$D" >>"$OUT/atk4.txt" 2>&1
echo "exit_atk4=$?" >>"$OUT/exits.env"

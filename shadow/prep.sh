#!/bin/bash
# Prepare shadow-fleet task environments: build + pack loopeix, then stage the tarball and the
# fixture bundle into every task's build context (hand-written spike tasks AND generated ones).
# The tarball/fixtures are build artefacts (gitignored), so this makes a fresh clone reproducible.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

echo "==> building + packing loopeix"
pnpm build >/dev/null
mkdir -p shadow/dist
pnpm pack --pack-destination shadow/dist >/dev/null
TGZ_ABS=$(ls -t "$REPO"/shadow/dist/*.tgz | head -1)
echo "==> packed: $TGZ_ABS"

# Fail loudly if a source fixture set is missing: a silently half-staged bundle makes an oracle
# test nothing and report green (the exact false-green class the review caught). No `|| true`.
require_glob() { local n; n=$(ls $1 2>/dev/null | wc -l | tr -d ' '); [ "$n" -ge "$2" ] || { echo "FATAL: expected >= $2 files matching $1, found $n" >&2; exit 1; }; }
require_glob "tests/fixtures/run-seal/*.yaml" 2
require_glob "tests/fixtures/run-seal/*.jsonl" 2
require_glob "tests/fixtures/receipts/*.receipt.json" 5
require_glob "tests/fixtures/valid/specs/*.yaml" 1
require_glob "tests/fixtures/invalid/specs/*.yaml" 1
[ -f shadow/generate/fuzz.mjs ] || { echo "FATAL: shadow/generate/fuzz.mjs missing" >&2; exit 1; }

# Anonymised fixture sets for Tier-1 missions: files renamed to a content-hash so neither
# directory labels (specs valid/invalid) nor self-describing filenames (snitch.tampered-verdict…)
# can leak the answer key to a live persona (review findings, P1). Built once, count-asserted so
# a hash collision or copy failure fails loudly.
hash10() { (md5 -q "$1" 2>/dev/null || md5sum "$1" | cut -d' ' -f1) | cut -c1-10; }
MIXED_TMP=$(mktemp -d); RCPT_TMP=$(mktemp -d)
trap 'rm -rf "$MIXED_TMP" "$RCPT_TMP"' EXIT
src_count=0
for f in tests/fixtures/valid/specs/*.yaml tests/fixtures/invalid/specs/*.yaml; do
  cp "$f" "$MIXED_TMP/spec-$(hash10 "$f").yaml"; src_count=$((src_count+1))
done
mixed_count=$(ls "$MIXED_TMP" | wc -l | tr -d ' ')
[ "$mixed_count" -eq "$src_count" ] || { echo "FATAL: specs-mixed has $mixed_count files, expected $src_count (hash collision or copy failure)" >&2; exit 1; }
rcpt_src=0
for f in tests/fixtures/receipts/*.receipt.json; do
  cp "$f" "$RCPT_TMP/receipt-$(hash10 "$f").receipt.json"; rcpt_src=$((rcpt_src+1))
done
rcpt_count=$(ls "$RCPT_TMP" | wc -l | tr -d ' ')
[ "$rcpt_count" -eq "$rcpt_src" ] || { echo "FATAL: receipts-mixed has $rcpt_count files, expected $rcpt_src" >&2; exit 1; }

# Per-tier bundles. Tier 0 (scripted oracles) gets the labelled fixtures its missions consume.
# Tier 1 (live personas) gets ONLY mission inputs — never the labelled specs dirs or the
# original receipt filenames, which are the answer keys the anonymised sets exist to hide.
# Both wipe the fixtures dir first so a re-prep never leaves stale content-hash zombies.
stage_bundle_t0() {
  local env="$1"
  rm -rf "$env/fixtures"
  mkdir -p "$env/fixtures/specs/valid" "$env/fixtures/specs/invalid"
  cp "$TGZ_ABS" "$env/loopeix-0.0.0.tgz"
  cp tests/fixtures/run-seal/*.yaml tests/fixtures/run-seal/*.jsonl "$env/fixtures/"
  cp tests/fixtures/receipts/*.receipt.json "$env/fixtures/"
  cp tests/fixtures/valid/specs/*.yaml "$env/fixtures/specs/valid/"
  cp tests/fixtures/invalid/specs/*.yaml "$env/fixtures/specs/invalid/"
  cp shadow/generate/fuzz.mjs "$env/fixtures/"
}
stage_bundle_t1() {
  local env="$1"
  rm -rf "$env/fixtures"
  mkdir -p "$env/fixtures/specs-mixed" "$env/fixtures/receipts-mixed"
  cp "$TGZ_ABS" "$env/loopeix-0.0.0.tgz"
  cp tests/fixtures/run-seal/*.yaml tests/fixtures/run-seal/*.jsonl "$env/fixtures/"
  cp "$MIXED_TMP"/*.yaml "$env/fixtures/specs-mixed/"
  cp "$RCPT_TMP"/*.receipt.json "$env/fixtures/receipts-mixed/"
}

n=0
for task in shadow/tasks/*/ shadow/generated/*/; do
  [ -d "$task/environment" ] || continue
  stage_bundle_t0 "$task/environment"
  n=$((n+1))
done
for task in shadow/generated-t1/*/; do
  [ -d "$task/environment" ] || continue
  stage_bundle_t1 "$task/environment"
  n=$((n+1))
done
echo "==> staged $n task(s)"
echo "==> ready. Run:  bash shadow/run-wave.sh   (Tier-0 wave with retry + curation)"

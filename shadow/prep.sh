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

# Full fixture bundle needed across all missions (spike tasks use a subset; harmless to over-stage).
stage_bundle() {
  local env="$1"
  mkdir -p "$env/fixtures" "$env/fixtures/specs/valid" "$env/fixtures/specs/invalid"
  cp "$TGZ_ABS" "$env/loopeix-0.0.0.tgz"
  cp tests/fixtures/run-seal/*.yaml tests/fixtures/run-seal/*.jsonl "$env/fixtures/"
  cp tests/fixtures/receipts/*.receipt.json "$env/fixtures/"
  cp tests/fixtures/valid/specs/*.yaml "$env/fixtures/specs/valid/"
  cp tests/fixtures/invalid/specs/*.yaml "$env/fixtures/specs/invalid/"
  cp shadow/generate/fuzz.mjs "$env/fixtures/"
}

n=0
for task in shadow/tasks/*/ shadow/generated/*/; do
  [ -d "$task/environment" ] || continue
  stage_bundle "$task/environment"
  n=$((n+1))
done
echo "==> staged $n task(s)"
echo "==> ready. Run:  cd shadow && harbor run -a oracle -p tasks -p generated --n-concurrent 8"

#!/bin/bash
# Prepare the shadow-fleet task environments: build + pack loopeix, then stage the tarball
# and demo fixtures into every task's build context. Run before `harbor run`.
# The tarball is a build artefact (gitignored), so this makes a fresh clone reproducible.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

echo "==> building + packing loopeix"
pnpm build >/dev/null
mkdir -p shadow/dist
TGZ=$(pnpm pack --pack-destination shadow/dist | tail -1)
TGZ_ABS="$REPO/$TGZ"
[ -f "$TGZ_ABS" ] || TGZ_ABS=$(ls -t "$REPO"/shadow/dist/*.tgz | head -1)
echo "==> packed: $TGZ_ABS"

for task in shadow/tasks/*/; do
  env="$task/environment"
  [ -d "$env" ] || continue
  cp "$TGZ_ABS" "$env/loopeix-0.0.0.tgz"
  mkdir -p "$env/fixtures"
  cp tests/fixtures/run-seal/*.yaml tests/fixtures/run-seal/*.jsonl "$env/fixtures/"
  echo "    staged $(basename "$task")"
done
echo "==> ready. Run:  cd shadow && harbor run -a oracle -p tasks --n-concurrent 2"

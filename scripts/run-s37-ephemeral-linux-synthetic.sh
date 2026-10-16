#!/usr/bin/env bash

set -Eeuo pipefail

printf '%s\n' \
  '================================================================' \
  'NON_PRODUCTION_SYNTHETIC_ONLY' \
  'This run performs repository checks and synthetic tests only.' \
  'It does not activate the product or produce deployment evidence.' \
  '================================================================'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

if [[ "$(uname -s)" != "Linux" ]]; then
  printf '%s\n' 'HOLD: this entrypoint requires Linux' >&2
  exit 69
fi

if [[ "$(uname -m)" != "x86_64" ]]; then
  printf '%s\n' 'HOLD: this entrypoint requires x86_64' >&2
  exit 69
fi

readonly REQUIRED_COMMANDS=(node cc /usr/bin/gcc)
for command_name in "${REQUIRED_COMMANDS[@]}"; do
  if ! command -v -- "${command_name}" >/dev/null 2>&1; then
    printf 'HOLD: required command is unavailable: %s\n' "${command_name}" >&2
    exit 69
  fi
done

readonly REQUIRED_FILES=(
  "scripts/check-s37-boundaries.mjs"
  "scripts/check-s37-linux-phase-b-artifacts.mjs"
  "scripts/s37-linux-phase-b/test-supervisor-execve-diagnostic.sh"
  "scripts/s37-linux-phase-b/test-probe-canonical-environment.sh"
  "tests/integration/s37-linux-product-host-v03-contract.test.ts"
  "tests/integration/s37-linux-product-host-v03-runtime.test.ts"
  "tests/unit/linux-product-runtime-v03-s37.test.ts"
  "node_modules/.bin/vitest"
)

for relative_path in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "${REPO_ROOT}/${relative_path}" ]]; then
    printf 'HOLD: required repository file is unavailable: %s\n' "${relative_path}" >&2
    exit 69
  fi
done

cd -- "${REPO_ROOT}"

printf '%s\n' 'STEP 1/5: repository boundary check'
node scripts/check-s37-boundaries.mjs

printf '%s\n' 'STEP 2/5: Linux artifact static check'
node scripts/check-s37-linux-phase-b-artifacts.mjs --root "${REPO_ROOT}"

printf '%s\n' 'STEP 3/5: supervisor diagnostic check'
/bin/sh scripts/s37-linux-phase-b/test-supervisor-execve-diagnostic.sh "${REPO_ROOT}"

printf '%s\n' 'STEP 4/5: canonical environment check'
/bin/sh scripts/s37-linux-phase-b/test-probe-canonical-environment.sh "${REPO_ROOT}"

printf '%s\n' 'STEP 5/5: focused V03 synthetic tests'
"${REPO_ROOT}/node_modules/.bin/vitest" run \
  tests/integration/s37-linux-product-host-v03-contract.test.ts \
  tests/integration/s37-linux-product-host-v03-runtime.test.ts \
  tests/unit/linux-product-runtime-v03-s37.test.ts

printf '%s\n' 'NON_PRODUCTION_SYNTHETIC_ONLY: PASS'

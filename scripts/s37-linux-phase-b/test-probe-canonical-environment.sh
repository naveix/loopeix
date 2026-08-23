#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  printf '%s\n' 'usage: test-probe-canonical-environment.sh <absolute-repository-root>' >&2
  exit 64
fi

case "$1" in
  /*) ;;
  *) printf '%s\n' 'repository root must be absolute' >&2; exit 64 ;;
esac

repository_root=$(realpath "$1")
source_path="$repository_root/scripts/s37-linux-phase-b/probe.c"
test -f "$source_path"
test ! -L "$source_path"

test_root=$(mktemp -d)
test -n "$test_root"
case "$test_root" in
  /*) ;;
  *) printf '%s\n' 'temporary path must be absolute' >&2; exit 70 ;;
esac
test -d "$test_root"
test ! -L "$test_root"

cleanup() {
  trap - EXIT HUP INT TERM
  if [ -e "$test_root/canonical-environment-test" ]; then
    test -f "$test_root/canonical-environment-test"
    test ! -L "$test_root/canonical-environment-test"
    rm "$test_root/canonical-environment-test"
  fi
  rmdir "$test_root"
}
trap cleanup EXIT HUP INT TERM

cc \
  -std=c17 -DLOOPEIX_S37_CANONICAL_ENVIRONMENT_TEST \
  -Wall -Wextra -Werror -Wconversion -Wformat=2 -Wshadow -Wstrict-prototypes \
  "$source_path" -o "$test_root/canonical-environment-test"

run_case() {
  expected_exit=$1
  working_directory=$2
  shift 2
  set +e
  (cd "$working_directory" && env -i "$@" "$test_root/canonical-environment-test")
  observed_exit=$?
  set -e
  test "$observed_exit" -eq "$expected_exit"
}

run_case 0 / PWD=/
run_case 1 /
run_case 1 / PWD=/ EXTRA=x
run_case 1 / PWD=/tmp
run_case 1 "$test_root" PWD=/

printf '%s\n' 'S37.1-B canonical environment runtime tests passed'

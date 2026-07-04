#!/bin/bash
# One-time: rename the planning workspace "Loop Specs" -> "loopeix-specs" and fix all companion
# state. MUST be run from a terminal that is NOT a Claude Code session rooted in the old folder
# (a plain Terminal tab), because you cannot rename the directory a running session lives in.
#
# After it succeeds: reopen Claude Code in /Users/naviix/Work/Projects/loopeix-specs
#
# New name is a variable — change NEW below if you prefer something else. It must NOT be "loopeix"
# (that is the implementation repo; macOS is case-insensitive so it would collide).
set -euo pipefail

BASE="/Users/naviix/Work/Projects"
OLD="Loop Specs"
NEW="loopeix-specs"
OLD_ABS="$BASE/$OLD"
NEW_ABS="$BASE/$NEW"

# 0. Safety checks.
case "$PWD" in "$OLD_ABS"|"$OLD_ABS"/*) echo "REFUSING: run this from outside '$OLD_ABS' (e.g. cd ~ first)"; exit 1;; esac
[ -d "$OLD_ABS" ] || { echo "nothing to do: '$OLD_ABS' does not exist"; exit 0; }
[ -e "$NEW_ABS" ] && { echo "ABORT: '$NEW_ABS' already exists"; exit 1; }

echo "==> 1/5 renaming the workspace folder"
mv "$OLD_ABS" "$NEW_ABS"

echo "==> 2/5 moving the Claude session-history dir (keeps history/memory continuity)"
SESS_OLD="$HOME/.claude/projects/-Users-naviix-Work-Projects-Loop-Specs"
SESS_NEW="$HOME/.claude/projects/-Users-naviix-Work-Projects-loopeix-specs"
[ -d "$SESS_OLD" ] && { [ -e "$SESS_NEW" ] || mv "$SESS_OLD" "$SESS_NEW"; } || echo "   (no session dir; skipping)"

echo "==> 3/5 updating the open replay trace path"
TRACE="$HOME/.claude/replay/20260702T131938Z-loop/run.json"
[ -f "$TRACE" ] && sed -i '' "s#Work/Projects/Loop Specs#Work/Projects/$NEW#g" "$TRACE" || echo "   (no trace; skipping)"

echo "==> 4/5 fixing path references inside the moved workspace"
grep -rl "Work/Projects/Loop Specs" "$NEW_ABS" --exclude-dir=.git 2>/dev/null | while read -r f; do
  sed -i '' "s#Work/Projects/Loop Specs#Work/Projects/$NEW#g" "$f"
done

echo "==> 5/5 fixing the one reference in the loopeix impl repo"
IMPL_REF="$BASE/loopeix/shadow/README.md"
[ -f "$IMPL_REF" ] && sed -i '' "s#\`Loop Specs/docs#\`$NEW/docs#g" "$IMPL_REF" || true

echo
echo "DONE. Next:"
echo "  1. Reopen Claude Code in:  $NEW_ABS"
echo "  2. In each repo, review + commit the path edits:"
echo "       git -C \"$NEW_ABS\" add -A && git -C \"$NEW_ABS\" commit -m 'Rename planning workspace Loop Specs -> $NEW'"
echo "       git -C \"$BASE/loopeix\" add -A && git -C \"$BASE/loopeix\" commit -m 'Update workspace path reference'"

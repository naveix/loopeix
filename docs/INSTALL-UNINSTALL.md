# Install & Uninstall

LoopSpec is a local-first CLI (`loopspec`). Install and uninstall are reversible; **your run data is
never deleted by uninstalling** — you delete it explicitly. This document states exactly what each
step touches (required by the redaction & retention policy).

## Install

```bash
# from the published package (once released)
npm install -g loopspec        # or: pnpm add -g loopspec

# from source (this repo)
pnpm install && pnpm build && npm link
```

What install creates:

- The `loopspec` binary on your `PATH` (via npm/pnpm global or `npm link`).
- **No global config or hidden home-directory state** is written on install.

Per-run state is created only when you run a loop, and lives **inside the workspace you run it in**
(e.g. a `.loopspec/` directory next to your project), never in your home directory. Nothing is sent
off your machine — LoopSpec uses the Codex/Claude CLIs' own auth and holds no API keys.

## Uninstall

```bash
npm uninstall -g loopspec       # or: pnpm remove -g loopspec
# from source: npm unlink -g loopspec
```

What uninstall **does** remove:

- The `loopspec` binary and its npm package files.

What uninstall **does NOT** remove (by design — it is your evidence):

- Any `.loopspec/` run data, ledgers, artifacts, reports, or quarantined items in your workspaces.

To remove run data yourself (irreversible):

```bash
rm -rf ./.loopspec              # in a workspace you want to wipe
```

## Retention (what ages out on its own)

| Class | Default | What |
|---|---|---|
| `short` | 7 days | Raw command output, raw adapter events, temporary captures. |
| `run` | until you delete the run | Gate results, evidence, reports, findings. |
| `project` | until you delete the workspace | LoopSpec versions, templates, approved retros. |
| `quarantine` | manual review required | Suspected secret captures / sensitive screenshots. |

`short`-class raw captures are eligible for automatic age-out after 7 days; everything else persists
until you explicitly delete the run or workspace. Quarantined items are **never** auto-deleted — you
review and remove them (`loopspec privacy list-quarantine`).

## Privacy commands

- `loopspec support bundle` — build a **redacted**, leak-scanned bundle safe to share for support.
- `loopspec privacy purge-run` — purge or tombstone one run per the retention policy.
- `loopspec privacy redact-artifact` — write a redacted replacement for one artifact.
- `loopspec privacy list-quarantine` — list quarantined evidence.

Redaction is conservative (privacy over completeness): it scrubs values under secret-like keys and
known secret patterns (provider keys, bearer tokens, DB URLs, PEM private keys), and every export is
leak-scanned before it leaves your machine. It cannot guarantee catching an unknown secret shape
under an innocuous key, so the report always states redaction limitations.

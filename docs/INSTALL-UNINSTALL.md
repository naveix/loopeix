# Install & Uninstall

Loopeix is a local-first CLI (`loopeix`). Install and uninstall are reversible; **your run data is
never deleted by uninstalling** — you delete it explicitly. This document states exactly what each
step touches (required by the redaction & retention policy).

## Install

```bash
# public package (currently 0.1.0; see the versioned release notes)
npm install -g loopeix        # or: pnpm add -g loopeix

# current unreleased source (currently 0.2.0-alpha.0)
pnpm install && pnpm build && npm link
```

The public package and the unreleased source do not have the same execution contract. Use
`loopeix --version`, then read the matching changelog and
[CLI reference](reference/cli.md) before relying on run behavior.

What install creates:

- The `loopeix` binary on your `PATH` (via npm/pnpm global or `npm link`).
- **No global config or hidden home-directory state** is written on install.

Per-run state is created only when you run a loop, and lives **inside the workspace you run it in**
(e.g. a `.loopeix/` directory next to your project), never in your home directory. Nothing is sent
off your machine by the current executable replay path. The unreleased source accepts captured
Codex/Claude events but does not start either provider, does not use their authentication, and holds
no provider API keys. Live provider execution remains deliberately fail-closed.

## Uninstall

```bash
npm uninstall -g loopeix       # or: pnpm remove -g loopeix
# from source: npm unlink -g loopeix
```

What uninstall **does** remove:

- The `loopeix` binary and its npm package files.

What uninstall **does NOT** remove (by design — it is your evidence):

- Any `.loopeix/` run data, ledgers, artifacts, reports, or quarantined items in your workspaces.

To remove run data yourself (irreversible):

```bash
rm -rf ./.loopeix              # in a workspace you want to wipe
```

## Retention policy (what becomes eligible for expiry)

| Class | Default | What |
|---|---|---|
| `short` | 7 days | Raw command output, raw adapter events, temporary captures. |
| `run` | until you delete the run | Gate results, evidence, reports, findings. |
| `project` | until you delete the workspace | Loopeix versions, templates, approved retros. |
| `quarantine` | manual review required | Suspected secret captures / sensitive screenshots. |

`short`-class raw captures become eligible for expiry after 7 days; the `isExpired` library helper
can make that policy decision. Nothing currently deletes them automatically. Everything persists
until you remove it yourself. Quarantined items are never expiry-eligible and require manual review.

## Privacy library and planned commands

The current library implements and tests `redact`, `scanForLeaks`, `buildSupportBundle`, and the pure
expiry predicate `isExpired`. It does **not** implement automatic deletion, purge/tombstone workflow,
artifact-replacement workflow, or quarantine listing. The following CLI surface is reserved for a
later contract and is intentionally absent today:

- Planned `loopeix support bundle` — expose the existing redacted, leak-scanned bundle builder.
- Planned `loopeix privacy purge-run` — purge or tombstone one run per the retention policy.
- Planned `loopeix privacy redact-artifact` — write a redacted replacement for one artifact.
- Planned `loopeix privacy list-quarantine` — list quarantined evidence.

Redaction is conservative (privacy over completeness): it scrubs values under secret-like keys and
known secret patterns (provider keys, bearer tokens, DB URLs, PEM private keys).
`buildSupportBundle` performs an independent leak scan before marking its result safe to share. It
cannot guarantee catching an unknown secret shape under an innocuous key, so the result states its
redaction limitations.

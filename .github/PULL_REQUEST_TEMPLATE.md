## What changed

<!-- One or two sentences. Link the issue if one exists. -->

## Proof it works

<!-- Loopeix's own rule applies to Loopeix PRs: claims need evidence.
     Paste the command(s) you ran and their real output — `pnpm test`, the golden-fixture
     validation, a seal→verify smoke — not a description of what would happen. -->

```
$ pnpm test
```

## Honesty checklist

- [ ] Tests pass locally (`pnpm test`) and no test was deleted, skipped, or weakened to get there
- [ ] New behaviour is covered by a test that fails without this change
- [ ] Anything this PR *cannot* prove is stated plainly above, not implied
- [ ] No secrets, tokens, personal paths, or unredacted transcripts (test fixtures use
      provider-canonical fake credentials only)

<!-- Agent-authored PRs are welcome — attach the Loopeix receipt (`loopeix pr <run-dir>`)
     and reviewers will verify it offline. Receipts or it didn't happen. -->

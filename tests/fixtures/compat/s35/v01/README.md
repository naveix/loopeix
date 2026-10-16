# S35 Frozen V01 Compatibility Oracles

Captured from clean detached implementation commit `13a8906fdd32b005d29c1eb07ee54f55f80c7fc2`.
Toolchain: Node `v26.0.0`, pnpm `11.9.0`, YAML `2.9.0`.
Reviewed source root: `/private/tmp/loopeix-s35-capture.QwUstp/source`.
Private execution source: `/private/tmp/loopeix-s35-capture.4peb36j1/loopeix-s35-source.ekbR2k` (tree SHA-256 `b39c914846cc73a42ffe82dc89bc82fc3ef3186331c6f35efafd8dfcb628cd6a`).
Staging root: `/private/tmp/loopeix-s35-capture.QwUstp/stage`.
V01 capture driver: `/Users/naviix/Work/Projects/loopeix/scripts/capture-v01-oracles-s35.ts` (SHA-256 `ad1e7c54572469d8ae227337ec99dd44b66bb24d0635d66b50c8aa47ead33fb0`).
Package capture driver: `/Users/naviix/Work/Projects/loopeix/scripts/capture-s35-package-oracles.mjs` (SHA-256 `c9c525d24f343e37b230547c5ee8d31e49dbee60c30a09db259f708c251f5927`).
Clean process launcher: `/Users/naviix/Work/Projects/loopeix/scripts/run-s35-capture-clean.sh` (SHA-256 `c614851287f64f0e01cf8430645b57e2ac694caf9cfb8bb525e84fcde84759c6`).

Oracle directories contain only their declared raw input/output members. Provenance lives separately under
provenance/. Tests must read committed bytes directly and never regenerate expected
output with the compiler under test.
The credential-shaped case deliberately omits its prompt from metadata and documentation.
The run-recover-zero-complete-event/ subtree freezes detached baseline bin/dev.js run recover output.
Cases: empty, blank-only, partial-only.
Each case contains: human.exit, human.stderr, human.stdout, json.exit, json.stderr, json.stdout, ledger.jsonl.
Human and --json stdout, stderr, and integer exit files are captured without byte normalization.

Capture command:

```text
"/Users/naviix/Work/Projects/loopeix/scripts/run-s35-capture-clean.sh" node "/Users/naviix/Work/Projects/loopeix/scripts/launch-v01-oracles-s35.mjs" --driver "/Users/naviix/Work/Projects/loopeix/scripts/capture-v01-oracles-s35.ts" --source-root "/private/tmp/loopeix-s35-capture.QwUstp/source" --out "/private/tmp/loopeix-s35-capture.QwUstp/stage" --assert-base-commit 13a8906fdd32b005d29c1eb07ee54f55f80c7fc2
```

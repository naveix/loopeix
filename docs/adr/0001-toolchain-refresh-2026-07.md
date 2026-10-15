# ADR 0001 — Toolchain refresh (verified 2026-07-02)

Status: Accepted — confirms the planning-workspace stack with three concrete updates.

Maintenance amendment (2026-10-15): security patch releases advanced pnpm to **11.11.0** and
Vitest to **4.1.11** without changing the decisions below. Exact transitive overrides are maintained
in `pnpm-workspace.yaml`.

## Context

The Loopeix planning workspace locked a stack (TypeScript ESM, pnpm, oclif `@oclif/core`,
Zod 4 → generated JSON Schema, Vitest, `npm-shrinkwrap.json`, npm provenance). Before writing
S6/S7 code we re-validated every choice against **current** sources on 2026-07-02 via three
parallel research lanes (Context7 for library docs; nodejs.org release schedule; npm/pnpm docs).
The original decisions were verified on 2026-07-02. Versions explicitly changed by the 2026-10-15
maintenance amendment are live as of that amendment and supersede their original pins. All versions
MUST be re-checked at install time, not quoted from memory.

## Confirmed (no change)

- `@oclif/core` **v4** (4.11.14) — full ESM (`"type":"module"`, NodeNext), topic-directory
  multi-command layout, internal hooks only. Correct.
- **Zod 4** (4.4.3) is the schema source of truth; generate JSON Schema **from** Zod. Correct.
- **Vitest 4** (4.1.11) for unit/fixture/golden tests. Correct. Do NOT adopt Vitest 5 for V1.
- `npm-shrinkwrap.json` is still the documented mechanism for a **global CLI** (not deprecated;
  discouraged only for libraries). Keep it.
- pnpm for source builds; exact-pin direct runtime deps. Correct.

## Decisions / updates

### D1 — `engines.node`: support the tested even-major lines
Use `">=22.12.0 <23 || >=24 <25 || >=26 <27"`. This accepts the Node 22 floor plus the tested Node
24 and 26 lines while rejecting untested odd majors and future majors. As of 2026-07: Node 24
"Krypton" = Active LTS (→ Maintenance 2026-10-20), Node 26 = Current (→ Active LTS 2026-10-28),
and Node 22 "Jod" = Maintenance LTS (EOL 2027-04-30). Floor `22.12` is correct (first v22 with
stable `require(esm)`). CI covers Node 22.12 / 24 / 26.

### D2 — Zod → JSON Schema: native `z.toJSONSchema`, two-layer invariants
- Use the built-in `z.toJSONSchema(schema, { target: "draft-2020-12", unrepresentable: "throw", reused: "ref" })`.
  Do NOT add `zod-to-json-schema` (legacy / Zod 3).
- Zod does NOT emit a root `$schema` dialect or `$id` — inject them in the `override` callback (or a
  post-generation wrapper). This satisfies the "declare dialect, `$id`, schema version" rule.
- Keep `unrepresentable: "throw"` in CI: it makes a non-serializable public schema fail the build,
  enforcing "no `transform()` / non-serializable `refine()` as the only expression of a constraint".
- **Two-layer validation is expected**: express invariants structurally where possible
  (`z.discriminatedUnion`, `z.enum`, `z.literal`) so they land in JSON Schema natively; keep genuinely
  relational invariants as a Zod `.refine()` **runtime second pass** and, only if external consumers
  must see them, mirror into JSON Schema via `override` (`if/then`, `not`, `dependentSchemas`).
  Example encodings: "blocking gate needs an evidence rule" → discriminated union on `blocking`;
  "forbidden context cannot also be required" → object-level `.refine()` (set-disjointness has no clean
  JSON Schema form).
- **Golden-test the EMITTED JSON Schema** (not just the Zod schema) against the S5 valid/invalid
  fixtures, so structural constraints and any `override`-injected keywords stay honest. Custom
  `.refine()` predicates are silently DROPPED from JSON Schema output — a generator unit test must
  assert expected keywords are present.

### D3 — TypeScript 6.0.x config (updates older NodeNext advice)
Current stable is **TypeScript 6.0.3** (TS 7 native compiler is RC — not yet). Baseline tsconfig:
`module`/`moduleResolution: "nodenext"`, `target: "es2024"`, `strict: true`, `verbatimModuleSyntax: true`,
`noUncheckedIndexedAccess: true`, **`types: ["node"]`** (TS 6 defaults `types: []` — Node globals vanish
otherwise), `rootDir: "./src"`, `declaration: true`, `erasableSyntaxOnly: true`. Pin `@types/node`
exactly to **22.20.0**, the oldest supported runtime line, so compilation cannot silently adopt a
newer Node API unavailable at the declared floor. Turn on `noUncheckedIndexedAccess` at the S7
skeleton, not mid-build.

## Packaging / supply chain (S7 + S16)

- Packed-tarball smoke = **`pnpm pack`** (the npm `.tgz`), NOT `oclif pack tarballs` (that builds
  node-embedded standalone bundles). `oclif manifest` runs in `prepack` and is listed in `files` so
  it ships inside the tarball. Then: install the tgz into a temp
  prefix and run `loopeix --version`, `loopeix doctor`, one fixture command.
- Publishing: **Trusted Publishing (OIDC) from GitHub Actions** (npm ≥ 11.5.1, Node ≥ 22.14 on the
  runner, `permissions: id-token: write`, no `NPM_TOKEN`). The privileged job receives only a
  digest-bound tarball from an unprivileged verification job and invokes `npm publish --provenance`
  explicitly. `npm-shrinkwrap.json` is committed and its deterministic npm view is guarded in CI;
  the release workflow publishes the already-verified tarball rather than regenerating dependency
  state under OIDC authority.
- pnpm **11** (11.11.0): reject unreviewed dependency build scripts with `allowBuilds` + `strictDepBuilds: true`
  (the old `onlyBuiltDependencies` keys were removed); pin via `packageManager`. npm **v12** (imminent)
  disables install scripts by default — adopt the `ignore-scripts` / `npm approve-scripts` posture now.
- Provenance proves build origin, NOT code safety (see the 2026 "Mini Shai-Hulud" trojaned-with-valid-
  provenance incident). Pair provenance with exact pins, release cooldown (`min-release-age` /
  `minimumReleaseAge`), `npm audit signatures`, an SBOM, and a `files` allowlist.

### Temporary upstream dependency exception (reviewed 2026-10-15)

`pnpm audit` reports one high-severity development-only path:
`oclif → find-yarn-workspace-root → micromatch → braces@3.0.3`. The advisory names `braces@3.0.4`
as the patched floor, but npm has not published that version; current oclif 6 retains the same
dependency chain. No runtime dependency or packed product path uses this package. Dependabot remains
enabled, and this exception must be removed as soon as a real patched upstream path is published.

## Sources (retrieved 2026-07-02)

- Node: nodejs.org release schedule.json; nodejs.org/en/about/previous-releases; v22.12.0 release notes.
- Zod: zod.dev/json-schema; zod.dev/v4. TypeScript: typescriptlang.org TS 6.0 release notes; Node type-stripping docs.
- oclif: oclif.io/docs/esm, configuring_your_cli, releasing; hello-world-esm template. Vitest: vitest.dev migration + snapshot guides.
- npm: docs.npmjs.com/trusted-publishers, npm-shrinkwrap-json; github.blog npm v12 changes. pnpm: pnpm.io/blog/releases/11.0, settings.

## Re-check at install time

Before `pnpm install`, re-query live: `@oclif/core`, `oclif`, `zod`, `vitest`, `typescript`, `@types/node`,
`pnpm`, and the Node LTS status. Pin exact versions in `package.json` from those live results.

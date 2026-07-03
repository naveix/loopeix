# Loopeix North-Star Architecture

> The companion to `hardening-plan.md`. The hardening plan makes every claim the system *already
> renders* become true. This doc is the longer arc: the shape that turns a solid local audit tool into
> **a portable standard for proving what an AI agent did** — evidence any security team can verify with
> `cosign`, no Loopeix installed. Grounded in current specs (in-toto v1.2.0 · DSSE v1.0.2 · SLSA v1.2 ·
> Rekor v2 GA · RFC 8785 · OTel GenAI semconv · DBOS SQLite durable execution, all 2025–2026).

## The vision in one sentence

A Loopeix run seals into a single, standard, signed file that **anyone can verify independently** — and
because nobody has minted an agent-run attestation predicate yet (in-toto registry, mid-2026), Loopeix
can be the one that defines it. That is the difference between "a nice tool" and "the format."

## The core idea: two layers, cleanly separated

The whole architecture rests on one separation that keeps two properties that usually fight:

- **Layer 1 — Local Truth (fast, offline, authoritative).** The bespoke hash-chained `ledger.jsonl`
  stays the on-machine source of truth. No open standard covers *hash-chained event logs for agent
  runs*, and none is needed. It never leaves the machine unless you ask.
- **Layer 2 — Portable Proof (interoperable, independently verifiable).** At run completion, the run is
  *projected* into a standard signed attestation. This is what travels, what an auditor checks, what an
  ecosystem trusts — without Loopeix code and without the ledger ever ceding authority to a server.

You keep the speed and privacy of local-first **and** gain ecosystem legibility. Every decision below
serves this separation.

---

## Layer 1 — pin the ledger to a real standard: RFC 8785 (JCS)

**Problem it closes.** Today canonicalization is a bespoke sorted-key `JSON.stringify`. It is
deterministic *here*, but a non-Node verifier (or a future Rust port, or a third party checking your
evidence — the entire point of tamper-evidence is that *someone else* can check) cannot confidently
re-derive the hashes. That is a silent ceiling on independent verification.

**The move.** Make each event's hash input the **RFC 8785 (JSON Canonicalization Scheme)** serialization,
and make the *stored line bytes* be those exact JCS bytes — so `hash(stored bytes) == hash(canonical
form)` and any third party can replay the chain from a published spec. The current implementation is
~95% of JCS already, so this is a library swap, not a redesign, and it **also closes the byte-level
tamper gap (hardening-plan P0.4) for free** — duplicate-key / whitespace tricks can no longer survive.

**Constraints JCS imposes (the schema already complies — verify at implementation):**
- Timestamps, ids, and hashes stay strings (`IsoTimestamp`, `sha256:<hex>` — already strings). ✓
- Every number must be IEEE-754-double-safe (`< 2^53`, no `NaN`/`Infinity`) — beyond `2^53` precision
  loss is *silent*, so keep counts/sequences in range and never serialize a raw bigint (I-JSON: as a
  string).
- No unicode normalization is ever applied to stored strings.
- Use a **vetted JCS library + the RFC 8785 test vectors** as fixtures — never hand-rolled sort-and-stringify.

---

## Layer 2 — seal every run as an in-toto attestation

**The artifact.** At run completion, emit `<run-dir>/run.attestation.sigstore.json`:

- **Statement** — `_type: "https://in-toto.io/Statement/v1"`; **subject** = ResourceDescriptors with
  sha256 digests of `report.json`, `run-manifest.json`, `artifact-manifest.json`, and the post-run git
  state (`gitCommit` is a registered in-toto digest algorithm).
- **predicateType** — `https://loopeix.dev/attestation/run-evidence/v1` (a versioned URI that resolves
  to a human-readable spec, per in-toto's new-predicate guidelines). **predicate** carries: run identity
  (`run_id`, `loop_family`, `loop_version`, `schema_version`), runner + adapter + model versions, the
  ledger anchor `{ head: "sha256:…", events: N, canonicalization: "RFC8785" }`, and `gates[]` — each gate
  with spec id, PASS/HOLD/FAIL verdict, blocking flag, and evidence as digest references. (Borrow the
  shape of in-toto **SCAI v0.3** attribute assertions for the `gates[]` encoding.)
- **DSSE envelope (v1.0.2)** — `payloadType: "application/vnd.in-toto+json"`, signature over
  `PAE("DSSEv1"…)` with the local key. **This *is* the planned Ed25519 head signature** — because the
  predicate contains the ledger head, signing the Statement seals the entire chain. One envelope,
  standard shape, threshold/multi-sig for free later (a run co-signed by machine key *and* CI key).
- **Sigstore bundle** wrapper (`sigstore/protobuf-specs`) so mainstream verifiers consume it directly.
  Node side: **`sigstore-js`** provides bundle + DSSE plumbing.

**Independent verification — zero Loopeix installed:**

```
cosign verify-blob-attestation \
  --key loopeix.pub --bundle run.attestation.sigstore.json \
  --type https://loopeix.dev/attestation/run-evidence/v1 \
  --insecure-ignore-tlog \
  report.json
```

…then any implementation of the published ledger spec replays the JCS hash chain up to the attested head.

**SLSA as a second, optional statement.** Emit a second Statement with
`predicateType: https://slsa.dev/provenance/v1` and a `buildType: https://loopeix.dev/buildtype/loop-run/v1`
— same subjects, same envelope — so SLSA-native tooling reads it. **Market it as "SLSA-style
provenance," never a certified level:** Build L2/L3 require signed provenance from a *hosted, hardened*
platform; a local tool can honestly self-attest an L1-shape only.

**Why this is the beautiful move, not just a feature:** GitHub Artifact Attestations (GA 2024) and
OpenSSF Model Signing v1.0 (Apr 2025, NVIDIA signing its model catalogue) both chose *exactly* this
stack (in-toto + DSSE + Sigstore bundle), and in-toto **Witness** (CNCF) already attests generic CLI
runs this way. So "Witness for AI coding loops" is a pitch security teams already understand — and the
agent-run predicate is unclaimed. Loopeix can define and (later) donate it.

**One key-management caveat to test, not assume:** cosign's documented PEM import covers RSA/EC only, so
either default the *interop* key to **ECDSA P-256** (the ecosystem default) or smoke-test the Ed25519
cosign path end-to-end first. DSSE and the Sigstore bundle both support Ed25519; the CLI path is the
unverified link.

---

## The anchoring ladder — the honest answer to "attacker with the key"

The headline limitation stays true and must keep being stated: a signed local chain is
**tamper-evident + signer-bound, not tamper-proof** — someone with your key and disk can re-seal.
You cannot fix that purely locally. Anchoring is the credible fix, offered as an **opt-in ladder** so
local-first stays the default:

| Rung | Command | What it proves | Cost |
|---|---|---|---|
| 0 (default) | — | Tamper-evident against everyone **except** the key holder — stated honestly | none |
| 1 | `loopeix anchor --tsa <url>` | An **RFC 3161** signed timestamp: the head existed by time T | one HTTPS call, leaks only a hash |
| 2 | `loopeix anchor --rekor` | Public **Rekor v2** (GA Oct 2025) transparency-log inclusion | network + metadata in a public log |
| 3 (teams) | self-hosted `rekor-tiles` | A private witness the org controls | run a cheap service |

Discover Rekor shard URLs via Sigstore's TUF signing config (they rotate yearly — never hardcode).

---

## Runtime substrate — from *record* to *recovery log*

The ledger is already event-sourcing done right (the same primitive Temporal/Restate/DBOS converged
on). Today it *records what happened* (perfect for attestation) but does not yet *guarantee resume*.
Closing that is one discipline, not a rewrite:

- **Substrate:** put **SQLite in WAL mode** under the ledger as the transactional durable write path.
  DBOS shipped exactly this embeddable pattern in March 2026 — it is first-class, not a hack: durable
  state, no separate service, no network hop. The hash-chained JSONL becomes the **exportable,
  tamper-evident *projection*** on top (a materialized view). You get transactional durability **and**
  portable attestation.
- **Resume rule:** *checkpoint-before-side-effect + idempotent steps.* Record a step's completion before
  its irreversible action commits; on resume, replay the log, skip completed steps, re-run only pending
  ones. (This is hardening-plan P1.2, now with a substrate.)
- **Don't** adopt Temporal/Restate/an external durable engine for the local product. The one thing that
  would justify it — unattended/scheduled ("T5") execution — Loopeix refuses by design. In an eventual
  hosted team mode, the minimal step is **DBOS on Postgres**, never a heavy orchestrator.

One writer per run means the concurrency problem the durable-execution literature warns about never
arises.

---

## The one outbound seam — OpenTelemetry GenAI conventions

Expose **exactly one** optional outbound projection: each ledger entry → **OTLP spans** conforming to
the (now industry-converged) OTel GenAI/agent conventions (`invoke_agent`, `execute_tool`,
`gen_ai.usage.*`). Why this is *the* seam and not a proprietary API:

- The local signed ledger stays **authoritative and on-machine**; OTLP is an *optional feed*, never the
  source of truth.
- A future hosted/team layer **ingests it with zero bespoke protocol** — this is the exact mechanism
  that makes open-core aggregation buildable without betraying local-first.
- It makes Loopeix **feed** Langfuse / Phoenix / Datadog instead of competing with them.

Map at *export* time; **never bake OTel into the ledger schema** — GenAI semconv is still
Development-status (moved repos, one breaking change already). The ledger is the stable core; the
exporter is the version-pinned edge.

---

## How this lands against the current code (minimal, additive)

| North-star piece | Where it lands | Shape of change |
|---|---|---|
| RFC 8785 JCS | `src/hash.ts` | swap `canonicalize` for a vetted JCS lib + RFC test-vector fixtures; version via `manifest.canonicalization` |
| Attestation layer | new `src/attest/` + a new schema alongside `run-manifest` | build Statement/predicate; DSSE + bundle via `sigstore-js`; write `run.attestation.sigstore.json` |
| Signing | **replaces** hardening-plan P0.3's bespoke sig | signing the Statement *is* the head signature |
| `loopeix verify` / `loopeix anchor` | new commands | verify bundle + replay chain; anchor ladder |
| SQLite substrate + resume | `src/run/` (P1) | WAL write path; JSONL becomes projection |
| OTLP exporter | deferred `src/export/otel.ts` | optional, version-pinned |

**Nothing here rewrites the reviewed core.** The ledger, gates, evidence verifier, redaction, and
run-execution layer stay exactly as built and reviewed; JCS + attestation are a *formatting and sealing*
layer added at the edges, and SQLite is a *substrate* the existing pure `assembleRun` projects onto.

---

## Revised sequencing (fuses the hardening plan with this vision)

The ordering rule is unchanged — **make every claim true, then make it standard, then make it durable** —
but JCS moves to the front because it is the foundation everything signed sits on:

1. **RFC 8785 JCS** (P2.6, promoted) — the canonical form everything else attests to.
2. **Claim↔evidence linkage** (P0.1) — the product's missing heart: a real run must *verify* claims.
3. **Wire the unwaivable gates** (P0.2) — truthfulness/evidence-integrity/secrets-privacy live in the run.
4. **Attestation layer** (in-toto Statement + DSSE + Sigstore bundle) — *replaces* bespoke signing;
   `loopeix verify`.
5. **Anchoring ladder** (TSA → Rekor) — the honest key-holder fix, opt-in.
6. **SQLite substrate + resume** (P1) — record becomes recovery log.
7. **OTLP export** — the one seam, last, because it's optional and version-volatile.

---

## Honest limits (kept loud, per the project's own discipline)

- **Tamper-evident + signer-bound, not tamper-proof** — until anchored. Anchoring touches the network,
  so it is opt-in and the offline default says so.
- **SLSA-*style*, never a certified level** on a laptop.
- **The agent-run predicate is new** — design it to be *donatable* to the in-toto registry / OpenSSF; if
  a public standard emerges (watch OpenSSF AI/ML WG, CoSAI), converge on it.
- **OTel GenAI is unstable** — export-only, pinned, never in the ledger schema.

## The strategic payoff (why this is the same question as "what does it become")

Bespoke evidence caps Loopeix at "a nice local tool." **This two-layer shape unlocks Arc A** (from the
licensing analysis): a run becomes a portable, `cosign`-verifiable artifact — *the way you prove what an
AI agent did* — under an ISO 42001 / SOC2-for-AI framing, feeding an optional open-core aggregation layer
through the OTel seam. Attestation, not observability. And the one posture the entire cloud-observability
field cannot copy without abandoning its own model — **refusing unattended runs and keeping code on the
machine** — is exactly the trust guarantee this architecture is built to sign.

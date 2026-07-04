#!/usr/bin/env node
// Compile personas.jsonl into runnable Harbor tasks under shadow/generated/<id>-<mission>/.
// Each task = task.toml + instruction.md + environment/Dockerfile + solution/solve.sh + tests/test.sh
// per shadow/CONTRACT.md §3-4. Fixtures + tarball are staged later by prep.sh (gitignored).
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const repo = join(here, "..", "..");
const OUT = join(root, "generated");      // Tier-0 tasks (scripted oracle personas)
const OUT_T1 = join(root, "generated-t1"); // Tier-1 tasks (live cheap-model personas; separate dir so a Tier-0 wave can never accidentally include them)

// Expected fixture counts, read from the repo at generate time and baked into the oracles as
// hard floors. This closes the empty-glob false-green: if staging drops the fixtures, the loop
// runs fewer times than the floor and the oracle FAILS instead of vacuously passing.
const yamlCount = (p) => (existsSync(p) ? readdirSync(p).filter((f) => f.endsWith(".yaml")).length : 0);
const EXP_VALID = yamlCount(join(repo, "tests/fixtures/valid/specs"));
const EXP_INVALID = yamlCount(join(repo, "tests/fixtures/invalid/specs"));
// A missing/renamed fixture dir at generate time would bake 0 floors and make every floor check
// vacuous (review finding, P2) — refuse to generate against an empty corpus.
if (EXP_VALID < 1 || EXP_INVALID < 1) {
  console.error(`FATAL: fixture corpus empty at generate time (valid=${EXP_VALID}, invalid=${EXP_INVALID}) — check tests/fixtures/{valid,invalid}/specs`);
  process.exit(1);
}
const FUZZ_N = 24; // mutations requested per fuzz persona; oracle requires exactly this many ran

// Persona corpus is an INPUT FILE (--personas): treat every string it carries as untrusted before
// interpolating it into instruction.md / task.toml / oracles — a crafted corpus must not be able
// to inject instructions into a (live-auth) Tier-1 container (review finding, P1). Charset is a
// whitelist; lengths bounded; numerics range-checked; enums closed.
const SAFE_STR = /^[A-Za-z0-9 ._:/-]+$/;
const FAULTS_ALLOWED = new Set(["none", "skip-build", "wrong-workspace", "stale-tarball"]);
function validatePersona(p) {
  const die = (msg) => { console.error(`FATAL: persona ${p && p.id ? p.id : "<no id>"}: ${msg}`); process.exit(1); };
  if (!/^p\d{4}$/.test(p.id || "")) die("bad id (expect pNNNN)");
  const strs = { archetype: p.archetype, occupation: p.identity?.occupation, experience: p.identity?.experience, os_pref: p.identity?.os_pref, node: p.env_cell?.node, base: p.env_cell?.base, shell: p.env_cell?.shell, mission: p.mission };
  for (const [k, v] of Object.entries(strs)) {
    if (typeof v !== "string" || !v.length || v.length > 64 || !SAFE_STR.test(v)) die(`unsafe or missing string field '${k}': ${JSON.stringify(v)}`);
  }
  const b = p.behaviour || {};
  if (typeof b.docs_read_ratio !== "number" || !(b.docs_read_ratio >= 0 && b.docs_read_ratio <= 1)) die("docs_read_ratio out of [0,1]");
  if (!Number.isInteger(b.patience_turns) || b.patience_turns < 1 || b.patience_turns > 24) die("patience_turns out of [1,24]");
  if (typeof b.adversarial !== "boolean") die("adversarial must be boolean");
  if (!Array.isArray(b.fault_injection) || !b.fault_injection.every((f) => FAULTS_ALLOWED.has(f))) die("fault_injection outside allowed set");
  if (!Number.isInteger(p.seed) || p.seed < 0) die("bad seed");
  if (![0, 1, 2].includes(p.tier)) die("bad tier");
}

const dockerfile = (base, extraPkgs = "") => `FROM ${base}
COPY loopeix-0.0.0.tgz /opt/loopeix.tgz
COPY fixtures /opt/fixtures
RUN npm install -g /opt/loopeix.tgz && loopeix --version${extraPkgs ? ` && apt-get update && apt-get install -y ${extraPkgs} && rm -rf /var/lib/apt/lists/*` : ""}
WORKDIR /app
`;

// Shared bash preamble for oracles: a SAFE key=value reader (never `source`s the agent-writable
// exits.env — that would execute attacker-controlled content in the verifier at tier 1/2), plus a
// fail() that emits a machine CODE token the curator classifies on (not prose).
const ORACLE_HEAD = `#!/bin/bash
set -u; mkdir -p /logs/verifier
fail(){ echo "ORACLE FAIL [$1]: $2"; echo 0 > /logs/verifier/reward.txt; exit 0; }
getv(){ grep -m1 "^$1=" /app/out/exits.env 2>/dev/null | cut -d= -f2-; }
`;
// Robust single run-dir extraction (nullglob-safe, first match, quoted).
const RUNDIR = `shopt -s nullglob; RD=$(ls -d "$WS"/.loopeix/runs/*/ 2>/dev/null | head -1); RD=\${RD%/}`;

// --- persona solve.sh per mission. Behaviour params are metadata at tier 0 (the oracle runs a
//     fixed per-mission script); they drive tier-1 LLM personas. See CONTRACT.md §1. ---
const solve = {
  "docile-install": () => `#!/bin/bash
set -u
OUT=/app/out; WS=/app/work; mkdir -p "$OUT" "$WS"
loopeix doctor >"$OUT/doctor.txt" 2>&1; echo "exit_doctor=$?" >>"$OUT/exits.env"
loopeix run start /opt/fixtures/seal-loop.yaml --engine codex --events-file /opt/fixtures/snitch-events.jsonl --seal /opt/fixtures/snitch-brief.yaml --workspace "$WS" >"$OUT/run.txt" 2>&1
echo "exit_run=$?" >>"$OUT/exits.env"
${RUNDIR}; echo "run_dir=$RD" >>"$OUT/exits.env"
loopeix verify "$RD/receipt.json" --run-dir "$RD" >"$OUT/verify.txt" 2>&1; echo "exit_verify=$?" >>"$OUT/exits.env"
loopeix pr "$RD" --card "$OUT/delta-card.svg" >"$OUT/pr.txt" 2>&1; echo "exit_pr=$?" >>"$OUT/exits.env"
`,
  "docs-followability": () => `#!/bin/bash
set -u
OUT=/app/out; mkdir -p "$OUT"
# Walkthrough L1. Each check records BOTH the exit code AND whether the fixture existed, so the
# oracle can tell a real rejection from a missing file (which also exits non-zero).
chk(){ local tag=$1 f=$2; [ -f "$f" ] && echo "have_$tag=1" >>"$OUT/exits.env" || echo "have_$tag=0" >>"$OUT/exits.env"; loopeix verify "$f" >"$OUT/$tag.txt" 2>&1; echo "exit_$tag=$?" >>"$OUT/exits.env"; }
chk good1 /opt/fixtures/snitch.receipt.json
chk good2 /opt/fixtures/clean-pass.receipt.json
chk bad1  /opt/fixtures/snitch.tampered-verdict.receipt.json
chk bad2  /opt/fixtures/snitch.bad-signature.receipt.json
chk bad3  /opt/fixtures/snitch.uncited-contradiction.receipt.json
`,
  "adversarial-tamper": () => `#!/bin/bash
set -u
OUT=/app/out; WS=/app/work; mkdir -p "$OUT" "$WS"
loopeix run start /opt/fixtures/seal-loop.yaml --engine codex --events-file /opt/fixtures/clean-events.jsonl --seal /opt/fixtures/clean-brief.yaml --workspace "$WS" >"$OUT/seal.txt" 2>&1
echo "exit_seal=$?" >"$OUT/exits.env"
${RUNDIR}; echo "run_dir=$RD" >>"$OUT/exits.env"
loopeix verify "$RD/receipt.json" --run-dir "$RD" >"$OUT/baseline.txt" 2>&1; echo "exit_baseline=$?" >>"$OUT/exits.env"
# guard(): a forgery counts only if the forged file exists, is non-empty, and differs from the original.
guard(){ { [ -s "$2" ] && ! cmp -s "$1" "$2"; } && echo "$3=1" >>"$OUT/exits.env" || echo "$3=0" >>"$OUT/exits.env"; }
A=/app/a1; mkdir -p "$A"; cp -r "$RD"/. "$A"/; sed -i 's/UNEVALUATED/KEPT/g; s/UNSUPPORTED/VERIFIED/g' "$A/receipt.json"
guard "$RD/receipt.json" "$A/receipt.json" atk1_changed
loopeix verify "$A/receipt.json" --run-dir "$A" >"$OUT/a1.txt" 2>&1; echo "exit_atk1=$?" >>"$OUT/exits.env"
B=/app/a2; mkdir -p "$B"; cp -r "$RD"/. "$B"/; sed -i 's/payments/paymentz/g' "$B/ledger.jsonl"
guard "$RD/ledger.jsonl" "$B/ledger.jsonl" atk2_changed
loopeix verify "$B/receipt.json" --run-dir "$B" >"$OUT/a2.txt" 2>&1; echo "exit_atk2=$?" >>"$OUT/exits.env"
C=/app/a3; mkdir -p "$C"; cp -r "$RD"/. "$C"/; head -c 200 "$RD/receipt.json" > "$C/receipt.json"
guard "$RD/receipt.json" "$C/receipt.json" atk3_changed
loopeix verify "$C/receipt.json" --run-dir "$C" >"$OUT/a3.txt" 2>&1; echo "exit_atk3=$?" >>"$OUT/exits.env"
D=/app/a4; mkdir -p "$D"; cp -r "$RD"/. "$D"/
# assert there is at least one VERIFIED verdict to downgrade, else the attack is vacuous.
nverified=$(jq '[.claims[]|select(.verdict=="VERIFIED")]|length' "$RD/receipt.json" 2>/dev/null || echo 0)
echo "atk4_nverified=$nverified" >>"$OUT/exits.env"
jq '(.claims[] | select(.verdict=="VERIFIED") | .verdict)="CONTRADICTED"' "$RD/receipt.json" > "$D/receipt.json" 2>"$OUT/a4.txt"
guard "$RD/receipt.json" "$D/receipt.json" atk4_changed
loopeix verify "$D/receipt.json" --run-dir "$D" >>"$OUT/a4.txt" 2>&1; echo "exit_atk4=$?" >>"$OUT/exits.env"
`,
  "spec-corpus": () => `#!/bin/bash
set -u; shopt -s nullglob
OUT=/app/out; mkdir -p "$OUT"
: > "$OUT/valid.env"; : > "$OUT/invalid.env"
# Capture the exit code into a var IMMEDIATELY — a command substitution like $(basename ...) would
# otherwise run first and reset $? to basename's (0) exit, masking the validator's real result.
for f in /opt/fixtures/specs/valid/*.yaml; do
  loopeix spec validate "$f" >/dev/null 2>&1; code=$?; b=$(basename "$f"); echo "$b=$code" >>"$OUT/valid.env"
done
for f in /opt/fixtures/specs/invalid/*.yaml; do
  loopeix spec validate "$f" >/dev/null 2>&1; code=$?; b=$(basename "$f"); echo "$b=$code" >>"$OUT/invalid.env"
done
`,
  "fuzz-receipt": (p) => `#!/bin/bash
set -u; shopt -s nullglob
OUT=/app/out; WS=/app/work; mkdir -p "$OUT" "$WS"
loopeix run start /opt/fixtures/seal-loop.yaml --engine codex --events-file /opt/fixtures/snitch-events.jsonl --seal /opt/fixtures/snitch-brief.yaml --workspace "$WS" >"$OUT/seal.txt" 2>&1
echo "exit_seal=$?" >"$OUT/exits.env"
${RUNDIR}; echo "run_dir=$RD" >>"$OUT/exits.env"
# Baseline: the honest sealed receipt MUST verify, else the fuzz result proves nothing.
loopeix verify "$RD/receipt.json" --run-dir "$RD" >"$OUT/baseline.txt" 2>&1; echo "exit_baseline=$?" >>"$OUT/exits.env"
node /opt/fixtures/fuzz.mjs "$RD/receipt.json" ${p.seed} ${FUZZ_N} /app/fuzz >"$OUT/fuzz-gen.txt" 2>&1
echo "exit_fuzzgen=$?" >>"$OUT/exits.env"
accepts=0; total=0
for m in /app/fuzz/*.json; do
  total=$((total+1))
  MD=/app/fz_$total; mkdir -p "$MD"; cp -r "$RD"/. "$MD"/; cp "$m" "$MD/receipt.json"
  if loopeix verify "$MD/receipt.json" --run-dir "$MD" >/dev/null 2>&1; then accepts=$((accepts+1)); echo "ACCEPTED: $(basename "$m")" >>"$OUT/fuzz-accepts.txt"; fi
done
echo "fuzz_total=$total" >>"$OUT/exits.env"; echo "fuzz_accepts=$accepts" >>"$OUT/exits.env"
`,
};

// --- deterministic oracles (bash, no network, no installs). All read exits.env via getv (never
//     source), default missing values to a FAILING value, and emit a CODE token on failure. ---
const oracle = {
  "docile-install": () => `${ORACLE_HEAD}[ -f /app/out/exits.env ] || fail no-run "persona never ran"
for k in exit_doctor exit_run exit_verify exit_pr; do v=$(getv "$k"); [ "$v" = "0" ] || fail crash "$k=\${v:-missing}"; done
grep -q VERIFIED /app/out/verify.txt || fail crash "no VERIFIED"
grep -q PROMISE_BROKEN /app/out/run.txt || fail crash "no PROMISE_BROKEN"
grep -q UNSUPPORTED /app/out/run.txt || fail crash "no UNSUPPORTED"
grep -q "PROMISE BROKEN" /app/out/pr.txt || fail crash "no PR row"
[ -s /app/out/delta-card.svg ] || fail crash "no card"
rd=$(getv run_dir); [ -n "$rd" ] && [ -f "$rd/receipt.json" ] || fail crash "no receipt at '\${rd:-missing}'"
echo "ORACLE PASS: docile on node $(node -v)"; echo 1 > /logs/verifier/reward.txt
`,
  "docs-followability": () => `${ORACLE_HEAD}[ -f /app/out/exits.env ] || fail no-run "persona never ran"
# Every fixture must have existed (else a missing file's non-zero exit would masquerade as a rejection).
for t in good1 good2 bad1 bad2 bad3; do [ "$(getv have_$t)" = "1" ] || fail missing-fixture "fixture $t absent — cannot judge"; done
[ "$(getv exit_good1)" = "0" ] || fail false-reject "good snitch receipt did not verify"
[ "$(getv exit_good2)" = "0" ] || fail false-reject "good clean-pass receipt did not verify"
# A real rejection prints NOT VERIFIED; a file-not-found error does not. Require the real reason.
for t in bad1 bad2 bad3; do
  [ "$(getv exit_$t)" != "0" ] || fail false-accept "$t verified (false-accept, P0)"
  grep -q "NOT VERIFIED" "/app/out/$t.txt" || fail false-accept "$t rejected for the WRONG reason (no NOT VERIFIED line) — P0"
done
echo "ORACLE PASS: good receipts verify; tampered ones rejected with the right reason"; echo 1 > /logs/verifier/reward.txt
`,
  "adversarial-tamper": () => `${ORACLE_HEAD}[ -f /app/out/exits.env ] || fail no-run "persona never ran"
[ "$(getv exit_seal)" = "0" ] || fail crash "seal (run start) failed"
[ "$(getv exit_baseline)" = "0" ] || fail false-reject "honest receipt did not verify"
[ "$(getv atk4_nverified)" -ge 1 ] 2>/dev/null || fail crash "no VERIFIED verdict to downgrade — atk4 vacuous"
for g in atk1_changed atk2_changed atk3_changed atk4_changed; do [ "$(getv "$g")" = "1" ] || fail crash "$g vacuous (forgery did not change bytes)"; done
# Fail-CLOSED: a missing exit var (timeout mid-write) defaults to 0 => 'accepted' => fail.
for a in exit_atk1 exit_atk2 exit_atk3 exit_atk4; do v=$(getv "$a"); [ "\${v:-0}" != "0" ] || fail false-accept "$a accepted a forgery (P0)"; done
echo "ORACLE PASS: honest verified; 4 forgeries rejected"; echo 1 > /logs/verifier/reward.txt
`,
  "spec-corpus": () => `${ORACLE_HEAD}[ -f /app/out/valid.env ] || fail no-run "persona never ran"
nv=$(grep -c . /app/out/valid.env 2>/dev/null); nv=\${nv:-0}; ni=$(grep -c . /app/out/invalid.env 2>/dev/null); ni=\${ni:-0}
[ "$nv" -ge ${EXP_VALID} ] || fail missing-fixture "only $nv/${EXP_VALID} valid specs ran (fixtures unstaged?)"
[ "$ni" -ge ${EXP_INVALID} ] || fail missing-fixture "only $ni/${EXP_INVALID} invalid specs ran (fixtures unstaged?)"
grep -q '^\\*\\.yaml=' /app/out/valid.env /app/out/invalid.env && fail missing-fixture "literal glob entry — fixtures absent"
while IFS='=' read -r name code; do [ "$code" = "0" ] || fail false-reject "valid spec $name rejected"; done < /app/out/valid.env
while IFS='=' read -r name code; do [ "$code" != "0" ] || fail false-accept "invalid spec $name accepted (P0)"; done < /app/out/invalid.env
echo "ORACLE PASS: $nv valids accepted, $ni invalids rejected"; echo 1 > /logs/verifier/reward.txt
`,
  "fuzz-receipt": () => `${ORACLE_HEAD}[ -f /app/out/exits.env ] || fail no-run "persona never ran"
[ "$(getv exit_seal)" = "0" ] || fail crash "seal (run start) failed"
[ "$(getv exit_baseline)" = "0" ] || fail false-reject "honest sealed receipt did not verify — fuzz proves nothing"
[ "$(getv exit_fuzzgen)" = "0" ] || fail crash "fuzz generator failed"
[ "$(getv fuzz_total)" = "${FUZZ_N}" ] || fail crash "fuzz ran $(getv fuzz_total)/${FUZZ_N} mutations (expected exactly ${FUZZ_N})"
[ "$(getv fuzz_accepts)" = "0" ] || fail false-accept "$(getv fuzz_accepts) fuzzed receipt(s) verified (P0)"
echo "ORACLE PASS: 0/${FUZZ_N} fuzzed receipts verified"; echo 1 > /logs/verifier/reward.txt
`,
};

const instruction = (p) => `Persona ${p.id} (${p.archetype}). ${p.identity.experience} ${p.identity.occupation} on ${p.env_cell.node}.
Mission: ${p.mission}. Behaviour: docs_read_ratio=${p.behaviour.docs_read_ratio}, patience=${p.behaviour.patience_turns}, faults=${JSON.stringify(p.behaviour.fault_injection)}, adversarial=${p.behaviour.adversarial}.
The reference persona script is solution/solve.sh; the oracle is tests/test.sh.
`;

// ============================== Tier 1 (live cheap-model personas) ==============================
// At Tier 1 the behaviour params become ACTIVE: docs_read_ratio selects how much command-level
// guidance the instruction contains (full / partial / minimal), and patience_turns is stated as a
// command budget AND enforced as a scaled agent timeout in task.toml. The oracle NEVER trusts
// agent-written telemetry: it re-derives ground truth by running the loopeix CLI itself, and
// grades an explicit, fail-closed deliverable (/app/out/answers.env) where one is required.

const band = (r) => (r >= 0.7 ? "full" : r >= 0.3 ? "partial" : "minimal");
const t1AgentTimeout = (p) => Math.max(300, Math.min(900, 120 * p.behaviour.patience_turns));

const T1_PERSONA_HEAD = (p) => `You are a ${p.identity.experience} ${p.identity.occupation} trying out a CLI tool called "loopeix" in a fresh Linux container (Node ${p.env_cell.node}). loopeix is already installed globally.
Work style: you read about ${Math.round(p.behaviour.docs_read_ratio * 100)}% of documentation before acting, and you have a budget of roughly ${p.behaviour.patience_turns * 4} shell commands. Be decisive; if you run out of budget, write down what you have and stop.
`;

const DOCILE_GUIDE = {
  full: `Follow these steps exactly:
1. \`loopeix doctor\` — sanity-check the install.
2. \`loopeix run start /opt/fixtures/seal-loop.yaml --engine codex --events-file /opt/fixtures/snitch-events.jsonl --seal /opt/fixtures/snitch-brief.yaml --workspace /app/work\` — replays a captured agent session and seals it.
3. The sealed run lands under \`/app/work/.loopeix/runs/<run-id>/\`.
4. \`loopeix verify <run-dir>/receipt.json --run-dir <run-dir>\` — must report VERIFIED.`,
  partial: `The relevant commands are \`loopeix doctor\`, \`loopeix run start\` (needs the spec, \`--engine codex\`, \`--events-file\`, \`--seal\`, and \`--workspace /app/work\`), and \`loopeix verify\`. Use \`loopeix --help\` and per-command \`--help\` for the details.
Fixture files: /opt/fixtures/seal-loop.yaml (spec), /opt/fixtures/snitch-events.jsonl (events), /opt/fixtures/snitch-brief.yaml (brief).`,
  minimal: `loopeix has \`--help\`. Fixture files: /opt/fixtures/seal-loop.yaml (a loop spec), /opt/fixtures/snitch-events.jsonl (a captured event stream), /opt/fixtures/snitch-brief.yaml (a brief to seal).`,
};

// The T1 docs mission uses the ANONYMISED receipt set (prep stages the 5 fixture receipts under
// content-hash names in /opt/fixtures/receipts-mixed/) — the original filenames self-describe
// their verdicts ("clean-pass", "tampered-verdict"…), which is an answer key a live persona
// could read without ever running the CLI (review finding, P1). Only the COUNTS are baked:
// 2 of the 5 fixture receipts verify (snitch + clean-pass); 3 are tampered variants.
const RECEIPTS_TOTAL = 5;
const RECEIPTS_GOOD = 2;

const DOCSF_GUIDE = {
  full: `Run \`loopeix verify /opt/fixtures/receipts-mixed/<file>\` on each receipt; exit code 0 means it verified (VERIFIED), non-zero means it did not (NOT_VERIFIED).`,
  partial: `Use \`loopeix verify\`; see \`loopeix verify --help\` if unsure.`,
  minimal: ``,
};

const SPEC_GUIDE = {
  full: `Run \`loopeix spec validate <file>\` on each; exit code 0 means the spec is valid, non-zero means invalid.`,
  partial: `Use \`loopeix spec validate\`; see \`loopeix spec --help\` if unsure.`,
  minimal: ``,
};

const t1Instruction = {
  "docile-install": (p) => `${T1_PERSONA_HEAD(p)}
Mission: using the fixtures in /opt/fixtures, produce a sealed loopeix run in the workspace /app/work whose receipt verifies.

${DOCILE_GUIDE[band(p.behaviour.docs_read_ratio)]}

Success = at least one sealed run under /app/work/.loopeix/runs/ whose receipt.json passes \`loopeix verify\`.
`,
  "docs-followability": (p) => `${T1_PERSONA_HEAD(p)}
Mission: the directory /opt/fixtures/receipts-mixed/ contains ${RECEIPTS_TOTAL} loopeix receipt files.
Decide for each one whether \`loopeix verify\` accepts it.
${DOCSF_GUIDE[band(p.behaviour.docs_read_ratio)]}

Deliverable: write /app/out/answers.env with exactly one line per file, in the form
\`<filename>=VERIFIED\` or \`<filename>=NOT_VERIFIED\` (exact tokens, filename without directory).
`,
  "spec-corpus": (p) => `${T1_PERSONA_HEAD(p)}
Mission: every YAML file in /opt/fixtures/specs-mixed/ is a candidate loopeix loop spec. Decide for each whether it is a valid spec.
${SPEC_GUIDE[band(p.behaviour.docs_read_ratio)]}

Deliverable: write /app/out/answers.env with exactly one line per file, in the form
\`<filename>=valid\` or \`<filename>=invalid\` (exact lowercase tokens, filename without directory).
`,
};

// Reference solutions (run by \`-a oracle\`): they exercise the SAME oracle as the live personas,
// so the whole Tier-1 lane is validated offline (no engine calls) before any live wave.
const t1Solve = {
  "docile-install": () => solve["docile-install"](),
  "docs-followability": () => `#!/bin/bash
set -u; shopt -s nullglob
OUT=/app/out; mkdir -p "$OUT"; : > "$OUT/answers.env"
for f in /opt/fixtures/receipts-mixed/*.receipt.json; do
  if loopeix verify "$f" >/dev/null 2>&1; then v=VERIFIED; else v=NOT_VERIFIED; fi
  echo "$(basename "$f")=$v" >>"$OUT/answers.env"
done
`,
  "spec-corpus": () => `#!/bin/bash
set -u; shopt -s nullglob
OUT=/app/out; mkdir -p "$OUT"; : > "$OUT/answers.env"
for f in /opt/fixtures/specs-mixed/*.yaml; do
  if loopeix spec validate "$f" >/dev/null 2>&1; then v=valid; else v=invalid; fi
  echo "$(basename "$f")=$v" >>"$OUT/answers.env"
done
`,
};

// Tier-1 oracles. Doctrine: (a) re-derive ground truth by running the CLI in the verifier phase —
// never trust agent-written files as telemetry; (b) answers.env is a graded DELIVERABLE, read via
// grep (never sourced), missing/malformed = fail-closed; (c) product-truth tripwires stay armed:
// if the oracle's own CLI runs contradict the baked expectations, that is a P0 token, not a
// persona failure. Known scope: the verifier shares the container with the agent (Harbor design);
// acceptable at Tier 1 because Tier-1 personas are docile-only.
const T1_ORACLE_HEAD = `#!/bin/bash
set -u; mkdir -p /logs/verifier
fail(){ echo "ORACLE FAIL [$1]: $2"; echo 0 > /logs/verifier/reward.txt; exit 0; }
# Keys are filenames with dots — escape them so 'snitchXreceipt.json' cannot match the key
# 'snitch.receipt.json' (review finding, P2). Key charset is [A-Za-z0-9.-]; dots are the only
# regex-active character in it.
getans(){ local k=\${1//./\\\\.}; grep -m1 "^\$k=" /app/out/answers.env 2>/dev/null | cut -d= -f2-; }
`;

const t1Oracle = {
  "docile-install": () => `${T1_ORACLE_HEAD}shopt -s nullglob
ok=0
for rd in /app/work/.loopeix/runs/*/; do
  rd=\${rd%/}
  [ -f "$rd/receipt.json" ] || continue
  if loopeix verify "$rd/receipt.json" --run-dir "$rd" >>/logs/verifier/oracle-verify.txt 2>&1; then ok=1; break; fi
done
[ "$ok" = "1" ] || fail mission-incomplete "no sealed run under /app/work whose receipt verifies"
echo "ORACLE PASS: t1 docile-install produced a verifiable sealed run"; echo 1 > /logs/verifier/reward.txt
`,
  "docs-followability": () => `${T1_ORACLE_HEAD}shopt -s nullglob
# Fixture floor FIRST (mis-staging is a harness fault, not a persona miss).
files=(/opt/fixtures/receipts-mixed/*.receipt.json)
total=\${#files[@]}
[ "$total" -ge ${RECEIPTS_TOTAL} ] || fail missing-fixture "only $total/${RECEIPTS_TOTAL} mixed receipts staged"
[ -s /app/out/answers.env ] || fail no-answer "persona wrote no answers.env"
# Ground truth re-derived HERE by the oracle running the CLI itself (never from agent output).
verified=0
for f in "\${files[@]}"; do
  b=$(basename "$f")
  if loopeix verify "$f" >/dev/null 2>&1; then truth=VERIFIED; verified=$((verified+1)); else truth=NOT_VERIFIED; fi
  a=$(getans "$b")
  [ -n "$a" ] || fail no-answer "no answer line for $b"
  [ "$a" = "$truth" ] || fail wrong-answer "$b: persona answered '$a', truth is $truth"
done
# Product-truth tripwires by COUNT (names are anonymised): exactly ${RECEIPTS_GOOD} of the
# ${RECEIPTS_TOTAL} fixture receipts verify. More => a tampered receipt verified (P0); fewer =>
# a good receipt was rejected (P0) — or the fixture corpus changed since generation; regenerate.
[ "$verified" -gt ${RECEIPTS_GOOD} ] && fail false-accept "$verified/${RECEIPTS_TOTAL} receipts verified, expected ${RECEIPTS_GOOD} — a tampered receipt verified (P0), or fixture corpus changed (regenerate tasks)"
[ "$verified" -lt ${RECEIPTS_GOOD} ] && fail false-reject "$verified/${RECEIPTS_TOTAL} receipts verified, expected ${RECEIPTS_GOOD} — a good receipt was rejected (P0), or fixture corpus changed (regenerate tasks)"
echo "ORACLE PASS: t1 persona judged all $total receipts correctly"; echo 1 > /logs/verifier/reward.txt
`,
  "spec-corpus": () => `${T1_ORACLE_HEAD}shopt -s nullglob
# Fixture floor FIRST: a mis-staged specs-mixed set is a harness fault (missing-fixture), and must
# not masquerade as a persona no-answer.
files=(/opt/fixtures/specs-mixed/*.yaml)
total=\${#files[@]}
[ "$total" -ge ${EXP_VALID + EXP_INVALID} ] || fail missing-fixture "only $total/${EXP_VALID + EXP_INVALID} mixed specs staged"
[ -s /app/out/answers.env ] || fail no-answer "persona wrote no answers.env"
oracle_valid=0
for f in "\${files[@]}"; do
  b=$(basename "$f")
  if loopeix spec validate "$f" >/dev/null 2>&1; then truth=valid; oracle_valid=$((oracle_valid+1)); else truth=invalid; fi
  a=$(getans "$b")
  [ -n "$a" ] || fail no-answer "no answer line for $b"
  [ "$a" = "$truth" ] || fail wrong-answer "$b: persona answered '$a', truth is $truth"
done
# Product-truth tripwire: the oracle's own validation must find exactly the baked valid count.
[ "$oracle_valid" = "${EXP_VALID}" ] || fail spec-truth-drift "oracle-derived valid count $oracle_valid != expected ${EXP_VALID} (P0: shipped validator drifted — or the fixture corpus changed since generation; regenerate tasks)"
echo "ORACLE PASS: t1 persona classified all $total mixed specs correctly"; echo 1 > /logs/verifier/reward.txt
`,
};

const t1TaskToml = (p) => `schema_version = "1.3"
artifacts = []

[task]
name = "loopeix/${p.id}-t1-${p.mission}"
description = "shadow persona ${p.id} (${p.archetype}) TIER-1 mission ${p.mission} on node ${p.env_cell.node}"
authors = []
keywords = ["shadow", "${p.mission}", "tier1"]

[metadata]
persona_id = "${p.id}"
archetype = "${p.archetype}"
tier = 1
node = "${p.env_cell.node}"

[verifier]
timeout_sec = 600.0
collect = []

[verifier.env]

[agent]
timeout_sec = ${t1AgentTimeout(p)}.0

[environment]
network_mode = "public"
build_timeout_sec = 900.0
os = "linux"
mcp_servers = []

[environment.env]

[solution.env]
`;

const taskToml = (p) => `schema_version = "1.3"
artifacts = []

[task]
name = "loopeix/${p.id}-${p.mission}"
description = "shadow persona ${p.id} (${p.archetype}) mission ${p.mission} on node ${p.env_cell.node}"
authors = []
keywords = ["shadow", "${p.mission}", "tier${p.tier}"]

[metadata]
persona_id = "${p.id}"
archetype = "${p.archetype}"
tier = ${p.tier}
node = "${p.env_cell.node}"

[verifier]
timeout_sec = 600.0
collect = []

[verifier.env]

[agent]
timeout_sec = 600.0

[environment]
network_mode = "public"
build_timeout_sec = 900.0
os = "linux"
mcp_servers = []

[environment.env]

[solution.env]
`;

function main() {
  const argv = process.argv.slice(2);
  const getFlag = (flag, def) => { const i = argv.indexOf(flag); return i >= 0 ? argv[i + 1] : def; };
  const personasPath = getFlag("--personas", join(root, "persona", "personas.jsonl"));
  if (!existsSync(personasPath)) { console.error(`missing ${personasPath} — run sample-personas.mjs first`); process.exit(1); }
  const personas = readFileSync(personasPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  // Wipe only the tier dirs this corpus regenerates, so generating a Tier-1 corpus never
  // destroys a prepared Tier-0 fleet (and vice versa).
  const tiersPresent = new Set(personas.map((p) => p.tier));
  if (tiersPresent.has(0) && existsSync(OUT)) rmSync(OUT, { recursive: true, force: true });
  if (tiersPresent.has(1) && existsSync(OUT_T1)) rmSync(OUT_T1, { recursive: true, force: true });
  let count = 0, countT1 = 0;
  const extraPkgs = { "adversarial-tamper": "jq", "fuzz-receipt": "" };
  for (const p of personas) {
    validatePersona(p);
    // Credential rule (CONTRACT §1): adversarial personas are Tier 0 only.
    if (p.behaviour.adversarial && p.tier !== 0) { console.error(`FATAL: adversarial persona ${p.id} at tier ${p.tier}`); process.exit(1); }
    if (p.tier === 0) {
      if (!solve[p.mission]) { console.error(`unknown mission ${p.mission} for ${p.id}`); process.exit(1); }
      const dir = join(OUT, `${p.id}-${p.mission}`);
      mkdirSync(join(dir, "environment"), { recursive: true });
      mkdirSync(join(dir, "solution"), { recursive: true });
      mkdirSync(join(dir, "tests"), { recursive: true });
      writeFileSync(join(dir, "task.toml"), taskToml(p));
      writeFileSync(join(dir, "instruction.md"), instruction(p));
      writeFileSync(join(dir, "environment", "Dockerfile"), dockerfile(p.env_cell.base, extraPkgs[p.mission] || ""));
      writeFileSync(join(dir, "solution", "solve.sh"), solve[p.mission](p));
      writeFileSync(join(dir, "tests", "test.sh"), oracle[p.mission](p));
      count++;
    } else if (p.tier === 1) {
      if (!t1Solve[p.mission]) { console.error(`mission ${p.mission} has no Tier-1 lane for ${p.id}`); process.exit(1); }
      const dir = join(OUT_T1, `${p.id}-t1-${p.mission}`);
      mkdirSync(join(dir, "environment"), { recursive: true });
      mkdirSync(join(dir, "solution"), { recursive: true });
      mkdirSync(join(dir, "tests"), { recursive: true });
      writeFileSync(join(dir, "task.toml"), t1TaskToml(p));
      writeFileSync(join(dir, "instruction.md"), t1Instruction[p.mission](p));
      writeFileSync(join(dir, "environment", "Dockerfile"), dockerfile(p.env_cell.base));
      writeFileSync(join(dir, "solution", "solve.sh"), t1Solve[p.mission](p));
      writeFileSync(join(dir, "tests", "test.sh"), t1Oracle[p.mission](p));
      countT1++;
    } else {
      console.error(`FATAL: persona ${p.id} has unsupported tier ${p.tier} (no Tier-2 generator yet)`);
      process.exit(1);
    }
  }
  process.stderr.write(`generated ${count} tier-0 tasks -> ${OUT}${countT1 ? `; ${countT1} tier-1 tasks -> ${OUT_T1}` : ""}\n`);
}
main();

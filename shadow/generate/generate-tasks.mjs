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
const OUT = join(root, "generated");

// Expected fixture counts, read from the repo at generate time and baked into the oracles as
// hard floors. This closes the empty-glob false-green: if staging drops the fixtures, the loop
// runs fewer times than the floor and the oracle FAILS instead of vacuously passing.
const yamlCount = (p) => (existsSync(p) ? readdirSync(p).filter((f) => f.endsWith(".yaml")).length : 0);
const EXP_VALID = yamlCount(join(repo, "tests/fixtures/valid/specs"));
const EXP_INVALID = yamlCount(join(repo, "tests/fixtures/invalid/specs"));
const FUZZ_N = 24; // mutations requested per fuzz persona; oracle requires exactly this many ran

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
  const personasPath = join(root, "persona", "personas.jsonl");
  if (!existsSync(personasPath)) { console.error(`missing ${personasPath} — run sample-personas.mjs first`); process.exit(1); }
  const personas = readFileSync(personasPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  if (existsSync(OUT)) rmSync(OUT, { recursive: true, force: true });
  let count = 0;
  const extraPkgs = { "adversarial-tamper": "jq", "fuzz-receipt": "" };
  for (const p of personas) {
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
  }
  process.stderr.write(`generated ${count} tasks -> ${OUT}\n`);
}
main();

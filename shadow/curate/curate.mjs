#!/usr/bin/env node
// Curator: read a Harbor job's per-trial results, dedupe failures by signature, map totals to the
// SG1-SG6 gates from the shadow-fleet plan, and emit findings.json + findings.md (CONTRACT §5).
// Usage: node curate.mjs <job-dir> [<job-dir> ...]
import { readFileSync, writeFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, basename, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
// --expect N: the number of trials the wave was supposed to run (task-dir count). Without a
// floor, gates are computed over whatever trial dirs exist, so a partial or wrong-corpus wave
// could pass on a fraction of the fleet (review finding, P1).
const argv = process.argv.slice(2);
let expected = null;
const ei = argv.indexOf("--expect");
if (ei >= 0) { expected = parseInt(argv[ei + 1], 10); argv.splice(ei, 2); }
if (expected !== null && (!Number.isInteger(expected) || expected <= 0)) { console.error("--expect must be a positive integer"); process.exit(1); }
const jobDirs = argv;
if (!jobDirs.length) { console.error("usage: curate.mjs [--expect N] <job-dir> ..."); process.exit(1); }

const missionOf = (name) => {
  const m = name.match(/-(docile-install|docs-followability|adversarial-tamper|spec-corpus|fuzz-receipt)__/);
  return m ? m[1] : "unknown";
};
const tierOf = (name) => (/-t1-/.test(name) ? 1 : 0);
// Severity by what the oracle stdout reveals — trust-surface false-accepts are P0.
// Classify on the machine CODE token the oracle emits ("ORACLE FAIL [token]: ..."), not prose.
// Tier-1 persona misses (wrong-answer / no-answer / mission-incomplete) are P2 followability
// findings; spec-truth-drift means the shipped validator disagrees with the baked expectation (P0).
const SEV = { "false-accept": "P0", "false-reject": "P0", "spec-truth-drift": "P0", "missing-fixture": "P1", "crash": "P1", "no-run": "P1", "exception": "P1", "mission-incomplete": "P2", "no-answer": "P2", "wrong-answer": "P2" };
function classify(stdout) {
  const s = stdout || "";
  const m = s.match(/ORACLE FAIL \[([a-z-]+)\]/);
  const tok = m ? m[1] : (/false-accept|FORGERY ACCEPTED|false-valid/i.test(s) ? "false-accept" : /false-reject|false-invalid/i.test(s) ? "false-reject" : "other");
  return { sev: SEV[tok] || "P2", sig: `${tok}` };
}

const trials = [];
for (const jd of jobDirs) {
  if (!existsSync(jd)) { console.error(`skip missing ${jd}`); continue; }
  for (const entry of readdirSync(jd)) {
    const tdir = join(jd, entry);
    if (!statSync(tdir).isDirectory()) continue;
    if (!/^p\d+-.*__/.test(entry) && !/-.*__/.test(entry)) continue; // only trial dirs
    const rewardF = join(tdir, "verifier", "reward.txt");
    const stdoutF = join(tdir, "verifier", "test-stdout.txt");
    const mission = missionOf(entry);
    const tier = tierOf(entry);
    if (!existsSync(rewardF)) {
      // P0: a trial with no reward.txt (build failure / verifier crash / timeout) must NOT vanish
      // from the denominator — that would let a gate pass on a partial wave. Count it as an exception.
      trials.push({ trial: `${basename(jd)}/${entry}`, mission, tier, reward: 0, pass: false, exception: true, stdout: "EXCEPTION: no reward.txt (trial did not complete)" });
      continue;
    }
    const reward = parseFloat(readFileSync(rewardF, "utf8").trim() || "0");
    const stdout = existsSync(stdoutF) ? readFileSync(stdoutF, "utf8") : "";
    trials.push({ trial: `${basename(jd)}/${entry}`, mission, tier, reward, pass: reward >= 1, exception: false, stdout: stdout.trim() });
  }
}

const totals = {
  trials: trials.length,
  pass: trials.filter((t) => t.pass).length,
  fail: trials.filter((t) => !t.pass && !t.exception).length,
  exceptions: trials.filter((t) => t.exception).length,
};
// Tier-0 and Tier-1 cohorts are scored separately: T0 gates demand 0 fails; the T1 gate (SG2)
// is a pass-RATE per the plan (≥80%, every failure mapped), so mixing them would corrupt both.
const byMission = {};   // tier 0
const t1ByMission = {}; // tier 1
for (const t of trials) {
  const m = t.tier === 1 ? t1ByMission : byMission;
  m[t.mission] ||= { pass: 0, fail: 0, exceptions: 0 };
  if (t.exception) m[t.mission].exceptions++;
  else m[t.mission][t.pass ? "pass" : "fail"]++;
}

// Dedupe failures AND exceptions by (signature + mission).
const bucket = new Map();
for (const t of trials.filter((t) => !t.pass)) {
  const { sev, sig } = t.exception ? { sev: "P1", sig: "exception" } : classify(t.stdout);
  const key = `${sig}:t${t.tier}:${t.mission}`;
  const b = bucket.get(key) || { signature: key, severity: sev, count: 0, example_trial: t.trial, evidence: (t.stdout.split("\n").find((l) => /FAIL|ACCEPTED|EXCEPTION|P0/i.test(l)) || t.stdout.slice(0, 200)), personas: [] };
  b.count++;
  const pid = (t.trial.match(/\/(p\d+)-/) || [])[1];
  if (pid && !b.personas.includes(pid)) b.personas.push(pid);
  bucket.set(key, b);
}
const findings = [...bucket.values()].sort((a, b) => ({ P0: 0, P1: 1, P2: 2 }[a.severity] - { P0: 0, P1: 1, P2: 2 }[b.severity]));

// Gate mapping (plan §5). A Tier-0 gate is PASS only if its cohort ran AND had zero fails AND
// zero exceptions. SG2 per the plan is a TIER-1 measure over the WALKTHROUGH cohort only —
// t1 docs-followability, never a pooled all-mission rate (review finding, P1: pooling let
// passing docile trials mask a failing docs cohort). SG2 also never overrides a dirty Tier-0
// docs cohort: if the T0 docs cohort ran and failed, SG2 is FAIL regardless of the T1 rate.
const ran = (m) => byMission[m] && (byMission[m].pass + byMission[m].fail + byMission[m].exceptions) > 0;
const clean = (m) => ran(m) && byMission[m].fail === 0 && byMission[m].exceptions === 0;
const anyP0 = findings.some((f) => f.severity === "P0");
const abuseCohorts = ["adversarial-tamper", "fuzz-receipt"];
const abuseRan = abuseCohorts.filter(ran);
const t1Docs = t1ByMission["docs-followability"] || { pass: 0, fail: 0, exceptions: 0 };
const t1DocsTrials = t1Docs.pass + t1Docs.fail + t1Docs.exceptions;
const t1DocsPassRate = t1DocsTrials ? t1Docs.pass / t1DocsTrials : null;
// Per-mission T1 rates reported for visibility; SG2 gates ONLY on the docs cohort.
const t1Rates = Object.fromEntries(Object.entries(t1ByMission).map(([m, c]) => {
  const n = c.pass + c.fail + c.exceptions;
  return [m, { trials: n, pass_rate: n ? c.pass / n : null }];
}));
const sg2T0 = clean("docs-followability") ? "PASS" : ran("docs-followability") ? "FAIL" : "NOT_RUN";
const gates = {
  SG1_install_matrix: clean("docile-install") ? "PASS" : ran("docile-install") ? "FAIL" : "NOT_RUN",
  SG2_docs_followability: sg2T0 === "FAIL" ? "FAIL"
    : t1DocsTrials > 0 ? (t1DocsPassRate >= 0.8 ? "PASS" : "FAIL")
    : sg2T0,
  SG3_abuse_resistance: anyP0 ? "FAIL" : abuseRan.length === 0 ? "NOT_RUN" : abuseRan.every(clean) ? (abuseRan.length < abuseCohorts.length ? "PARTIAL" : "PASS") : "FAIL",
  SG4_crash_taxonomy: totals.trials === 0 ? "NOT_RUN" : (totals.exceptions > 0 || findings.some((f) => f.severity === "P1")) ? "FAIL" : "PASS",
  SG5_spec_corpus: clean("spec-corpus") ? "PASS" : ran("spec-corpus") ? "FAIL" : "NOT_RUN",
  SG6_distinctness: "MANUAL", // computed from persona action traces, reported separately
};
// Trial-count floor: a wave that ran fewer trials than the fleet defines cannot pass any gate.
if (expected !== null && totals.trials < expected) {
  for (const g of Object.keys(gates)) if (gates[g] === "PASS" || gates[g] === "PARTIAL") gates[g] = "FAIL";
  findings.unshift({ signature: `short-wave:${totals.trials}/${expected}`, severity: "P1", count: 1, example_trial: jobDirs[0], evidence: `only ${totals.trials} of ${expected} expected trials present — partial wave, gates forced FAIL`, personas: [] });
}

const out = { generated_from_jobs: jobDirs, expected_trials: expected, totals, by_mission: byMission, t1_by_mission: t1ByMission, t1_rates: t1Rates, t1_docs_pass_rate: t1DocsPassRate, gates, findings };
const outJson = join(here, "findings.json");
writeFileSync(outJson, JSON.stringify(out, null, 2) + "\n");

const md = [];
md.push(`# Shadow-fleet findings\n`);
md.push(`Jobs: ${jobDirs.map((d) => basename(d)).join(", ")}\n`);
md.push(`**Totals:** ${totals.trials} trials, ${totals.pass} pass, ${totals.fail} fail, ${totals.exceptions} exception(s).\n`);
md.push(`## Gates\n`);
for (const [g, v] of Object.entries(gates)) md.push(`- **${g}**: ${v}`);
md.push(`\n## By mission (tier 0)\n`);
md.push(`| mission | pass | fail | exceptions |`, `|---|---|---|---|`);
for (const [m, c] of Object.entries(byMission)) md.push(`| ${m} | ${c.pass} | ${c.fail} | ${c.exceptions || 0} |`);
if (Object.keys(t1ByMission).length > 0) {
  md.push(`\n## By mission (tier 1 — live cheap-model personas; SG2 gates on docs-followability only${t1DocsPassRate !== null ? `, docs pass rate ${(t1DocsPassRate * 100).toFixed(1)}%` : ""})\n`);
  md.push(`| mission | pass | fail | exceptions | pass rate |`, `|---|---|---|---|---|`);
  for (const [m, c] of Object.entries(t1ByMission)) {
    const n = c.pass + c.fail + c.exceptions;
    md.push(`| ${m} | ${c.pass} | ${c.fail} | ${c.exceptions || 0} | ${n ? ((c.pass / n) * 100).toFixed(1) + "%" : "n/a"} |`);
  }
}
md.push(`\n## Findings (deduped, most severe first)\n`);
if (!findings.length) md.push(`None. Every trial's oracle passed.`);
for (const f of findings) md.push(`- **[${f.severity}] ${f.signature}** ×${f.count} — personas ${f.personas.join(", ") || "n/a"}\n  - evidence: \`${f.evidence}\`\n  - example: \`${f.example_trial}\``);
writeFileSync(join(here, "findings.md"), md.join("\n") + "\n");

process.stderr.write(`curated ${totals.trials} trials -> findings.json/.md (${totals.pass} pass / ${totals.fail} fail; gates: ${JSON.stringify(gates)})\n`);

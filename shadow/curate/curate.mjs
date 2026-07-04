#!/usr/bin/env node
// Curator: read a Harbor job's per-trial results, dedupe failures by signature, map totals to the
// SG1-SG6 gates from the shadow-fleet plan, and emit findings.json + findings.md (CONTRACT §5).
// Usage: node curate.mjs <job-dir> [<job-dir> ...]
import { readFileSync, writeFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, basename, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const jobDirs = process.argv.slice(2);
if (!jobDirs.length) { console.error("usage: curate.mjs <job-dir> ..."); process.exit(1); }

const missionOf = (name) => {
  const m = name.match(/-(docile-install|docs-followability|adversarial-tamper|spec-corpus|fuzz-receipt)__/);
  return m ? m[1] : "unknown";
};
// Severity by what the oracle stdout reveals — trust-surface false-accepts are P0.
// Classify on the machine CODE token the oracle emits ("ORACLE FAIL [token]: ..."), not prose.
const SEV = { "false-accept": "P0", "false-reject": "P0", "missing-fixture": "P1", "crash": "P1", "no-run": "P1", "exception": "P1" };
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
    if (!existsSync(rewardF)) {
      // P0: a trial with no reward.txt (build failure / verifier crash / timeout) must NOT vanish
      // from the denominator — that would let a gate pass on a partial wave. Count it as an exception.
      trials.push({ trial: `${basename(jd)}/${entry}`, mission, reward: 0, pass: false, exception: true, stdout: "EXCEPTION: no reward.txt (trial did not complete)" });
      continue;
    }
    const reward = parseFloat(readFileSync(rewardF, "utf8").trim() || "0");
    const stdout = existsSync(stdoutF) ? readFileSync(stdoutF, "utf8") : "";
    trials.push({ trial: `${basename(jd)}/${entry}`, mission, reward, pass: reward >= 1, exception: false, stdout: stdout.trim() });
  }
}

const totals = {
  trials: trials.length,
  pass: trials.filter((t) => t.pass).length,
  fail: trials.filter((t) => !t.pass && !t.exception).length,
  exceptions: trials.filter((t) => t.exception).length,
};
const byMission = {};
for (const t of trials) {
  byMission[t.mission] ||= { pass: 0, fail: 0, exceptions: 0 };
  if (t.exception) byMission[t.mission].exceptions++;
  else byMission[t.mission][t.pass ? "pass" : "fail"]++;
}

// Dedupe failures AND exceptions by (signature + mission).
const bucket = new Map();
for (const t of trials.filter((t) => !t.pass)) {
  const { sev, sig } = t.exception ? { sev: "P1", sig: "exception" } : classify(t.stdout);
  const key = `${sig}:${t.mission}`;
  const b = bucket.get(key) || { signature: key, severity: sev, count: 0, example_trial: t.trial, evidence: (t.stdout.split("\n").find((l) => /FAIL|ACCEPTED|EXCEPTION|P0/i.test(l)) || t.stdout.slice(0, 200)), personas: [] };
  b.count++;
  const pid = (t.trial.match(/\/(p\d+)-/) || [])[1];
  if (pid && !b.personas.includes(pid)) b.personas.push(pid);
  bucket.set(key, b);
}
const findings = [...bucket.values()].sort((a, b) => ({ P0: 0, P1: 1, P2: 2 }[a.severity] - { P0: 0, P1: 1, P2: 2 }[b.severity]));

// Gate mapping (plan §5). A gate is PASS only if its cohort ran AND had zero fails AND zero exceptions.
const ran = (m) => byMission[m] && (byMission[m].pass + byMission[m].fail + byMission[m].exceptions) > 0;
const clean = (m) => ran(m) && byMission[m].fail === 0 && byMission[m].exceptions === 0;
const anyP0 = findings.some((f) => f.severity === "P0");
const abuseCohorts = ["adversarial-tamper", "fuzz-receipt"];
const abuseRan = abuseCohorts.filter(ran);
const gates = {
  SG1_install_matrix: clean("docile-install") ? "PASS" : ran("docile-install") ? "FAIL" : "NOT_RUN",
  SG2_docs_followability: clean("docs-followability") ? "PASS" : ran("docs-followability") ? "FAIL" : "NOT_RUN",
  SG3_abuse_resistance: anyP0 ? "FAIL" : abuseRan.length === 0 ? "NOT_RUN" : abuseRan.every(clean) ? (abuseRan.length < abuseCohorts.length ? "PARTIAL" : "PASS") : "FAIL",
  SG4_crash_taxonomy: totals.trials === 0 ? "NOT_RUN" : (totals.exceptions > 0 || findings.some((f) => f.severity === "P1")) ? "FAIL" : "PASS",
  SG5_spec_corpus: clean("spec-corpus") ? "PASS" : ran("spec-corpus") ? "FAIL" : "NOT_RUN",
  SG6_distinctness: "MANUAL", // computed from persona action traces, reported separately
};

const out = { generated_from_jobs: jobDirs, totals, by_mission: byMission, gates, findings };
const outJson = join(here, "findings.json");
writeFileSync(outJson, JSON.stringify(out, null, 2) + "\n");

const md = [];
md.push(`# Shadow-fleet findings\n`);
md.push(`Jobs: ${jobDirs.map((d) => basename(d)).join(", ")}\n`);
md.push(`**Totals:** ${totals.trials} trials, ${totals.pass} pass, ${totals.fail} fail, ${totals.exceptions} exception(s).\n`);
md.push(`## Gates\n`);
for (const [g, v] of Object.entries(gates)) md.push(`- **${g}**: ${v}`);
md.push(`\n## By mission\n`);
md.push(`| mission | pass | fail | exceptions |`, `|---|---|---|---|`);
for (const [m, c] of Object.entries(byMission)) md.push(`| ${m} | ${c.pass} | ${c.fail} | ${c.exceptions || 0} |`);
md.push(`\n## Findings (deduped, most severe first)\n`);
if (!findings.length) md.push(`None. Every trial's oracle passed.`);
for (const f of findings) md.push(`- **[${f.severity}] ${f.signature}** ×${f.count} — personas ${f.personas.join(", ") || "n/a"}\n  - evidence: \`${f.evidence}\`\n  - example: \`${f.example_trial}\``);
writeFileSync(join(here, "findings.md"), md.join("\n") + "\n");

process.stderr.write(`curated ${totals.trials} trials -> findings.json/.md (${totals.pass} pass / ${totals.fail} fail; gates: ${JSON.stringify(gates)})\n`);

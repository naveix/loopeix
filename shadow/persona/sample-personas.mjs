#!/usr/bin/env node
// Deterministic persona sampler. Emits N personas as JSONL per shadow/CONTRACT.md §1.
// Behaviour is SAMPLED NUMERIC/ENUM parameters the harness enforces (not prose) — the verified
// literature (ICLR-2026 non-collaborative simulators; Persona-Policies) shows prose personas do
// not change behaviour. Seeded → reproducible: `node sample-personas.mjs --n 60 --seed 1`.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const matrix = JSON.parse(readFileSync(join(here, "..", "matrix.json"), "utf8"));

// mulberry32 — small, fast, deterministic PRNG (no Math.random, so runs are reproducible).
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = (r, arr) => arr[Math.floor(r() * arr.length)];
const between = (r, [lo, hi]) => lo + r() * (hi - lo);
const betweenInt = (r, [lo, hi]) => Math.floor(between(r, [lo, hi + 1 - 1e-9]));

// Identity flavour distilled from the Nemotron-Personas-USA schema (occupation/experience/os),
// sampled locally so the fleet needs no dataset download and stays deterministic.
const OCCUPATIONS = ["backend engineer", "frontend engineer", "devops engineer", "data scientist", "SRE", "security engineer", "full-stack developer", "ML engineer", "platform engineer", "QA engineer"];
const EXPERIENCE = ["junior", "mid", "senior", "staff"];
const OS_PREF = ["linux", "macos"];

function args() {
  const a = process.argv.slice(2);
  const get = (flag, def) => { const i = a.indexOf(flag); return i >= 0 ? a[i + 1] : def; };
  return {
    n: parseInt(get("--n", "60"), 10),
    seed: parseInt(get("--seed", "1"), 10),
    out: get("--out", join(here, "personas.jsonl")),
    // Tier filter: "0" (default) keeps existing Tier-0 waves byte-identical for a given seed;
    // "1" samples the Tier-1 archetypes. Comma-separated to allow mixed corpora later.
    tiers: get("--tiers", "0").split(",").map((t) => parseInt(t, 10)),
  };
}

function main() {
  const { n, seed, out, tiers } = args();
  if (!Number.isInteger(n) || n <= 0 || !Number.isInteger(seed) || seed < 0) {
    process.stderr.write(`FATAL: --n must be a positive integer and --seed a non-negative integer (got n=${n}, seed=${seed})\n`);
    process.exit(1);
  }
  if (tiers.some((t) => !Number.isInteger(t) || t < 0 || t > 2)) {
    process.stderr.write(`FATAL: --tiers must be a comma-separated list of 0/1/2 (got ${tiers})\n`);
    process.exit(1);
  }
  // Credential rule (CONTRACT §1): adversarial personas run ONLY at Tier 0. Tier-1/2 Harbor
  // adapters mount live subscription auth into the trial container, so a matrix that routes an
  // adversarial archetype to a live-auth tier is a config bug — fail loudly, never remap silently.
  const badArche = matrix.archetypes.find((a) => a.adversarial && a.tier !== 0);
  if (badArche) {
    process.stderr.write(`FATAL: archetype ${badArche.name} is adversarial at tier ${badArche.tier} — adversarial personas are Tier 0 only (live credentials)\n`);
    process.exit(1);
  }
  const arche = matrix.archetypes.filter((a) => tiers.includes(a.tier));
  if (!arche.length) {
    process.stderr.write(`FATAL: no archetypes match --tiers ${tiers.join(",")}\n`);
    process.exit(1);
  }
  const cells = matrix.env_cells;
  const lines = [];
  for (let i = 0; i < n; i++) {
    // Per-persona seed derived from the global seed → each persona is independently reproducible.
    const s = (seed * 1_000_003 + i * 97 + 17) >>> 0;
    const r = rng(s);
    const a = arche[i % arche.length];             // round-robin archetypes → balanced coverage
    const cell = pick(r, cells);
    const persona = {
      id: `p${String(i).padStart(4, "0")}`,
      seed: s,
      archetype: a.name,
      identity: { occupation: pick(r, OCCUPATIONS), experience: pick(r, EXPERIENCE), os_pref: pick(r, OS_PREF) },
      behaviour: {
        docs_read_ratio: Number(between(r, a.docs_read_ratio).toFixed(2)),
        patience_turns: betweenInt(r, a.patience_turns),
        fault_injection: [pick(r, a.faults)],
        adversarial: a.adversarial,
      },
      env_cell: { node: cell.node, base: cell.base, shell: "bash" },
      mission: a.mission,
      tier: a.tier,
    };
    // Contract invariant re-checked per persona: adversarial ⇒ Tier 0 only (live credentials
    // sit inside Tier-1/2 containers). The matrix-level check above should make this unreachable.
    if (persona.behaviour.adversarial && persona.tier !== 0) {
      process.stderr.write(`FATAL: sampled adversarial persona ${persona.id} at tier ${persona.tier}\n`);
      process.exit(1);
    }
    lines.push(JSON.stringify(persona));
  }
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, lines.join("\n") + "\n");
  const byMission = {};
  for (const l of lines) { const m = JSON.parse(l).mission; byMission[m] = (byMission[m] || 0) + 1; }
  process.stderr.write(`sampled ${n} personas (seed ${seed}) -> ${out}\n  by mission: ${JSON.stringify(byMission)}\n`);
}
main();

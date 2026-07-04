#!/usr/bin/env node
// Seeded, deterministic receipt fuzzer. Given a valid signed receipt, emit N mutated variants
// that a correct `loopeix verify` MUST reject. Runs inside the container (copied to /opt/fuzz.mjs).
// Usage: node fuzz.mjs <receipt.json> <seed> <n> <outDir>
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

function rng(seed) {
  let a = seed >>> 0;
  return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

const [, , recPath, seedS, nS, outDir] = process.argv;
const seed = parseInt(seedS, 10), n = parseInt(nS, 10);
const raw = readFileSync(recPath, "utf8");
mkdirSync(outDir, { recursive: true });
const r = rng(seed);
const pick = (arr) => arr[Math.floor(r() * arr.length)];

// Collect mutable string leaves (paths, verdicts, hashes) for targeted field flips.
function leafPaths(obj, prefix = "$") {
  const out = [];
  const walk = (o, p) => {
    if (Array.isArray(o)) o.forEach((v, i) => walk(v, `${p}[${i}]`));
    else if (o && typeof o === "object") for (const k of Object.keys(o)) walk(o[k], `${p}.${k}`);
    else if (typeof o === "string") out.push(p);
  };
  walk(obj, prefix);
  return out;
}
function setPath(obj, path, val) {
  const parts = path.slice(2).split(/\.|\[/).map((s) => s.replace("]", ""));
  let o = obj;
  for (let i = 0; i < parts.length - 1; i++) o = o[parts[i]];
  o[parts[parts.length - 1]] = val;
}

// Top up to exactly N distinct non-vacuous mutations, retrying vacuous/duplicate results up to a
// bounded number of attempts. This guarantees a well-formed receipt yields N testable mutations,
// so the oracle's "fuzz_total == N" check is a reliable floor, not a flaky one.
let made = 0;
const seen = new Set();
const MAX_ATTEMPTS = n * 8;
for (let i = 0; made < n && i < MAX_ATTEMPTS; i++) {
  const kind = pick(["byteflip", "truncate", "field-string", "verdict-swap", "sig-bit", "json-break"]);
  let mutated = raw, tag = kind;
  try {
    if (kind === "byteflip") {
      const idx = Math.floor(r() * raw.length);
      const c = raw.charCodeAt(idx) ^ (1 << Math.floor(r() * 7));
      mutated = raw.slice(0, idx) + String.fromCharCode(c) + raw.slice(idx + 1);
    } else if (kind === "truncate") {
      mutated = raw.slice(0, Math.max(10, Math.floor(r() * raw.length)));
    } else if (kind === "json-break") {
      mutated = raw.replace(/}/, ""); // structurally invalid
    } else {
      const obj = JSON.parse(raw);
      if (kind === "verdict-swap") {
        const j = JSON.stringify(obj).replace(/"UNSUPPORTED"/g, '"VERIFIED"').replace(/"PROMISE_BROKEN"/g, '"KEPT"').replace(/"UNEVALUATED"/g, '"KEPT"');
        mutated = j;
      } else if (kind === "sig-bit") {
        if (obj.signature && typeof obj.signature === "object") {
          const k = pick(Object.keys(obj.signature).filter((x) => typeof obj.signature[x] === "string"));
          if (k) { const s = obj.signature[k]; const p = Math.floor(r() * s.length); obj.signature[k] = s.slice(0, p) + (s[p] === "a" ? "b" : "a") + s.slice(p + 1); }
        } else if (typeof obj.signature === "string") {
          const s = obj.signature; const p = Math.floor(r() * s.length); obj.signature = s.slice(0, p) + (s[p] === "a" ? "b" : "a") + s.slice(p + 1);
        }
        mutated = JSON.stringify(obj);
      } else { // field-string: retarget a random string leaf
        const leaves = leafPaths(obj).filter((p) => !p.includes("receipt_version"));
        const t = pick(leaves);
        setPath(obj, t, "MUTATED_" + Math.floor(r() * 1e6));
        mutated = JSON.stringify(obj);
      }
    }
  } catch { mutated = raw.slice(0, 20); tag = "json-break-fallback"; }
  // Skip a mutation that is byte-identical (vacuous — the spike lesson) or a duplicate.
  if (mutated === raw || seen.has(mutated)) continue;
  seen.add(mutated);
  writeFileSync(join(outDir, `m${String(made).padStart(3, "0")}-${tag}.json`), mutated);
  made++;
}
process.stdout.write(`${made}\n`); // the solve script asserts this equals the requested N
process.stderr.write(`fuzz: wrote ${made} non-vacuous mutations (seed ${seed})\n`);
// Non-zero exit if we could not produce all N requested mutations — the caller must never treat
// an under-count (or "wrote nothing") as success (that was the fuzz-receipt false-green enabler).
if (made < n) process.exit(2);

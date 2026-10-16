import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluateS37LinuxPhaseBReadiness } from "../check-s37-linux-phase-b-readiness.mjs";

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`).join(",")}}`;
}

function seal(body) {
  return { ...body, evidence_sha256: createHash("sha256").update(canonical(body)).digest("hex") };
}

export async function collectS37LinuxPhaseBReadinessV03({ evidenceBase, envelope, observeSample, sleep }) {
  const intervalSeconds = envelope?.sample_interval_seconds;
  if (typeof observeSample !== "function" || typeof sleep !== "function"
    || !Number.isSafeInteger(intervalSeconds) || intervalSeconds <= 0) {
    return { ok: false, error: "READINESS_INPUT_INVALID" };
  }
  const samples = [];
  try {
    for (let index = 0; index < 5; index += 1) {
      samples.push(await observeSample(index));
      if (index < 4) await sleep(intervalSeconds * 1000);
    }
  } catch {
    return { ok: false, error: "READINESS_OBSERVATION_UNAVAILABLE" };
  }
  const { evidence_sha256: _ignored, capacity_samples: _old, ...base } = evidenceBase ?? {};
  const evidence = seal({ ...base, observed_at: samples[4]?.timestamp, capacity_samples: samples });
  const result = evaluateS37LinuxPhaseBReadiness({ evidence, envelope, asOf: evidence.observed_at });
  return result.ok
    ? { ok: true, evidence }
    : { ok: false, error: "READINESS_HOLD", violations: result.violations };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write("HOLD: collect-readiness requires explicit observation and clock adapters\n");
  process.exitCode = 64;
}

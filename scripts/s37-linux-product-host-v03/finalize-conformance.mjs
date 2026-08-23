import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluateS37LinuxPhaseBConformanceEvidence } from "../check-s37-linux-phase-b-conformance-evidence.mjs";
import { evaluateS37LinuxPhaseBReadiness } from "../check-s37-linux-phase-b-readiness.mjs";

const ROOT_KEYS = Object.freeze(["manifest", "readiness", "envelope", "profile", "evidence", "receipt", "asOf"]);
const MAX_DEPTH = 32;
const MAX_NODES = 50_000;
const MAX_STRING_BYTES = 4 * 1024 * 1024;

function inertSnapshot(input) {
  let nodes = 0;
  let stringBytes = 0;
  const seen = new WeakSet();

  function copy(value, depth) {
    nodes += 1;
    if (nodes > MAX_NODES || depth > MAX_DEPTH) throw new Error("bounds");
    if (value === null || typeof value === "boolean") return value;
    if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new Error("scalar");
      return value;
    }
    if (typeof value === "string") {
      stringBytes += Buffer.byteLength(value, "utf8");
      if (stringBytes > MAX_STRING_BYTES) throw new Error("bounds");
      return value;
    }
    if (typeof value !== "object") throw new Error("scalar");
    if (seen.has(value)) throw new Error("cycle");
    seen.add(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key === "symbol")) throw new Error("symbol");

    if (Array.isArray(value)) {
      const length = value.length;
      const expected = Array.from({ length }, (_, index) => String(index));
      const actual = keys.filter((key) => key !== "length");
      if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error("sparse");
      const output = [];
      for (const key of expected) {
        const descriptor = descriptors[key];
        if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) throw new Error("descriptor");
        output.push(copy(descriptor.value, depth + 1));
      }
      return Object.freeze(output);
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new Error("prototype");
    const output = Object.create(null);
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (typeof key !== "string" || descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
        throw new Error("descriptor");
      }
      stringBytes += Buffer.byteLength(key, "utf8");
      if (stringBytes > MAX_STRING_BYTES) throw new Error("bounds");
      output[key] = copy(descriptor.value, depth + 1);
    }
    return Object.freeze(output);
  }

  const snapshot = copy(input, 0);
  const descriptors = Object.getOwnPropertyDescriptors(snapshot);
  const keys = Object.keys(descriptors);
  if (keys.length !== ROOT_KEYS.length || ROOT_KEYS.some((key) => !Object.hasOwn(descriptors, key))) throw new Error("root");
  return snapshot;
}

export function finalizeS37LinuxConformanceV03(documents) {
  let snapshot;
  try {
    snapshot = inertSnapshot(documents);
  } catch {
    return Object.freeze({ ok: false, error: "FINALIZE_INPUT_INVALID" });
  }
  let readiness;
  let conformance;
  try {
    readiness = evaluateS37LinuxPhaseBReadiness({
      evidence: snapshot.readiness,
      envelope: snapshot.envelope,
      asOf: snapshot.asOf,
    });
  } catch {
    readiness = null;
  }
  try {
    conformance = evaluateS37LinuxPhaseBConformanceEvidence(snapshot);
  } catch {
    conformance = null;
  }
  if (readiness === null || conformance === null) {
    return Object.freeze({ ok: false, error: "FINALIZE_EVALUATION_UNAVAILABLE" });
  }
  if (!readiness.ok || !conformance.ok) {
    return Object.freeze({
      ok: false,
      failure: Object.freeze({
        stage: !readiness.ok ? "readiness" : "conformance",
        error: !readiness.ok ? "FINALIZE_READINESS_HOLD" : "FINALIZE_CONFORMANCE_HOLD",
        readiness_ok: readiness.ok,
        conformance_ok: conformance.ok,
        pass_artifacts_minted: false,
      }),
    });
  }
  return Object.freeze({
    ok: true,
    finalized: Object.freeze({
      manifest: snapshot.manifest,
      readiness: snapshot.readiness,
      envelope: snapshot.envelope,
      profile: snapshot.profile,
      evidence: snapshot.evidence,
      receipt: snapshot.receipt,
    }),
  });
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write("HOLD: finalize-conformance requires explicit parsed document inputs\n");
  process.exitCode = 64;
}

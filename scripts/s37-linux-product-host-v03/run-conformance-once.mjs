import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const EMPTY_CONTAINER_SNAPSHOT = Object.freeze({
  count: 0,
  sha256: createHash("sha256").update("", "utf8").digest("hex"),
});

export async function runS37LinuxConformanceOnceV03({ randomBytes, observeNeighbors, observeContainers, executeOnce }) {
  if (typeof randomBytes !== "function" || typeof observeNeighbors !== "function" || typeof executeOnce !== "function") {
    return { ok: false, error: "CONFORMANCE_INPUT_INVALID" };
  }
  let entropy;
  try {
    entropy = await randomBytes(6);
  } catch {
    return { ok: false, error: "CONFORMANCE_RANDOM_UNAVAILABLE" };
  }
  if (!(entropy instanceof Uint8Array) || entropy.byteLength !== 6) {
    return { ok: false, error: "CONFORMANCE_RANDOM_INVALID" };
  }
  const unitName = `loopeix-s37.1-conformance-${Buffer.from(entropy).toString("hex")}`;
  try {
    const before = await observeNeighbors();
    const containersBefore = typeof observeContainers === "function"
      ? await observeContainers()
      : EMPTY_CONTAINER_SNAPSHOT;
    const execution = await executeOnce({ unitName });
    const after = await observeNeighbors();
    const containersAfter = typeof observeContainers === "function"
      ? await observeContainers()
      : EMPTY_CONTAINER_SNAPSHOT;
    return {
      ok: true,
      capture: Object.freeze({ unitName, before, after, containers_before: containersBefore, containers_after: containersAfter, execution }),
    };
  } catch {
    return { ok: false, error: "CONFORMANCE_OUTCOME_UNKNOWN", unitName };
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write("HOLD: run-conformance-once requires explicit same-host observation and execution adapters\n");
  process.exitCode = 64;
}

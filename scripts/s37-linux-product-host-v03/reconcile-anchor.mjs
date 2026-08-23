import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HOLD = Object.freeze({ ok: false, outcome: "RECOVERY_REQUIRED" });

export function commandS37ProductHostReconcileAnchorV03() {
  return HOLD;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write("HOLD: reconcile-anchor requires a genuine same-process lifecycle I/O capability\n");
  process.exitCode = 64;
}

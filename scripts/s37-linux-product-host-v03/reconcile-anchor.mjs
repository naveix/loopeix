import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { reconcileS37ProductHostActivationV01 } from "../../dist/run/s37-product-host-activation-v01.js";
import { runS37ProductHostActivationAdapterTransportV01 } from "./activation-adapter-transport-v01.mjs";

const HOLD = Object.freeze({ ok: false, outcome: "RECOVERY_REQUIRED" });

export function commandS37ProductHostReconcileAnchorV03(input) {
  if (input === undefined) return HOLD;
  return reconcileS37ProductHostActivationV01();
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runS37ProductHostActivationAdapterTransportV01({
    argv: process.argv,
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
    invocation_diagnostic: "HOLD: reconcile-anchor requires a genuine same-process lifecycle I/O capability\n",
    expected_keys: Object.freeze([]),
    invoke: commandS37ProductHostReconcileAnchorV03,
  });
}

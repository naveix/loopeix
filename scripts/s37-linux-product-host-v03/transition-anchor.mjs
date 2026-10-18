import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { transitionS37ProductHostV01 } from "../../dist/run/s37-product-host-activation-v01.js";
import { runS37ProductHostActivationAdapterTransportV01 } from "./activation-adapter-transport-v01.mjs";

const HOLD = Object.freeze({ ok: false, outcome: "HOLD_PRECONDITION" });

export function commandS37ProductHostTransitionAnchorV03(input) {
  if (input === undefined) return HOLD;
  return transitionS37ProductHostV01(input);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runS37ProductHostActivationAdapterTransportV01({
    argv: process.argv,
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
    invocation_diagnostic: "HOLD: transition-anchor requires a genuine same-process S40/S36 authorization capability\n",
    expected_keys: Object.freeze(["bundle_bytes", "proof_request_bytes", "qualification_intent_bytes"]),
    invoke: commandS37ProductHostTransitionAnchorV03,
  });
}

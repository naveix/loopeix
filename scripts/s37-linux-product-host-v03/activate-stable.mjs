import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { activateStableS37ProductHostV01 } from "../../dist/run/s37-product-host-activation-v01.js";
import { runS37ProductHostActivationAdapterTransportV01 } from "./activation-adapter-transport-v01.mjs";

const HOLD = Object.freeze({ ok: false, outcome: "HOLD_PRECONDITION" });

export function commandS37ProductHostActivateStableV01(input) {
  if (input === undefined) return HOLD;
  return activateStableS37ProductHostV01(input);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runS37ProductHostActivationAdapterTransportV01({
    argv: process.argv,
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
    invocation_diagnostic: "HOLD: activate-stable requires bounded owned-byte input from the root command host\n",
    expected_keys: Object.freeze(["proof_request_bytes", "qualification_intent_bytes"]),
    invoke: commandS37ProductHostActivateStableV01,
  });
}

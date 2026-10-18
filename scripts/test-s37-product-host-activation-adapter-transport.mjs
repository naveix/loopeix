import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";

import { runS37ProductHostActivationAdapterTransportV01 } from "./s37-linux-product-host-v03/activation-adapter-transport-v01.mjs";

const KEYS = Object.freeze(["proof_request_bytes", "qualification_intent_bytes"]);
const ID = "activation_" + "a".repeat(64);
const HASH = "sha256:" + "b".repeat(64);

function captureWritable(options = {}) {
  let text = "";
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      if (options.fail) callback(new Error("closed"));
      else { text += chunk.toString(); callback(); }
    },
  });
  stream.on("error", () => {});
  return { stream, text: () => text };
}

async function run(frame, invoke, options = {}) {
  const stdout = captureWritable({ fail: options.failOutput });
  const stderr = captureWritable();
  const code = await runS37ProductHostActivationAdapterTransportV01({
    argv: options.argv ?? ["/usr/bin/node", "/adapter.mjs", "--stdin-json-v01"],
    stdin: Readable.from([frame]),
    stdout: stdout.stream,
    stderr: stderr.stream,
    expected_keys: KEYS,
    invoke,
  });
  return { code, stdout: stdout.text(), stderr: stderr.text() };
}

{
  let calls = 0;
  const seen = [];
  const frame = JSON.stringify({ proof_request_bytes: "YQ==", qualification_intent_bytes: "Yg==" }) + "\n";
  const result = await run(frame, (input) => {
    calls += 1;
    seen.push(input.proof_request_bytes, input.qualification_intent_bytes);
    return { ok: true, outcome: "COMPLETED", activation_id: ID, evidence_hash: HASH };
  });
  assert.equal(calls, 1);
  assert.equal(result.code, 0);
  assert.equal(result.stderr, "");
  assert.equal(result.stdout, JSON.stringify({ ok: true, outcome: "COMPLETED", activation_id: ID, evidence_hash: HASH }) + "\n");
  assert.deepEqual(seen.map((bytes) => Buffer.from(bytes).toString()), ["a", "b"]);
  assert.ok(seen.every((bytes) => bytes instanceof Uint8Array && !(bytes instanceof Buffer)
    && bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength && !bytes.buffer.resizable));
}

{
  let calls = 0;
  const stdout = captureWritable();
  const stderr = captureWritable();
  const code = await runS37ProductHostActivationAdapterTransportV01({
    argv: ["/usr/bin/node", "/reconcile-anchor.mjs", "--stdin-json-v01"],
    stdin: Readable.from(["{}\n"]),
    stdout: stdout.stream,
    stderr: stderr.stream,
    expected_keys: Object.freeze([]),
    invoke: (input) => {
      calls += 1;
      assert.deepEqual(input, {});
      return { ok: false, outcome: "NOT_STARTED", activation_id: null, evidence_hash: null };
    },
  });
  assert.equal(calls, 1);
  assert.equal(code, 20);
  assert.equal(stderr.text(), "");
}

for (const [name, frame] of [
  ["reordered keys", JSON.stringify({ qualification_intent_bytes: "Yg==", proof_request_bytes: "YQ==" }) + "\n"],
  ["noncanonical JSON", "{ \"proof_request_bytes\":\"YQ==\",\"qualification_intent_bytes\":\"Yg==\"}\n"],
  ["noncanonical base64", JSON.stringify({ proof_request_bytes: "YQ", qualification_intent_bytes: "Yg==" }) + "\n"],
  ["extra framing", JSON.stringify({ proof_request_bytes: "YQ==", qualification_intent_bytes: "Yg==" }) + "\n\n"],
  ["oversize field", JSON.stringify({
    proof_request_bytes: Buffer.alloc(65_537).toString("base64"),
    qualification_intent_bytes: "Yg==",
  }) + "\n"],
  ["oversize frame", "x".repeat(200_001)],
]) {
  let calls = 0;
  const result = await run(frame, () => { calls += 1; return null; });
  assert.equal(calls, 0, name);
  assert.equal(result.code, 64, name);
  assert.equal(result.stdout, "", name);
  assert.ok(result.stderr.length > 0 && result.stderr.length < 100, name);
}

{
  let calls = 0;
  const frame = JSON.stringify({ proof_request_bytes: "YQ==", qualification_intent_bytes: "Yg==" }) + "\n";
  const result = await run(frame, () => { calls += 1; return null; }, { argv: ["node", "adapter.mjs"] });
  assert.equal(calls, 0);
  assert.equal(result.code, 64);
  assert.equal(result.stdout, "");
}

for (const [outcome, code] of [
  ["NOT_STARTED", 20],
  ["NOT_COMMITTED", 21],
  ["RECOVERY_REQUIRED", 22],
  ["OUTCOME_UNKNOWN", 23],
]) {
  const frame = JSON.stringify({ proof_request_bytes: "YQ==", qualification_intent_bytes: "Yg==" }) + "\n";
  const result = await run(frame, () => ({ ok: false, outcome, activation_id: null, evidence_hash: null }));
  assert.equal(result.code, code, outcome);
  assert.equal(result.stdout, JSON.stringify({ ok: false, outcome, activation_id: null, evidence_hash: null }) + "\n", outcome);
}

{
  let calls = 0;
  const frame = JSON.stringify({ proof_request_bytes: "YQ==", qualification_intent_bytes: "Yg==" }) + "\n";
  const result = await run(frame, () => {
    calls += 1;
    return { ok: false, outcome: "RECOVERY_REQUIRED", activation_id: ID, evidence_hash: HASH };
  }, { failOutput: true });
  assert.equal(calls, 1);
  assert.equal(result.code, 74);
}

process.stdout.write("S37 activation adapter transport self-test passed\n");

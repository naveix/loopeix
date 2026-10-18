const MAX_FIELD_BYTES = 65_536;
const MAX_STDIN_BYTES = 200_000;
const INPUT_FLAG = "--stdin-json-v01";

const EXIT_BY_OUTCOME = Object.freeze({
  COMPLETED: 0,
  NOT_STARTED: 20,
  NOT_COMMITTED: 21,
  RECOVERY_REQUIRED: 22,
  OUTCOME_UNKNOWN: 23,
});
const FAILURE_OUTCOMES = new Set(["NOT_STARTED", "NOT_COMMITTED", "RECOVERY_REQUIRED", "OUTCOME_UNKNOWN"]);

const ACTIVATION_ID = /^activation_[a-f0-9]{64}$/u;
const HASH = /^sha256:[a-f0-9]{64}$/u;
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

function ownedBytesFromBase64(value) {
  if (typeof value !== "string" || !CANONICAL_BASE64.test(value)) return null;
  const decoded = Buffer.from(value, "base64");
  if (decoded.byteLength > MAX_FIELD_BYTES || decoded.toString("base64") !== value) return null;
  return Uint8Array.from(decoded);
}

function decodeInput(frame, expectedKeys) {
  if (!(frame instanceof Uint8Array) || frame.byteLength === 0 || frame.byteLength > MAX_STDIN_BYTES
    || frame[frame.byteLength - 1] !== 0x0a) return null;
  const bodyBytes = frame.subarray(0, frame.byteLength - 1);
  if (bodyBytes.includes(0x0a) || bodyBytes.includes(0x0d)) return null;
  let body;
  let parsed;
  try {
    body = new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes);
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
    || Object.getPrototypeOf(parsed) !== Object.prototype
    || JSON.stringify(parsed) !== body) return null;
  const keys = Object.keys(parsed);
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) return null;
  const input = {};
  for (const key of expectedKeys) {
    const bytes = ownedBytesFromBase64(parsed[key]);
    if (bytes === null) return null;
    input[key] = bytes;
  }
  return Object.freeze(input);
}

async function readFrame(stream) {
  const chunks = [];
  let length = 0;
  for await (const chunk of stream) {
    const bytes = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : Buffer.from(chunk);
    length += bytes.byteLength;
    if (length > MAX_STDIN_BYTES) return null;
    chunks.push(bytes);
  }
  return Uint8Array.from(Buffer.concat(chunks, length));
}

function normalizeOutcome(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const keys = Object.keys(value);
  const expected = ["ok", "outcome", "activation_id", "evidence_hash"];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) return null;
  if (value.ok === true && value.outcome === "COMPLETED"
    && typeof value.activation_id === "string" && ACTIVATION_ID.test(value.activation_id)
    && typeof value.evidence_hash === "string" && HASH.test(value.evidence_hash)) {
    return Object.freeze({
      ok: true,
      outcome: "COMPLETED",
      activation_id: value.activation_id,
      evidence_hash: value.evidence_hash,
    });
  }
  if (value.ok !== false || !FAILURE_OUTCOMES.has(value.outcome)) return null;
  const bothNull = value.activation_id === null && value.evidence_hash === null;
  const bothPresent = typeof value.activation_id === "string" && ACTIVATION_ID.test(value.activation_id)
    && typeof value.evidence_hash === "string" && HASH.test(value.evidence_hash);
  if (!bothNull && !bothPresent) return null;
  return Object.freeze({
    ok: false,
    outcome: value.outcome,
    activation_id: value.activation_id,
    evidence_hash: value.evidence_hash,
  });
}

function writeOnce(stream, bytes) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      stream.off?.("error", onError);
      resolve(ok);
    };
    const onError = () => finish(false);
    stream.once?.("error", onError);
    try {
      stream.write(bytes, (error) => finish(error === undefined || error === null));
    } catch {
      finish(false);
    }
  });
}

function boundedDiagnostic(stream, message) {
  try { stream.write(message); } catch { /* A diagnostic channel is not an authority or retry path. */ }
}

export async function runS37ProductHostActivationAdapterTransportV01(options) {
  const {
    argv, stdin, stdout, stderr, expected_keys: expectedKeys, invoke,
    invocation_diagnostic: invocationDiagnostic = "invalid S37 activation adapter invocation\n",
  } = options;
  if (!Array.isArray(argv) || argv.length !== 3 || typeof argv[0] !== "string" || argv[0].length === 0
    || typeof argv[1] !== "string" || argv[1].length === 0 || argv[2] !== INPUT_FLAG
    || !Array.isArray(expectedKeys) || typeof invoke !== "function") {
    boundedDiagnostic(stderr, typeof invocationDiagnostic === "string" && invocationDiagnostic.length <= 160
      ? invocationDiagnostic : "invalid S37 activation adapter invocation\n");
    return 64;
  }
  let frame;
  try { frame = await readFrame(stdin); } catch { frame = null; }
  const input = frame === null ? null : decodeInput(frame, expectedKeys);
  if (input === null) {
    boundedDiagnostic(stderr, "invalid S37 activation adapter input\n");
    return 64;
  }
  let outcome;
  try { outcome = normalizeOutcome(await invoke(input)); } catch { outcome = null; }
  if (outcome === null) {
    outcome = Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null });
  }
  const written = await writeOnce(stdout, JSON.stringify(outcome) + "\n");
  if (!written) {
    boundedDiagnostic(stderr, "S37 activation adapter output failure\n");
    return 74;
  }
  return EXIT_BY_OUTCOME[outcome.outcome];
}

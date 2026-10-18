// Test-only subprocess harness. tsx is pinned by the parent to the installed loader;
// production sources are loaded directly, never from possibly stale dist output.
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { lstat, open, readdir, readFile, realpath, rename, stat, unlink } from "node:fs/promises";
import { basename, join } from "node:path";

import {
  commitS37ProductHostActivationEventV01,
  commitS37ProductHostAuthorizationNonceV01,
  createS37ProductHostActivationStoreForTestV01,
  disposeS37ProductHostActivationStoreV01,
  openS37ProductHostActivationStoreSessionV01,
  reconcileS37ProductHostActivationStoreV01,
} from "../../src/run/s37-product-host-activation-store-v01.ts";

const hash = (character) => `sha256:${character.repeat(64)}`;
const request = hash("1");
const activationId = `activation_${request.slice(7)}`;
const nonce = Object.freeze({
  authenticated_principal_ref: "operator_1", approval_nonce: hash("7"), domain: "primary-v02",
  run_id: "run_process_1", authorization_id: "authorization_process_1", authorization_statement_hash: hash("8"),
});
const requestedEvent = Object.freeze({
  operation: "install-and-launch", event_type: "activation.requested", anchor_generation: 1,
  anchor_hash: hash("a"), controller_uid: 64037,
  payload: {
    request_hash: request, bundle_hash: hash("2"), proof_request_hash: hash("3"),
    qualification_intent_hash: hash("4"), action_scope_hash: hash("5"), initial_absence_observation_hash: hash("6"),
  },
});

function report(message) {
  return new Promise((resolve, reject) => {
    if (process.send === undefined) { reject(new Error("IPC unavailable")); return; }
    process.send(message, (error) => error ? reject(error) : resolve());
  });
}

async function stoppedAt(stage) {
  await report({ type: "checkpoint", stage });
  // Only the parent can end this checkpoint, using an actual SIGKILL.
  await new Promise(() => {});
}

async function snapshot(root) {
  const rows = [];
  for (const name of (await readdir(join(root, "activation"))).sort()) {
    const path = join(root, "activation", name);
    const info = await lstat(path, { bigint: true });
    if (!info.isFile() || info.isSymbolicLink()) throw new Error("unexpected activation entry");
    rows.push({
      name, bytes: (await readFile(path)).toString("base64"), inode: String(info.ino),
      mode: String(info.mode), size: String(info.size), links: String(info.nlink),
      mtime: String(info.mtimeNs), ctime: String(info.ctimeNs),
    });
  }
  return rows;
}

async function main() {
  const [root, mode] = process.argv.slice(2);
  if (typeof root !== "string" || !basename(root).startsWith("loopeix-s37-g5-process-")
    || await realpath(root) !== root || !["race", "lock", "nonce", "event-one", "ledger-rename", "recover"].includes(mode)) {
    throw new Error("invalid process test fixture");
  }
  const owner = await stat(root, { bigint: true });
  const io = {
    lstat: (path) => lstat(path, { bigint: true }), realpath, open, unlink,
    random_bytes: (size) => randomBytes(size),
    rename: async (source, destination) => {
      await rename(source, destination);
      if (mode === "ledger-rename" && destination === join(root, "activation", "activation-ledger.jsonl")) {
        await stoppedAt("ledger-rename");
      }
    },
  };
  const captured = await createS37ProductHostActivationStoreForTestV01({
    root_path: root, owner_uid: owner.uid, owner_gid: owner.gid, io,
  });
  if (!captured.ok) throw new Error(captured.error);
  // Install the receive listener before acknowledging readiness to avoid lost starts.
  const start = once(process, "message");
  await report({ type: "ready", pid: process.pid });
  const [command] = await start;
  if (command?.type !== "start") throw new Error("unexpected IPC command");

  if (mode === "recover") {
    const before = await snapshot(root);
    const first = await reconcileS37ProductHostActivationStoreV01(captured.store);
    const middle = await snapshot(root);
    const second = await reconcileS37ProductHostActivationStoreV01(captured.store);
    const reopen = await openS37ProductHostActivationStoreSessionV01(captured.store, {
      activation_id: activationId, activation_request_hash: request, boot_id_hash: hash("b"),
    });
    const after = await snapshot(root);
    if (!await disposeS37ProductHostActivationStoreV01(captured.store)) throw new Error("recovery dispose failed");
    await report({ type: "recovered", first, second, reopen, before, middle, after });
    process.disconnect();
    return;
  }

  const opened = await openS37ProductHostActivationStoreSessionV01(captured.store, {
    activation_id: activationId, activation_request_hash: request, boot_id_hash: hash("b"),
  });
  if (!opened.ok) {
    await report({ type: "result", won: false, result: opened });
    if (!await disposeS37ProductHostActivationStoreV01(captured.store)) throw new Error("loser dispose failed");
    process.disconnect();
    return;
  }
  if (mode === "race") {
    // A real, durable, create-new effect witness is reachable only by the lock owner.
    // This is a test witness, not a production dispatch or a simulated broker success.
    const handle = await open(join(root, "effect-sentinel"), "wx", 0o600);
    try { await handle.writeFile(`${process.pid}\n`); await handle.sync(); } finally { await handle.close(); }
    const directory = await open(root, "r");
    try { await directory.sync(); } finally { await directory.close(); }
    await report({ type: "result", won: true, pid: process.pid });
    await stoppedAt("race-winner");
  }
  if (mode === "lock") await stoppedAt("lock");
  const committedNonce = await commitS37ProductHostAuthorizationNonceV01(opened.session, nonce);
  if (!committedNonce.ok) throw new Error(`nonce commit failed: ${JSON.stringify(committedNonce)}`);
  if (mode === "nonce") await stoppedAt("nonce");
  const event = await commitS37ProductHostActivationEventV01(opened.session, requestedEvent);
  if (!event.ok) throw new Error(`event commit failed: ${JSON.stringify(event)}`);
  await stoppedAt("event-one");
}

main().catch(async (error) => {
  process.exitCode = 1;
  try { await report({ type: "fatal", error: error instanceof Error ? error.message : String(error) }); }
  catch (reportError) { console.error("worker error could not be reported", reportError); }
  if (process.connected) process.disconnect();
});

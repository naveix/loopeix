import { fork, type ChildProcess } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

type Message = Readonly<Record<string, unknown>> & { type: string };
const require = createRequire(import.meta.url);
const loader = pathToFileURL(require.resolve("tsx")).href;
const workerPath = fileURLToPath(new URL("../helpers/s37-activation-process-worker.mjs", import.meta.url));
const roots: string[] = [];
const workers: ProcessWorker[] = [];

class ProcessWorker {
  readonly child: ChildProcess;
  readonly exit: Promise<Readonly<{ code: number | null; signal: NodeJS.Signals | null }>>;
  closed = false;
  private readonly messages: Message[] = [];
  private readonly listeners = new Set<() => void>();
  private stderr = "";

  constructor(root: string, mode: string, executable = process.execPath) {
    this.child = fork(workerPath, [root, mode], {
      execPath: executable,
      execArgv: ["--import", loader], stdio: ["ignore", "ignore", "pipe", "ipc"],
      cwd: resolve(fileURLToPath(new URL("../../", import.meta.url))),
    });
    this.child.stderr?.on("data", (bytes: Buffer) => { this.stderr = (this.stderr + bytes.toString()).slice(-8192); });
    this.child.on("message", (message: unknown) => {
      if (message !== null && typeof message === "object" && "type" in message && typeof message.type === "string") {
        this.messages.push(message as Message);
        for (const listener of this.listeners) listener();
      }
    });
    // close also fires after spawn errors where exit never fires.
    this.exit = new Promise((fulfill) => {
      this.child.once("error", (error) => {
        this.messages.push({ type: "fatal", error: error.message });
        for (const listener of this.listeners) listener();
      });
      this.child.once("close", (code, signal) => {
        this.closed = true;
        fulfill({ code, signal });
        for (const listener of this.listeners) listener();
      });
    });
    workers.push(this);
  }

  async next(type: string): Promise<Message> {
    return new Promise((fulfill, reject) => {
      const timer = setTimeout(() => finish(new Error(`worker ${type} timed out: ${this.stderr}`)), 15_000);
      const finish = (error?: Error, message?: Message): void => {
        clearTimeout(timer);
        this.listeners.delete(check);
        if (error !== undefined) reject(error);
        else if (message !== undefined) fulfill(message);
      };
      const check = (): void => {
        const fatal = this.messages.find((message) => message.type === "fatal");
        if (fatal !== undefined) { finish(new Error(`worker failed: ${String(fatal.error)} ${this.stderr}`)); return; }
        const index = this.messages.findIndex((message) => message.type === type);
        if (index >= 0) { finish(undefined, this.messages.splice(index, 1)[0]); return; }
        if (this.closed || this.child.exitCode !== null || this.child.signalCode !== null) finish(new Error(`worker exited before ${type}: ${this.stderr}`));
      };
      this.listeners.add(check);
      check();
    });
  }

  start(): Promise<void> {
    return new Promise((fulfill, reject) => {
      this.child.send({ type: "start" }, (error: Error | null) => error ? reject(error) : fulfill());
    });
  }

  async kill(): Promise<void> {
    if (!this.closed && this.child.pid !== undefined && this.child.exitCode === null && this.child.signalCode === null) {
      if (!this.child.kill("SIGKILL")) throw new Error("test child SIGKILL was not delivered");
    }
    const ended = await this.waitForExit();
    expect(ended.signal).toBe("SIGKILL");
  }

  async waitForExit(): Promise<Readonly<{ code: number | null; signal: NodeJS.Signals | null }>> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        this.exit,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error(`child close timed out: ${this.stderr}`)), 5_000);
        }),
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }
}

function fixtureRoot(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-s37-g5-process-")));
  roots.push(root);
  chmodSync(root, 0o755);
  mkdirSync(join(root, "activation"), { mode: 0o700 });
  for (const name of ["activation-ledger.jsonl", "authorization-nonces.jsonl", "qualification-nonces.jsonl"]) {
    writeFileSync(join(root, "activation", name), "", { mode: 0o600 });
  }
  return root;
}

async function recoverInFreshProcess(root: string) {
  const recovery = new ProcessWorker(root, "recover");
  await recovery.next("ready");
  await recovery.start();
  const message = await recovery.next("recovered");
  expect(await recovery.waitForExit()).toEqual({ code: 0, signal: null });
  expect(message.first).toEqual(message.second);
  expect(message.first).toMatchObject({ outcome: "RECOVERY_REQUIRED" });
  expect(message.reopen).toMatchObject({ ok: false, outcome: "RECOVERY_REQUIRED" });
  expect(message.middle).toEqual(message.before);
  expect(message.after).toEqual(message.before);
  return message;
}

afterEach(async () => {
  const cleanup = await Promise.allSettled(workers.splice(0).map(async (worker) => {
    if (!worker.closed && worker.child.pid !== undefined && worker.child.exitCode === null && worker.child.signalCode === null) {
      if (!worker.child.kill("SIGKILL")) throw new Error("test child cleanup failed");
    }
    await worker.waitForExit();
  }));
  const failures = cleanup.filter((result) => result.status === "rejected");
  if (failures.length > 0) throw new Error(`worker cleanup failed; fixture roots retained: ${JSON.stringify(roots)}`);
  for (const root of roots.splice(0)) {
    if (!basename(root).startsWith("loopeix-s37-g5-process-") || realpathSync(root) !== root || !statSync(root).isDirectory()) {
      throw new Error("unsafe process fixture cleanup target");
    }
    await rm(root, { recursive: true, force: false });
  }
});

describe("S37 activation store real-process race and restart", () => {
  it("reports a failed spawn and accounts for close without waiting for an exit event", async () => {
    const root = fixtureRoot();
    const failed = new ProcessWorker(root, "lock", join(root, "missing-node-executable"));
    await expect(failed.next("ready")).rejects.toThrow("worker failed");
    expect((await failed.waitForExit()).code).not.toBe(0);
    expect(failed.closed).toBe(true);
    expect(readdirSync(join(root, "activation")).sort()).toEqual([
      "activation-ledger.jsonl", "authorization-nonces.jsonl", "qualification-nonces.jsonl",
    ]);
  });

  it("admits one of two IPC-barrier contenders and creates exactly one durable effect witness", async () => {
    const root = fixtureRoot();
    const contenders = [new ProcessWorker(root, "race"), new ProcessWorker(root, "race")];
    const ready = await Promise.all(contenders.map((worker) => worker.next("ready")));
    expect(new Set(ready.map((message) => message.pid)).size).toBe(2);
    await Promise.all(contenders.map((worker) => worker.start()));
    const outcomes = await Promise.all(contenders.map((worker) => worker.next("result")));
    expect(outcomes.filter((outcome) => outcome.won === true)).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.won === false)).toHaveLength(1);
    const winnerIndex = outcomes.findIndex((outcome) => outcome.won === true);
    const winner = contenders[winnerIndex]!;
    expect(readFileSync(join(root, "effect-sentinel"), "utf8")).toBe(`${outcomes[winnerIndex]!.pid}\n`);
    expect(statSync(join(root, "effect-sentinel")).nlink).toBe(1);
    expect(readdirSync(root).filter((name) => name === "effect-sentinel")).toHaveLength(1);
    expect(statSync(join(root, "activation", "activation.lock")).mode & 0o777).toBe(0o400);
    await winner.next("checkpoint");
    await winner.kill();
    await recoverInFreshProcess(root);
    expect(readFileSync(join(root, "effect-sentinel"), "utf8")).toBe(`${outcomes[winnerIndex]!.pid}\n`);
  }, 30_000);

  it.each(["lock", "nonce", "event-one", "ledger-rename"])(
    "SIGKILL at %s preserves the durable prefix and fresh-process reconciliation has no writes or dispatch",
    async (stage) => {
      const root = fixtureRoot();
      const writer = new ProcessWorker(root, stage);
      await writer.next("ready");
      await writer.start();
      expect(await writer.next("checkpoint")).toMatchObject({ stage });
      await writer.kill();
      const nonceBefore = readFileSync(join(root, "activation", "authorization-nonces.jsonl"), "utf8");
      const ledgerBefore = readFileSync(join(root, "activation", "activation-ledger.jsonl"), "utf8");
      if (stage === "lock") expect(nonceBefore).toBe("");
      else {
        const rows = nonceBefore.trim().split("\n").map((row) => JSON.parse(row));
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({ approval_nonce: `sha256:${"7".repeat(64)}`, sequence: 1 });
      }
      if (stage === "event-one" || stage === "ledger-rename") {
        expect(JSON.parse(ledgerBefore.trim())).toMatchObject({ event_type: "activation.requested", sequence: 1 });
      } else expect(ledgerBefore).toBe("");
      if (stage === "ledger-rename") expect(readdirSync(join(root, "activation"))).not.toContain("activation-manifest.json");
      await recoverInFreshProcess(root);
      expect(readFileSync(join(root, "activation", "authorization-nonces.jsonl"), "utf8")).toBe(nonceBefore);
      expect(readFileSync(join(root, "activation", "activation-ledger.jsonl"), "utf8")).toBe(ledgerBefore);
      expect(readdirSync(root)).not.toContain("effect-sentinel");
    }, 30_000,
  );
});

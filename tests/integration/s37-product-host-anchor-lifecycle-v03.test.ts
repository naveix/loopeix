import { describe, expect, it } from "vitest";

import {
  applyS37ProductHostAnchorMutationV03,
  observeS37ProductHostCustodyV03,
  reconcileS37ProductHostAnchorV03,
} from "../../src/run/s37-product-host-lifecycle-v03.js";
import {
  encodeV03,
  makeAnchorV03,
  makeAuthorizedMutationV03,
  makeLifecycleStateV03,
  makeTransitionLockV03,
  S37_V03_ANCHOR,
  S37_V03_LIFECYCLE,
  S37_V03_LOCK,
  S37_V03_PARENT,
} from "../helpers/s37-product-host-v03-fixtures.js";
import { createS37ProductHostIoHarness } from "../helpers/s37-product-host-v03-io-harness.js";

async function runMutation(
  harness: ReturnType<typeof createS37ProductHostIoHarness>,
  anchor: ReturnType<typeof makeAnchorV03>,
) {
  const authorized = await makeAuthorizedMutationV03(anchor);
  const result = applyS37ProductHostAnchorMutationV03(
    { authorization: authorized.authorization },
    { io: harness.io },
  );
  return { result, anchor: authorized.anchor };
}

describe("S37.1-F2 crash-safe product-host anchor lifecycle", () => {
  it("rejects a missing/invalid authorization capability before any filesystem call", () => {
    const harness = createS37ProductHostIoHarness();
    const result = applyS37ProductHostAnchorMutationV03(
      { authorization: Object.freeze({}) as never },
      { io: harness.io },
    );
    expect(result).toEqual({ ok: false, outcome: "HOLD_PRECONDITION" });
    expect(harness.trace).toEqual([]);
  });

  it("installs generation one through the exact durable lock and PREPARING-anchor-STABLE sandwich", async () => {
    const harness = createS37ProductHostIoHarness();
    const requestedAnchor = makeAnchorV03();
    const { result, anchor } = await runMutation(harness, requestedAnchor);
    const lock = makeTransitionLockV03(anchor);

    expect(result).toEqual({ ok: true, outcome: "INSTALLED", generation: 1, anchor_hash: anchor.anchor_hash });
    expect(harness.exists(S37_V03_LOCK)).toBe(false);
    expect(JSON.parse(harness.text(S37_V03_ANCHOR)!.slice(0, -1))).toEqual(anchor);
    expect(JSON.parse(harness.text(S37_V03_LIFECYCLE)!.slice(0, -1))).toMatchObject({
      status: "STABLE", generation: 1, stable_anchor_hash: anchor.anchor_hash,
    });
    expect(harness.publications.map(({ path, text }) => [path, JSON.parse(text).status ?? "ANCHOR"])).toEqual([
      [S37_V03_LIFECYCLE, "PREPARING"],
      [S37_V03_ANCHOR, "ANCHOR"],
      [S37_V03_LIFECYCLE, "STABLE"],
    ]);

    const suffix = lock.lock_hash.slice("sha256:".length);
    expect(harness.trace).toContain(`open:${S37_V03_PARENT}/.anchor.${suffix}.tmp`);
    expect(harness.trace.filter((row) => row === `open:${S37_V03_PARENT}/.lifecycle-state.${suffix}.tmp`)).toHaveLength(2);
    const lockOpen = harness.openCalls.find((row) => row.path === S37_V03_LOCK)!;
    expect(lockOpen.flags).toBe(
      harness.io.constants.O_WRONLY | harness.io.constants.O_CREAT | harness.io.constants.O_EXCL
      | harness.io.constants.O_NOFOLLOW | harness.io.constants.O_CLOEXEC
    );
    expect(lockOpen.mode).toBe(0o600);
    expect(harness.trace.indexOf(`fsync:${S37_V03_LOCK}`)).toBeLessThan(harness.trace.indexOf(`fsync:${S37_V03_PARENT}`));
    expect(harness.trace.indexOf(`unlink:${S37_V03_LOCK}`)).toBeGreaterThan(
      harness.trace.lastIndexOf(`rename:${S37_V03_PARENT}/.lifecycle-state.${suffix}.tmp->${S37_V03_LIFECYCLE}`),
    );
  });

  it("transitions only from the coherent current head to exactly generation plus one", async () => {
    const previous = makeAnchorV03();
    const previousState = makeLifecycleStateV03("STABLE", previous, null);
    const harness = createS37ProductHostIoHarness({
      [S37_V03_ANCHOR]: encodeV03(previous),
      [S37_V03_LIFECYCLE]: encodeV03(previousState),
    });
    const next = await makeAuthorizedMutationV03(makeAnchorV03(2, previous.anchor_hash));

    expect(applyS37ProductHostAnchorMutationV03({ authorization: next.authorization }, { io: harness.io })).toEqual({
      ok: true, outcome: "TRANSITIONED", generation: 2, anchor_hash: next.anchor.anchor_hash,
    });
    expect(JSON.parse(harness.text(S37_V03_ANCHOR)!.slice(0, -1))).toEqual(next.anchor);
  });

  it("maps exclusive-create EEXIST to a no-retry concurrent HOLD without inspecting or replacing the lock", async () => {
    const anchor = makeAnchorV03();
    const harness = createS37ProductHostIoHarness({ [S37_V03_LOCK]: encodeV03(makeTransitionLockV03(anchor)) });
    expect((await runMutation(harness, anchor)).result).toEqual({ ok: false, outcome: "HOLD_CONCURRENT_TRANSITION" });
    expect(harness.trace.filter((row) => row === `open:${S37_V03_LOCK}`)).toHaveLength(1);
    expect(harness.trace.some((row) => row.startsWith("read:") || row.startsWith("unlink:") || row.startsWith("rename:"))).toBe(false);
  });

  it("distinguishes an untrusted parent precondition from incoherent root-file custody after lock ownership", async () => {
    const anchor = makeAnchorV03();
    const untrustedParent = createS37ProductHostIoHarness();
    untrustedParent.setMetadata(S37_V03_PARENT, { uid: 1n });
    expect((await runMutation(untrustedParent, anchor)).result).toEqual({ ok: false, outcome: "HOLD_PRECONDITION" });
    expect(untrustedParent.exists(S37_V03_LOCK)).toBe(false);

    const current = makeAnchorV03();
    const state = makeLifecycleStateV03("STABLE", current, null);
    const hardLinkedAnchor = createS37ProductHostIoHarness({
      [S37_V03_ANCHOR]: encodeV03(current),
      [S37_V03_LIFECYCLE]: encodeV03(state),
    });
    hardLinkedAnchor.setMetadata(S37_V03_ANCHOR, { nlink: 2n });
    const next = makeAnchorV03(2, current.anchor_hash);
    expect((await runMutation(hardLinkedAnchor, next)).result).toEqual({ ok: false, outcome: "RECOVERY_REQUIRED" });
    expect(hardLinkedAnchor.exists(S37_V03_LOCK)).toBe(true);
    expect(hardLinkedAnchor.publications).toEqual([]);
  });

  it.each([
    ["lock file sync", (lock: ReturnType<typeof makeTransitionLockV03>) => `fsync:${S37_V03_LOCK}`, 1],
    ["PREPARING rename", (lock: ReturnType<typeof makeTransitionLockV03>) => `rename:${S37_V03_PARENT}/.lifecycle-state.${lock.lock_hash.slice(7)}.tmp->${S37_V03_LIFECYCLE}`, 1],
    ["anchor file sync", (lock: ReturnType<typeof makeTransitionLockV03>) => `fsync:${S37_V03_PARENT}/.anchor.${lock.lock_hash.slice(7)}.tmp`, 1],
    ["anchor rename", (lock: ReturnType<typeof makeTransitionLockV03>) => `rename:${S37_V03_PARENT}/.anchor.${lock.lock_hash.slice(7)}.tmp->${S37_V03_ANCHOR}`, 1],
    ["STABLE directory sync", () => `fsync:${S37_V03_PARENT}`, 4],
    ["owned-lock unlink", () => `unlink:${S37_V03_LOCK}`, 1],
  ] as const)("returns OUTCOME_UNKNOWN without retry when %s fails", async (_name, label, occurrence) => {
    const requestedAnchor = makeAnchorV03();
    const authorized = await makeAuthorizedMutationV03(requestedAnchor);
    const lock = makeTransitionLockV03(authorized.anchor);
    const harness = createS37ProductHostIoHarness();
    const fault = label(lock);
    harness.fail(fault, occurrence);
    expect(applyS37ProductHostAnchorMutationV03({ authorization: authorized.authorization }, { io: harness.io }))
      .toEqual({ ok: false, outcome: "OUTCOME_UNKNOWN" });
    expect(harness.trace.filter((row) => row === fault)).toHaveLength(occurrence);
  });

  it("durably releases its owned lock before reporting a compare-and-swap precondition mismatch", async () => {
    const current = makeAnchorV03();
    const state = makeLifecycleStateV03("STABLE", current, null);
    const harness = createS37ProductHostIoHarness({
      [S37_V03_ANCHOR]: encodeV03(current),
      [S37_V03_LIFECYCLE]: encodeV03(state),
    });
    const skipped = makeAnchorV03(3, current.anchor_hash);
    expect((await runMutation(harness, skipped)).result).toEqual({ ok: false, outcome: "HOLD_PRECONDITION" });
    expect(harness.exists(S37_V03_LOCK)).toBe(false);
    expect(harness.trace).toContain(`unlink:${S37_V03_LOCK}`);
    expect(harness.trace.indexOf(`unlink:${S37_V03_LOCK}`)).toBeLessThan(harness.trace.lastIndexOf(`fsync:${S37_V03_PARENT}`));
    expect(harness.publications).toEqual([]);
  });

  it("keeps the lock and requires recovery when initial-install custody is PREPARING or incoherent", async () => {
    const authorized = await makeAuthorizedMutationV03(makeAnchorV03());
    const preparing = makeLifecycleStateV03("PREPARING", authorized.anchor, null);
    const harness = createS37ProductHostIoHarness({
      [S37_V03_ANCHOR]: encodeV03(authorized.anchor),
      [S37_V03_LIFECYCLE]: encodeV03(preparing),
    });
    expect(applyS37ProductHostAnchorMutationV03({ authorization: authorized.authorization }, { io: harness.io }))
      .toEqual({ ok: false, outcome: "RECOVERY_REQUIRED" });
    expect(harness.exists(S37_V03_LOCK)).toBe(true);
    expect(harness.trace).not.toContain(`unlink:${S37_V03_LOCK}`);
    expect(harness.publications).toEqual([]);
  });

  it("revalidates exact lock ownership before release and leaves ambiguous custody fail-closed", async () => {
    const anchor = makeAnchorV03();
    const harness = createS37ProductHostIoHarness();
    harness.fail(`lstat:${S37_V03_LOCK}`, 2);
    expect((await runMutation(harness, anchor)).result).toEqual({ ok: false, outcome: "OUTCOME_UNKNOWN" });
    expect(harness.trace).not.toContain(`unlink:${S37_V03_LOCK}`);
  });

  it("observes coherent custody stably and reconciles lock/PREPARING custody read-only", () => {
    const anchor = makeAnchorV03();
    const state = makeLifecycleStateV03("STABLE", anchor, null);
    const harness = createS37ProductHostIoHarness({
      [S37_V03_ANCHOR]: encodeV03(anchor),
      [S37_V03_LIFECYCLE]: encodeV03(state),
    });
    expect(observeS37ProductHostCustodyV03({ io: harness.io })).toEqual({
      ok: true, status: "STABLE", generation: 1, anchor_hash: anchor.anchor_hash,
    });
    expect(reconcileS37ProductHostAnchorV03({ io: harness.io })).toEqual({
      ok: true, status: "STABLE", generation: 1, anchor_hash: anchor.anchor_hash,
    });

    harness.put(S37_V03_LOCK, encodeV03(makeTransitionLockV03(anchor)));
    const before = [...harness.trace];
    expect(observeS37ProductHostCustodyV03({ io: harness.io })).toEqual({ ok: false, outcome: "ENFORCEMENT_UNAVAILABLE" });
    expect(reconcileS37ProductHostAnchorV03({ io: harness.io })).toEqual({ ok: false, outcome: "RECOVERY_REQUIRED" });
    expect(harness.exists(S37_V03_LOCK)).toBe(true);
    expect(harness.trace.slice(before.length).some((row) => row.startsWith("unlink:") || row.startsWith("rename:") || row.startsWith("write:"))).toBe(false);
  });

  it("fails closed when a transition lock appears between the two observation fences", () => {
    const anchor = makeAnchorV03();
    const state = makeLifecycleStateV03("STABLE", anchor, null);
    const harness = createS37ProductHostIoHarness({
      [S37_V03_ANCHOR]: encodeV03(anchor),
      [S37_V03_LIFECYCLE]: encodeV03(state),
    });
    harness.after(`lstat:${S37_V03_LOCK}`, 2, () => harness.put(S37_V03_LOCK, "busy\n"));
    expect(observeS37ProductHostCustodyV03({ io: harness.io }))
      .toEqual({ ok: false, outcome: "ENFORCEMENT_UNAVAILABLE" });
    expect(harness.exists(S37_V03_LOCK)).toBe(true);
  });

  it("uses the same two-lock fence for final post-release apply observation", async () => {
    const authorized = await makeAuthorizedMutationV03(makeAnchorV03());
    const harness = createS37ProductHostIoHarness();
    harness.after(`lstat:${S37_V03_LOCK}`, 5, () => harness.put(S37_V03_LOCK, "raced\n"));
    expect(applyS37ProductHostAnchorMutationV03({ authorization: authorized.authorization }, { io: harness.io }))
      .toEqual({ ok: false, outcome: "OUTCOME_UNKNOWN" });
    expect(harness.exists(S37_V03_LOCK)).toBe(true);
  });

  it("detects same-inode, same-size content mutation through nanosecond metadata during observe and apply", async () => {
    const current = makeAnchorV03();
    const currentBytes = encodeV03(current);
    const changedBytes = currentBytes.replace(current.anchor_hash, `sha256:${"0".repeat(64)}`);
    expect(Buffer.byteLength(changedBytes)).toBe(Buffer.byteLength(currentBytes));
    const state = makeLifecycleStateV03("STABLE", current, null);

    const observing = createS37ProductHostIoHarness({
      [S37_V03_ANCHOR]: currentBytes,
      [S37_V03_LIFECYCLE]: encodeV03(state),
    });
    observing.after(`fstat:${S37_V03_ANCHOR}`, 2, () => observing.replaceSameSize(S37_V03_ANCHOR, changedBytes));
    expect(observeS37ProductHostCustodyV03({ io: observing.io }))
      .toEqual({ ok: false, outcome: "ENFORCEMENT_UNAVAILABLE" });

    const applying = createS37ProductHostIoHarness({
      [S37_V03_ANCHOR]: currentBytes,
      [S37_V03_LIFECYCLE]: encodeV03(state),
    });
    applying.after(`fstat:${S37_V03_ANCHOR}`, 2, () => applying.replaceSameSize(S37_V03_ANCHOR, changedBytes));
    const next = await makeAuthorizedMutationV03(makeAnchorV03(2, current.anchor_hash));
    expect(applyS37ProductHostAnchorMutationV03({ authorization: next.authorization }, { io: applying.io }))
      .toEqual({ ok: false, outcome: "RECOVERY_REQUIRED" });
    expect(applying.exists(S37_V03_LOCK)).toBe(true);
  });
});

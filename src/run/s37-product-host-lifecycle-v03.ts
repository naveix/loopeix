import {
  constants,
  closeSync,
  fchmodSync,
  fchownSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";

import {
  canonicalV03,
  hashCanonicalV03,
  parseS37LocalProductHostAnchorV03,
  parseS37ProductHostLifecycleStateV01,
  parseS37ProductHostTransitionLockV01,
} from "./s37-product-host-contract-v03.js";
import {
  consumeAuthorizedS37AnchorMutationV03,
  type AuthorizedS37AnchorMutationV03,
  type S37AuthorizedAnchorMutationBindingV03,
} from "./s37-anchor-authorization-v03.js";

const S37_PRODUCT_HOST_PARENT_V03 = "/etc/loopeix/s37.1/product-host-v03";
const S37_PRODUCT_HOST_ANCHOR_PATH_V03 = `${S37_PRODUCT_HOST_PARENT_V03}/anchor.json`;
const S37_PRODUCT_HOST_LIFECYCLE_PATH_V03 = `${S37_PRODUCT_HOST_PARENT_V03}/lifecycle-state.json`;
const S37_PRODUCT_HOST_TRANSITION_LOCK_PATH_V03 = `${S37_PRODUCT_HOST_PARENT_V03}/transition.lock`;

type S37ProductHostStatV03 = Readonly<{
  dev: bigint;
  ino: bigint;
  uid: bigint;
  gid: bigint;
  mode: bigint;
  nlink: bigint;
  size: bigint;
  mtimeNs: bigint;
  ctimeNs: bigint;
  isFile(): boolean;
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
}>;

export type S37ProductHostLifecycleIoV03 = Readonly<{
  constants: Readonly<{
    O_RDONLY: number;
    O_WRONLY: number;
    O_CREAT: number;
    O_EXCL: number;
    O_NOFOLLOW: number;
    O_CLOEXEC: number;
    O_DIRECTORY: number;
  }>;
  lstatSync(path: string): S37ProductHostStatV03;
  realpathSync(path: string): string;
  openSync(path: string, flags: number, mode?: number): number;
  fstatSync(descriptor: number): S37ProductHostStatV03;
  readFileSync(descriptor: number): Uint8Array;
  writeFileSync(descriptor: number, bytes: Uint8Array): void;
  fsyncSync(descriptor: number): void;
  fchownSync(descriptor: number, uid: number, gid: number): void;
  fchmodSync(descriptor: number, mode: number): void;
  closeSync(descriptor: number): void;
  renameSync(source: string, destination: string): void;
  unlinkSync(path: string): void;
}>;

type AnchorRecord = Readonly<Record<string, unknown>> & Readonly<{
  generation: number;
  predecessor_anchor_hash: string | null;
  anchor_hash: string;
  anchor_subject_hash: string;
  installed_at: string;
  operator_authority: Readonly<{
    authorization_transaction_id: string;
    mutation_plan_hash: string;
    action_scope_hash: string;
    proof_record_hash: string;
  }>;
}>;

type LifecycleRecord = Readonly<Record<string, unknown>> & Readonly<{
  status: "PREPARING" | "STABLE";
  generation: number;
  stable_anchor_hash: string | null;
  state_hash: string;
}>;

type LockRecord = Readonly<Record<string, unknown>> & Readonly<{
  lock_hash: string;
  authorization_transaction_id: string;
}>;

type S37ProductHostMutationResultV03 =
  | Readonly<{ ok: true; outcome: "INSTALLED" | "TRANSITIONED"; generation: number; anchor_hash: string }>
  | Readonly<{ ok: false; outcome: "HOLD_PRECONDITION" | "HOLD_CONCURRENT_TRANSITION" | "OUTCOME_UNKNOWN" | "RECOVERY_REQUIRED" }>;

type S37ProductHostCustodyObservationV03 =
  | Readonly<{ ok: true; status: "UNINSTALLED" }>
  | Readonly<{ ok: true; status: "STABLE"; generation: number; anchor_hash: string }>
  | Readonly<{ ok: false; outcome: "ENFORCEMENT_UNAVAILABLE" }>;

type S37ProductHostReconcileResultV03 =
  | Readonly<{ ok: true; status: "UNINSTALLED" }>
  | Readonly<{ ok: true; status: "STABLE"; generation: number; anchor_hash: string }>
  | Readonly<{ ok: false; outcome: "RECOVERY_REQUIRED" }>;

type LifecycleDependencies = Readonly<{
  io?: S37ProductHostLifecycleIoV03;
}>;

type ReadResult<T> = Readonly<{ kind: "present"; value: T; canonical: string }>
  | Readonly<{ kind: "absent" }>
  | Readonly<{ kind: "invalid" }>;

function nodeConstants(): S37ProductHostLifecycleIoV03["constants"] {
  const values = constants as Readonly<Record<string, number>>;
  return Object.freeze({
    O_RDONLY: constants.O_RDONLY,
    O_WRONLY: constants.O_WRONLY,
    O_CREAT: constants.O_CREAT,
    O_EXCL: constants.O_EXCL,
    O_NOFOLLOW: constants.O_NOFOLLOW,
    O_CLOEXEC: values.O_CLOEXEC ?? 0,
    O_DIRECTORY: constants.O_DIRECTORY,
  });
}

const defaultIo: S37ProductHostLifecycleIoV03 = Object.freeze({
  constants: nodeConstants(),
  lstatSync: (path) => lstatSync(path, { bigint: true }),
  realpathSync,
  openSync,
  fstatSync: (descriptor) => fstatSync(descriptor, { bigint: true }),
  readFileSync: (descriptor) => new Uint8Array(readFileSync(descriptor)),
  writeFileSync: (descriptor, bytes) => writeFileSync(descriptor, bytes),
  fsyncSync,
  fchownSync,
  fchmodSync,
  closeSync,
  renameSync,
  unlinkSync,
});

function errorCode(error: unknown): string | null {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string"
    ? error.code
    : null;
}

function permissionMode(stat: S37ProductHostStatV03): bigint {
  return stat.mode & 0o7777n;
}

function sameIdentity(left: S37ProductHostStatV03, right: S37ProductHostStatV03): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.uid === right.uid && left.gid === right.gid && left.mode === right.mode && left.nlink === right.nlink
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function trustedParent(io: S37ProductHostLifecycleIoV03): number | null {
  let descriptor: number | null = null;
  try {
    const direct = io.lstatSync(S37_PRODUCT_HOST_PARENT_V03);
    if (!direct.isDirectory() || direct.isSymbolicLink() || direct.uid !== 0n || direct.gid !== 0n
      || permissionMode(direct) !== 0o755n || direct.nlink < 1n
      || io.realpathSync(S37_PRODUCT_HOST_PARENT_V03) !== S37_PRODUCT_HOST_PARENT_V03) return null;
    descriptor = io.openSync(
      S37_PRODUCT_HOST_PARENT_V03,
      io.constants.O_RDONLY | io.constants.O_DIRECTORY | io.constants.O_NOFOLLOW | io.constants.O_CLOEXEC,
    );
    const opened = io.fstatSync(descriptor);
    if (!opened.isDirectory() || !sameIdentity(direct, opened)) {
      io.closeSync(descriptor);
      return null;
    }
    return descriptor;
  } catch {
    if (descriptor !== null) {
      try { io.closeSync(descriptor); } catch { /* closed failure domain */ }
    }
    return null;
  }
}

function parentUnchanged(io: S37ProductHostLifecycleIoV03, descriptor: number): boolean {
  try {
    const direct = io.lstatSync(S37_PRODUCT_HOST_PARENT_V03);
    const opened = io.fstatSync(descriptor);
    return direct.isDirectory() && !direct.isSymbolicLink() && direct.uid === 0n && direct.gid === 0n
      && permissionMode(direct) === 0o755n && io.realpathSync(S37_PRODUCT_HOST_PARENT_V03) === S37_PRODUCT_HOST_PARENT_V03
      && sameIdentity(direct, opened);
  } catch { return false; }
}

function pathAbsent(io: S37ProductHostLifecycleIoV03, path: string): boolean | null {
  try { io.lstatSync(path); return false; }
  catch (error) { return errorCode(error) === "ENOENT" ? true : null; }
}

function canonicalBytes(value: unknown): Uint8Array | null {
  const canonical = canonicalV03(value);
  return canonical.ok ? Buffer.from(`${canonical.value}\n`, "utf8") : null;
}

function stableRead<T>(
  io: S37ProductHostLifecycleIoV03,
  parentDescriptor: number,
  path: string,
  parse: (candidate: unknown) => Readonly<{ ok: true; value: Readonly<Record<string, unknown>> } | { ok: false; error: string }>,
): ReadResult<T> {
  let descriptor: number | null = null;
  try {
    const before = io.lstatSync(path);
    if (!before.isFile() || before.isSymbolicLink() || before.uid !== 0n || before.gid !== 0n
      || permissionMode(before) !== 0o400n || before.nlink !== 1n || before.size < 2n || before.size > 65_537n) return { kind: "invalid" };
    descriptor = io.openSync(path, io.constants.O_RDONLY | io.constants.O_NOFOLLOW | io.constants.O_CLOEXEC);
    const opened = io.fstatSync(descriptor);
    if (!opened.isFile() || !sameIdentity(before, opened)) return { kind: "invalid" };
    const bytes = io.readFileSync(descriptor);
    const afterDescriptor = io.fstatSync(descriptor);
    const afterPath = io.lstatSync(path);
    if (BigInt(bytes.byteLength) !== before.size || !sameIdentity(opened, afterDescriptor)
      || !sameIdentity(opened, afterPath) || !parentUnchanged(io, parentDescriptor)) return { kind: "invalid" };
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (!text.endsWith("\n") || text.endsWith("\n\n")) return { kind: "invalid" };
    const body = text.slice(0, -1);
    const decoded: unknown = JSON.parse(body);
    const parsed = parse(decoded);
    if (!parsed.ok) return { kind: "invalid" };
    const canonical = canonicalV03(parsed.value);
    if (!canonical.ok || canonical.value !== body) return { kind: "invalid" };
    return { kind: "present", value: parsed.value as T, canonical: body };
  } catch (error) {
    return errorCode(error) === "ENOENT" ? { kind: "absent" } : { kind: "invalid" };
  } finally {
    if (descriptor !== null) {
      try { io.closeSync(descriptor); } catch { /* read result remains fail-closed */ }
    }
  }
}

function readAnchor(io: S37ProductHostLifecycleIoV03, parent: number): ReadResult<AnchorRecord> {
  return stableRead<AnchorRecord>(io, parent, S37_PRODUCT_HOST_ANCHOR_PATH_V03, parseS37LocalProductHostAnchorV03);
}

function readLifecycle(io: S37ProductHostLifecycleIoV03, parent: number): ReadResult<LifecycleRecord> {
  return stableRead<LifecycleRecord>(io, parent, S37_PRODUCT_HOST_LIFECYCLE_PATH_V03, parseS37ProductHostLifecycleStateV01);
}

function readLock(io: S37ProductHostLifecycleIoV03, parent: number): ReadResult<LockRecord> {
  return stableRead<LockRecord>(io, parent, S37_PRODUCT_HOST_TRANSITION_LOCK_PATH_V03, parseS37ProductHostTransitionLockV01);
}

function writeDurableFile(
  io: S37ProductHostLifecycleIoV03,
  path: string,
  bytes: Uint8Array,
): void {
  const descriptor = io.openSync(
    path,
    io.constants.O_WRONLY | io.constants.O_CREAT | io.constants.O_EXCL | io.constants.O_NOFOLLOW | io.constants.O_CLOEXEC,
    0o600,
  );
  try {
    io.writeFileSync(descriptor, bytes);
    io.fsyncSync(descriptor);
    io.fchownSync(descriptor, 0, 0);
    io.fchmodSync(descriptor, 0o400);
    io.fsyncSync(descriptor);
  } finally {
    io.closeSync(descriptor);
  }
}

function replaceDurably(
  io: S37ProductHostLifecycleIoV03,
  parent: number,
  temporaryPath: string,
  destination: string,
  value: unknown,
): void {
  const bytes = canonicalBytes(value);
  if (bytes === null) throw new Error("invalid durable value");
  writeDurableFile(io, temporaryPath, bytes);
  io.renameSync(temporaryPath, destination);
  io.fsyncSync(parent);
  if (!parentUnchanged(io, parent)) throw new Error("parent changed");
}

function buildState(
  status: "PREPARING" | "STABLE",
  anchor: AnchorRecord,
  stableAnchorHash: string | null,
): LifecycleRecord | null {
  const body = status === "PREPARING" ? {
    schema_version: "s37-product-host-lifecycle-state-v01",
    status,
    generation: anchor.generation,
    stable_anchor_hash: stableAnchorHash,
    expected_previous_anchor_hash: anchor.predecessor_anchor_hash,
    proposed_anchor_hash: anchor.anchor_hash,
    authorization_transaction_id: anchor.operator_authority.authorization_transaction_id,
    authorization_record_hash: anchor.operator_authority.proof_record_hash,
    updated_at: anchor.installed_at,
  } : {
    schema_version: "s37-product-host-lifecycle-state-v01",
    status,
    generation: anchor.generation,
    stable_anchor_hash: anchor.anchor_hash,
    expected_previous_anchor_hash: null,
    proposed_anchor_hash: null,
    authorization_transaction_id: null,
    authorization_record_hash: null,
    updated_at: anchor.installed_at,
  };
  const hash = hashCanonicalV03({ purpose: "s37-product-host-lifecycle-state-v01", ...body });
  if (!hash.ok) return null;
  const parsed = parseS37ProductHostLifecycleStateV01({ ...body, state_hash: hash.value });
  return parsed.ok ? parsed.value as LifecycleRecord : null;
}

function buildLock(binding: S37AuthorizedAnchorMutationBindingV03, anchor: AnchorRecord): LockRecord | null {
  const body = {
    schema_version: "s37-product-host-transition-lock-v01",
    operation: binding.operation,
    authorization_transaction_id: binding.authorization_transaction_id,
    generation: binding.generation,
    expected_previous_anchor_hash: binding.predecessor_anchor_hash,
    proposed_anchor_hash: anchor.anchor_hash,
    authorization_record_hash: binding.operator_authority.proof_record_hash,
  };
  const hash = hashCanonicalV03({ purpose: "s37-product-host-transition-lock-v01", ...body });
  if (!hash.ok) return null;
  const parsed = parseS37ProductHostTransitionLockV01({ ...body, lock_hash: hash.value });
  return parsed.ok ? parsed.value as LockRecord : null;
}

function exactEqual(left: unknown, right: unknown): boolean {
  const a = canonicalV03(left);
  const b = canonicalV03(right);
  return a.ok && b.ok && a.value === b.value;
}

function bindingMatchesAnchor(binding: S37AuthorizedAnchorMutationBindingV03, anchor: AnchorRecord): boolean {
  return binding.generation === anchor.generation
    && binding.predecessor_anchor_hash === anchor.predecessor_anchor_hash
    && binding.anchor_subject_hash === anchor.anchor_subject_hash
    && binding.authorization_transaction_id === anchor.operator_authority.authorization_transaction_id
    && binding.mutation_plan_hash === anchor.operator_authority.mutation_plan_hash
    && binding.action_scope_hash === anchor.operator_authority.action_scope_hash
    && binding.proposed_anchor_hash === anchor.anchor_hash
    && exactEqual(binding.proposed_anchor, anchor)
    && binding.mutation_plan.purpose === "s37-anchor-mutation-plan-v03"
    && binding.mutation_plan.operation === binding.operation
    && binding.mutation_plan.authorization_transaction_id === binding.authorization_transaction_id
    && binding.mutation_plan.anchor_subject_hash === binding.anchor_subject_hash
    && binding.mutation_plan.anchor_path === S37_PRODUCT_HOST_ANCHOR_PATH_V03
    && binding.mutation_plan.lifecycle_path === S37_PRODUCT_HOST_LIFECYCLE_PATH_V03
    && binding.mutation_plan.generation === binding.generation
    && binding.mutation_plan.predecessor_anchor_hash === binding.predecessor_anchor_hash
    && exactEqual(binding.operator_authority, anchor.operator_authority);
}

function coherentStable(
  first: ReadResult<LifecycleRecord>,
  anchor: ReadResult<AnchorRecord>,
  second: ReadResult<LifecycleRecord>,
): Readonly<{ generation: number; anchor_hash: string }> | null {
  if (first.kind !== "present" || anchor.kind !== "present" || second.kind !== "present"
    || first.canonical !== second.canonical || first.value.status !== "STABLE"
    || first.value.generation !== anchor.value.generation
    || first.value.stable_anchor_hash !== anchor.value.anchor_hash) return null;
  return Object.freeze({ generation: anchor.value.generation, anchor_hash: anchor.value.anchor_hash });
}

function releaseOwnedLock(
  io: S37ProductHostLifecycleIoV03,
  parent: number,
  lock: LockRecord,
): boolean {
  const captured = readLock(io, parent);
  if (captured.kind !== "present" || !exactEqual(captured.value, lock)) return false;
  io.unlinkSync(S37_PRODUCT_HOST_TRANSITION_LOCK_PATH_V03);
  io.fsyncSync(parent);
  return pathAbsent(io, S37_PRODUCT_HOST_TRANSITION_LOCK_PATH_V03) === true && parentUnchanged(io, parent);
}

export function applyS37ProductHostAnchorMutationV03(
  input: Readonly<{ authorization: AuthorizedS37AnchorMutationV03 }>,
  dependencies: LifecycleDependencies = {},
): S37ProductHostMutationResultV03 {
  let binding: S37AuthorizedAnchorMutationBindingV03 | null;
  try { binding = consumeAuthorizedS37AnchorMutationV03(input?.authorization); } catch { binding = null; }
  if (binding === null) {
    return Object.freeze({ ok: false, outcome: "HOLD_PRECONDITION" });
  }
  const parsedAnchor = parseS37LocalProductHostAnchorV03(binding.proposed_anchor);
  if (!parsedAnchor.ok) return Object.freeze({ ok: false, outcome: "HOLD_PRECONDITION" });
  const anchor = parsedAnchor.value as AnchorRecord;
  if (!bindingMatchesAnchor(binding, anchor)) return Object.freeze({ ok: false, outcome: "HOLD_PRECONDITION" });
  const lock = buildLock(binding, anchor);
  if (lock === null) return Object.freeze({ ok: false, outcome: "HOLD_PRECONDITION" });
  const io = dependencies.io ?? defaultIo;
  const parent = trustedParent(io);
  if (parent === null) return Object.freeze({ ok: false, outcome: "HOLD_PRECONDITION" });
  let lockOwned = false;
  try {
    try {
      const bytes = canonicalBytes(lock);
      if (bytes === null) return Object.freeze({ ok: false, outcome: "HOLD_PRECONDITION" });
      writeDurableFile(io, S37_PRODUCT_HOST_TRANSITION_LOCK_PATH_V03, bytes);
      lockOwned = true;
      io.fsyncSync(parent);
      const capturedLock = readLock(io, parent);
      if (capturedLock.kind !== "present" || !exactEqual(capturedLock.value, lock)) {
        return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN" });
      }
    } catch (error) {
      if (!lockOwned && errorCode(error) === "EEXIST") {
        return Object.freeze({ ok: false, outcome: "HOLD_CONCURRENT_TRANSITION" });
      }
      return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN" });
    }

    const currentState = readLifecycle(io, parent);
    const currentAnchor = readAnchor(io, parent);
    let stableAnchorHash: string | null = null;
    let compareAndSwapMismatch = false;
    if (binding.operation === "install") {
      if (currentState.kind === "absent" && currentAnchor.kind === "absent") {
        compareAndSwapMismatch = false;
      } else {
        const secondState = readLifecycle(io, parent);
        const stable = coherentStable(currentState, currentAnchor, secondState);
        if (stable === null) return Object.freeze({ ok: false, outcome: "RECOVERY_REQUIRED" });
        compareAndSwapMismatch = true;
      }
    } else {
      const secondState = readLifecycle(io, parent);
      const stable = coherentStable(currentState, currentAnchor, secondState);
      if (stable === null) return Object.freeze({ ok: false, outcome: "RECOVERY_REQUIRED" });
      stableAnchorHash = stable.anchor_hash;
      compareAndSwapMismatch = stable.generation + 1 !== binding.generation
        || stable.anchor_hash !== binding.predecessor_anchor_hash;
    }
    if (compareAndSwapMismatch) {
      try {
        if (!releaseOwnedLock(io, parent, lock)) return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN" });
        return Object.freeze({ ok: false, outcome: "HOLD_PRECONDITION" });
      } catch { return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN" }); }
    }

    const preparing = buildState("PREPARING", anchor, stableAnchorHash);
    const stable = buildState("STABLE", anchor, null);
    if (preparing === null || stable === null) return Object.freeze({ ok: false, outcome: "HOLD_PRECONDITION" });
    const suffix = lock.lock_hash.slice("sha256:".length);
    const anchorTemp = `${S37_PRODUCT_HOST_PARENT_V03}/.anchor.${suffix}.tmp`;
    const lifecycleTemp = `${S37_PRODUCT_HOST_PARENT_V03}/.lifecycle-state.${suffix}.tmp`;
    try {
      replaceDurably(io, parent, lifecycleTemp, S37_PRODUCT_HOST_LIFECYCLE_PATH_V03, preparing);
      replaceDurably(io, parent, anchorTemp, S37_PRODUCT_HOST_ANCHOR_PATH_V03, anchor);
      replaceDurably(io, parent, lifecycleTemp, S37_PRODUCT_HOST_LIFECYCLE_PATH_V03, stable);
      const before = readLifecycle(io, parent);
      const observedAnchor = readAnchor(io, parent);
      const after = readLifecycle(io, parent);
      const coherent = coherentStable(before, observedAnchor, after);
      if (coherent === null || coherent.anchor_hash !== anchor.anchor_hash || coherent.generation !== anchor.generation) {
        return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN" });
      }
      if (!releaseOwnedLock(io, parent, lock)) return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN" });
      const final = observeWithParent(io, parent);
      if (!final.ok || final.status !== "STABLE" || final.anchor_hash !== anchor.anchor_hash) {
        return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN" });
      }
      return Object.freeze({
        ok: true,
        outcome: binding.operation === "install" ? "INSTALLED" : "TRANSITIONED",
        generation: anchor.generation,
        anchor_hash: anchor.anchor_hash,
      });
    } catch {
      return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN" });
    }
  } finally {
    try { io.closeSync(parent); } catch { /* public outcome is already fail-closed */ }
  }
}

function observeWithParent(
  io: S37ProductHostLifecycleIoV03,
  parent: number,
): S37ProductHostCustodyObservationV03 {
  if (pathAbsent(io, S37_PRODUCT_HOST_TRANSITION_LOCK_PATH_V03) !== true) {
    return Object.freeze({ ok: false, outcome: "ENFORCEMENT_UNAVAILABLE" });
  }
  const first = readLifecycle(io, parent);
  const anchor = readAnchor(io, parent);
  const second = readLifecycle(io, parent);
  if (pathAbsent(io, S37_PRODUCT_HOST_TRANSITION_LOCK_PATH_V03) !== true) {
    return Object.freeze({ ok: false, outcome: "ENFORCEMENT_UNAVAILABLE" });
  }
  if (first.kind === "absent" && anchor.kind === "absent" && second.kind === "absent") {
    return Object.freeze({ ok: true, status: "UNINSTALLED" });
  }
  const stable = coherentStable(first, anchor, second);
  return stable === null
    ? Object.freeze({ ok: false, outcome: "ENFORCEMENT_UNAVAILABLE" })
    : Object.freeze({ ok: true, status: "STABLE", ...stable });
}

export function observeS37ProductHostCustodyV03(
  dependencies: Readonly<{ io?: S37ProductHostLifecycleIoV03 }> = {},
): S37ProductHostCustodyObservationV03 {
  const io = dependencies.io ?? defaultIo;
  const parent = trustedParent(io);
  if (parent === null) return Object.freeze({ ok: false, outcome: "ENFORCEMENT_UNAVAILABLE" });
  try { return observeWithParent(io, parent); }
  finally { try { io.closeSync(parent); } catch { /* fail-closed observation */ } }
}

export function reconcileS37ProductHostAnchorV03(
  dependencies: Readonly<{ io?: S37ProductHostLifecycleIoV03 }> = {},
): S37ProductHostReconcileResultV03 {
  const io = dependencies.io ?? defaultIo;
  const parent = trustedParent(io);
  if (parent === null) return Object.freeze({ ok: false, outcome: "RECOVERY_REQUIRED" });
  try {
    if (pathAbsent(io, S37_PRODUCT_HOST_TRANSITION_LOCK_PATH_V03) !== true) {
      return Object.freeze({ ok: false, outcome: "RECOVERY_REQUIRED" });
    }
    const observed = observeWithParent(io, parent);
    return observed.ok
      ? observed
      : Object.freeze({ ok: false, outcome: "RECOVERY_REQUIRED" });
  } finally { try { io.closeSync(parent); } catch { /* read-only reconciliation stays closed */ } }
}

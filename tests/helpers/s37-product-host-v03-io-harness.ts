import type { S37ProductHostLifecycleIoV03 } from "../../src/run/s37-product-host-lifecycle-v03.js";
import { S37_V03_PARENT } from "./s37-product-host-v03-fixtures.js";

type Node = { kind: "file" | "directory"; bytes: Uint8Array; dev: bigint; ino: bigint; uid: bigint; gid: bigint; mode: bigint; nlink: bigint; mtimeNs: bigint; ctimeNs: bigint };
type Handle = { path: string; node: Node };

export function createS37ProductHostIoHarness(initial: Readonly<Record<string, string>> = {}) {
  const trace: string[] = [];
  const publications: Array<Readonly<{ path: string; text: string }>> = [];
  const nodes = new Map<string, Node>();
  const handles = new Map<number, Handle>();
  const failures = new Map<string, number>();
  const hooks = new Map<string, { remaining: number; callback: () => void }>();
  const hitCounts = new Map<string, number>();
  const openCalls: Array<Readonly<{ path: string; flags: number; mode: number | null }>> = [];
  let nextDescriptor = 10;
  let nextInode = 2n;
  let nextTimestamp = 10n;

  const makeNode = (kind: Node["kind"], text = "", mode = kind === "directory" ? 0o755n : 0o400n): Node => ({
    kind, bytes: Buffer.from(text, "utf8"), dev: 1n, ino: nextInode++, uid: 0n, gid: 0n, mode, nlink: 1n,
    mtimeNs: nextTimestamp++, ctimeNs: nextTimestamp++,
  });
  nodes.set(S37_V03_PARENT, makeNode("directory"));
  for (const [path, text] of Object.entries(initial)) nodes.set(path, makeNode("file", text));

  const hit = (label: string): void => {
    trace.push(label);
    const count = (hitCounts.get(label) ?? 0) + 1;
    hitCounts.set(label, count);
    const hook = hooks.get(label);
    if (hook !== undefined) {
      if (hook.remaining > 1) hook.remaining -= 1;
      else { hooks.delete(label); hook.callback(); }
    }
    const remaining = failures.get(label);
    if (remaining === undefined) return;
    if (remaining > 1) failures.set(label, remaining - 1);
    else {
      failures.delete(label);
      const error = new Error(`injected:${label}`) as NodeJS.ErrnoException;
      error.code = "EIO";
      throw error;
    }
  };
  const stat = (node: Node): ReturnType<S37ProductHostLifecycleIoV03["lstatSync"]> => ({
    dev: node.dev, ino: node.ino, uid: node.uid, gid: node.gid, mode: node.mode,
    nlink: node.nlink, size: BigInt(node.bytes.byteLength),
    mtimeNs: node.mtimeNs, ctimeNs: node.ctimeNs,
    isFile: () => node.kind === "file", isDirectory: () => node.kind === "directory",
    isSymbolicLink: () => false,
  });
  const requiredHandle = (descriptor: number): Handle => {
    const handle = handles.get(descriptor);
    if (handle === undefined) throw new Error(`bad descriptor ${descriptor}`);
    return handle;
  };

  const constants = Object.freeze({
    O_RDONLY: 1, O_WRONLY: 2, O_CREAT: 4, O_EXCL: 8, O_NOFOLLOW: 16,
    O_CLOEXEC: 32, O_DIRECTORY: 64,
  });
  const io: S37ProductHostLifecycleIoV03 = {
    constants,
    lstatSync(path) {
      hit(`lstat:${path}`);
      const node = nodes.get(path);
      if (node === undefined) { const error = new Error("missing") as NodeJS.ErrnoException; error.code = "ENOENT"; throw error; }
      return stat(node);
    },
    realpathSync(path) { hit(`realpath:${path}`); if (!nodes.has(path)) throw new Error("missing"); return path; },
    openSync(path, flags, mode) {
      hit(`open:${path}`);
      openCalls.push(Object.freeze({ path, flags, mode: mode ?? null }));
      let node = nodes.get(path);
      if ((flags & constants.O_CREAT) !== 0) {
        if (node !== undefined && (flags & constants.O_EXCL) !== 0) { const error = new Error("exists") as NodeJS.ErrnoException; error.code = "EEXIST"; throw error; }
        if (node === undefined) { node = makeNode("file", "", BigInt(mode ?? 0o600)); nodes.set(path, node); }
      }
      if (node === undefined) { const error = new Error("missing") as NodeJS.ErrnoException; error.code = "ENOENT"; throw error; }
      const descriptor = nextDescriptor++;
      handles.set(descriptor, { path, node });
      return descriptor;
    },
    fstatSync(descriptor) { const handle = requiredHandle(descriptor); hit(`fstat:${handle.path}`); return stat(handle.node); },
    readFileSync(descriptor) { const handle = requiredHandle(descriptor); hit(`read:${handle.path}`); return new Uint8Array(handle.node.bytes); },
    writeFileSync(descriptor, bytes) { const handle = requiredHandle(descriptor); hit(`write:${handle.path}`); handle.node.bytes = new Uint8Array(bytes); handle.node.mtimeNs = nextTimestamp++; handle.node.ctimeNs = nextTimestamp++; },
    fsyncSync(descriptor) { const handle = requiredHandle(descriptor); hit(`fsync:${handle.path}`); },
    fchownSync(descriptor, uid, gid) { const handle = requiredHandle(descriptor); hit(`fchown:${handle.path}`); handle.node.uid = BigInt(uid); handle.node.gid = BigInt(gid); handle.node.ctimeNs = nextTimestamp++; },
    fchmodSync(descriptor, mode) { const handle = requiredHandle(descriptor); hit(`fchmod:${handle.path}`); handle.node.mode = BigInt(mode); handle.node.ctimeNs = nextTimestamp++; },
    closeSync(descriptor) { const handle = requiredHandle(descriptor); hit(`close:${handle.path}`); handles.delete(descriptor); },
    renameSync(source, destination) {
      hit(`rename:${source}->${destination}`);
      const node = nodes.get(source);
      if (node === undefined) throw new Error("missing source");
      nodes.set(destination, node); nodes.delete(source);
      publications.push(Object.freeze({ path: destination, text: Buffer.from(node.bytes).toString("utf8") }));
    },
    unlinkSync(path) { hit(`unlink:${path}`); if (!nodes.delete(path)) { const error = new Error("missing") as NodeJS.ErrnoException; error.code = "ENOENT"; throw error; } },
  };

  return {
    io,
    trace,
    openCalls,
    publications,
    fail(label: string, occurrence = 1) { failures.set(label, occurrence); },
    after(label: string, occurrence: number, callback: () => void) { hooks.set(label, { remaining: occurrence, callback }); },
    put(path: string, text: string, metadata: Partial<Pick<Node, "uid" | "gid" | "mode" | "nlink">> = {}) {
      nodes.set(path, { ...makeNode("file", text), ...metadata });
    },
    setMetadata(path: string, metadata: Partial<Pick<Node, "uid" | "gid" | "mode" | "nlink">>) {
      const node = nodes.get(path);
      if (node === undefined) throw new Error(`missing harness path: ${path}`);
      Object.assign(node, metadata);
      node.ctimeNs = nextTimestamp++;
    },
    replaceSameSize(path: string, text: string) {
      const node = nodes.get(path);
      if (node === undefined) throw new Error(`missing harness path: ${path}`);
      const bytes = Buffer.from(text, "utf8");
      if (bytes.byteLength !== node.bytes.byteLength) throw new Error("replacement must preserve byte length");
      node.bytes = bytes;
      node.mtimeNs = nextTimestamp++;
      node.ctimeNs = nextTimestamp++;
    },
    text(path: string): string | null { const node = nodes.get(path); return node === undefined ? null : Buffer.from(node.bytes).toString("utf8"); },
    exists(path: string): boolean { return nodes.has(path); },
  };
}

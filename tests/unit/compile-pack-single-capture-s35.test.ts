import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseDirectChildName } from "../../src/io/captured-file.js";
import { openCompilePackCaptureSessionV02 } from "../../src/io/compile-pack-capture-v02.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function root(): string { const value = mkdtempSync(join(tmpdir(), "loopeix-pack-capture-")); roots.push(value); return value; }
function name(value: string) { const parsed = parseDirectChildName(value); if (parsed === null) throw new Error("invalid fixture name"); return parsed; }

describe("single-helper V02 compile-pack capture", () => {
  it("captures each member once in fixed order and returns defensive snapshots", async () => {
    const path = root(); writeFileSync(join(path, "pack-manifest.json"), "manifest\n"); writeFileSync(join(path, "work-item.json"), "work\n");
    const opened = await openCompilePackCaptureSessionV02(path); expect(opened.ok).toBe(true); if (!opened.ok) return;
    const listed = await opened.value.listDirectEntries(); expect(listed.ok).toBe(true);
    expect(opened.value.snapshotCapturedManifest().ok).toBe(false);
    expect((await opened.value.captureMember(name("pack-manifest.json"))).ok).toBe(true);
    const manifestSnapshot = opened.value.snapshotCapturedManifest(); expect(manifestSnapshot.ok).toBe(true);
    if (manifestSnapshot.ok) manifestSnapshot.value[0] = 0;
    const unchangedManifest = opened.value.snapshotCapturedManifest();
    expect(unchangedManifest.ok && new TextDecoder().decode(unchangedManifest.value)).toBe("manifest\n");
    expect((await opened.value.captureMember(name("pack-manifest.json"))).ok).toBe(false);
    expect(opened.value.snapshotCapturedManifest().ok).toBe(false);
    expect((await opened.value.captureMember(name("work-item.json"))).ok).toBe(false);

    const reopened = await openCompilePackCaptureSessionV02(path); expect(reopened.ok).toBe(true); if (!reopened.ok) return;
    expect((await reopened.value.captureMember(name("pack-manifest.json"))).ok).toBe(true);
    expect((await reopened.value.captureMember(name("work-item.json"))).ok).toBe(true);
    const sealed = await reopened.value.seal([name("pack-manifest.json"), name("work-item.json")], [name("pack-manifest.json"), name("work-item.json")]);
    expect(sealed.ok).toBe(true); if (!sealed.ok) return;
    writeFileSync(join(path, "work-item.json"), "changed\n");
    const first = sealed.value.snapshotMemberBytes(name("work-item.json")); expect(first.ok).toBe(true); if (!first.ok) return;
    first.value[0] = 0;
    const second = sealed.value.snapshotMemberBytes(name("work-item.json")); expect(second.ok && new TextDecoder().decode(second.value)).toBe("work\n");
    expect(sealed.value.schema_version).toBe("0.2");
    expect(reopened.value.snapshotCapturedManifest().ok).toBe(false);
    expect((await reopened.value.abort()).ok).toBe(false);
  });

  it("rejects symlink and non-regular members without following them", async () => {
    const path = root(); const target = join(path, "target.json"); writeFileSync(target, "{}\n"); symlinkSync(target, join(path, "link.json")); mkdirSync(join(path, "directory.json"));
    const opened = await openCompilePackCaptureSessionV02(path); expect(opened.ok).toBe(true); if (!opened.ok) return;
    expect((await opened.value.captureMember(name("link.json"))).ok).toBe(false);
    expect((await opened.value.captureMember(name("directory.json"))).ok).toBe(false);
    expect((await opened.value.abort()).ok).toBe(false);
  });

  it("rejects overlapping parent operations without corrupting the first capture", async () => {
    const path = root(); writeFileSync(join(path, "first.json"), "first\n"); writeFileSync(join(path, "second.json"), "second\n");
    const opened = await openCompilePackCaptureSessionV02(path); expect(opened.ok).toBe(true); if (!opened.ok) return;
    const first = opened.value.captureMember(name("first.json"));
    const overlapping = await opened.value.captureMember(name("second.json"));
    expect(overlapping).toMatchObject({ ok: false, reason: "INVALID_COMPILE_PACK" });
    expect((await first).ok).toBe(true);
    expect((await opened.value.captureMember(name("second.json"))).ok).toBe(true);
    expect((await opened.value.abort()).ok).toBe(true);
  });

  it("accepts the exact member ceiling and rejects one byte over", async () => {
    const exact = root(); writeFileSync(join(exact, "member.bin"), Buffer.alloc(4_194_304, 97));
    const first = await openCompilePackCaptureSessionV02(exact); expect(first.ok).toBe(true); if (!first.ok) return;
    expect((await first.value.captureMember(name("member.bin"))).ok).toBe(true); expect((await first.value.abort()).ok).toBe(true);
    const over = root(); writeFileSync(join(over, "member.bin"), Buffer.alloc(4_194_305, 97));
    const second = await openCompilePackCaptureSessionV02(over); expect(second.ok).toBe(true); if (!second.ok) return;
    expect(await second.value.captureMember(name("member.bin"))).toMatchObject({ ok: false, reason: "INPUT_TOO_LARGE" }); expect((await second.value.abort()).ok).toBe(false);
  }, 30_000);

  it("accepts exactly 32 MiB aggregate and rejects an additional byte", async () => {
    const path = root();
    const names = Array.from({ length: 8 }, (_, index) => name(`member-${index}.bin`));
    for (const member of names) writeFileSync(join(path, member), Buffer.alloc(4_194_304, 97));
    writeFileSync(join(path, "extra.bin"), "x");
    const opened = await openCompilePackCaptureSessionV02(path); expect(opened.ok).toBe(true); if (!opened.ok) return;
    for (const member of names) expect((await opened.value.captureMember(member)).ok).toBe(true);
    expect(await opened.value.captureMember(name("extra.bin"))).toMatchObject({ ok: false, reason: "INPUT_TOO_LARGE" });
    expect((await opened.value.abort()).ok).toBe(false);
  }, 30_000);
});

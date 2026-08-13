import { parseDirectChildName, type DirectChildName } from "../io/captured-file.js";
import {
  consumeRegisteredReadCompilePackV02,
  type ReadCompilePackV02Success,
  type V02ReplaySelector,
} from "./read-pack-v02.js";
import { regenerateCompilePackV02 } from "./serialize-v02.js";

export type ExactV02ReplaySuccess = Readonly<{
  schema_version: "0.2";
  selector: V02ReplaySelector;
  source_pack_root_hash: string;
  terminal_state: ReadCompilePackV02Success["manifest"]["terminal_state"];
  compared_member_count: number;
  readonly __exact_v02_replay_success: unique symbol;
}>;

export type ReplayCompilePackV02Result =
  | { ok: true; disposition: "replayed"; replay: ExactV02ReplaySuccess; reason: null; findings: [] }
  | {
      ok: false;
      disposition: "hold";
      schema_version: "0.2";
      source_pack_root_hash: null;
      compared_member_count: 0;
      reason: "INVALID_COMPILE_PACK";
      findings: [];
    };

const exactReplayRegistryV02 = new WeakMap<ExactV02ReplaySuccess, ReadCompilePackV02Success>();

function fixedName(value: string): DirectChildName {
  const parsed = parseDirectChildName(value);
  if (parsed === null) throw new Error("invalid fixed V02 replay member");
  return parsed;
}

function hold(): ReplayCompilePackV02Result {
  return {
    ok: false,
    disposition: "hold",
    schema_version: "0.2",
    source_pack_root_hash: null,
    compared_member_count: 0,
    reason: "INVALID_COMPILE_PACK",
    findings: [],
  };
}

export function replayCompilePackV02(read: ReadCompilePackV02Success): ReplayCompilePackV02Result {
  const pack = consumeRegisteredReadCompilePackV02(read);
  if (pack === null) return hold();
  const regenerated = regenerateCompilePackV02({
    work_item: read.work_item,
    binding_input: read.binding_input,
    compiler_bundle_id: read.selector.compiler_bundle_id,
    catalog_version_hash: read.selector.catalog_version_hash,
    verified_binding_input_hash: read.manifest.file_hashes.binding_input,
  });
  if (!regenerated.ok) return hold();

  const expectedNames = regenerated.pack_members
    .map(({ name }) => name)
    .filter((name) => name !== "binding-input.json");
  for (const name of expectedNames) {
    const actual = pack.snapshotMemberBytes(fixedName(name));
    const expected = regenerated.pack_members.find((member) => member.name === name);
    if (!actual.ok || expected === undefined || !Buffer.from(actual.value).equals(Buffer.from(expected.bytes))) return hold();
  }
  const bindingBytes = pack.snapshotMemberBytes(fixedName("binding-input.json"));
  if (!bindingBytes.ok) return hold();

  const replay = Object.freeze({
    schema_version: "0.2" as const,
    selector: Object.freeze({ ...read.selector }),
    source_pack_root_hash: pack.source_pack_root_hash,
    terminal_state: read.manifest.terminal_state,
    compared_member_count: expectedNames.length,
  }) as ExactV02ReplaySuccess;
  exactReplayRegistryV02.set(replay, read);
  return { ok: true, disposition: "replayed", replay, reason: null, findings: [] };
}

export function isRegisteredExactV02ReplaySuccess(replay: ExactV02ReplaySuccess): boolean {
  return exactReplayRegistryV02.has(replay);
}

export function consumeExactV02ReplayForPlanning(
  replay: ExactV02ReplaySuccess,
): ReadCompilePackV02Success | null {
  const read = exactReplayRegistryV02.get(replay);
  if (read === undefined) return null;
  exactReplayRegistryV02.delete(replay);
  return read;
}

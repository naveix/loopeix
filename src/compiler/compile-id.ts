import { randomBytes as secureRandomBytes } from "node:crypto";
import { join } from "node:path";
import { IsoTimestampV02, MachineIdV02, type MachineIdV02Value } from "../schema/scalars-v02.js";
import {
  revalidateCompileStoreV02,
  resolveVerifiedCompileStoreV02,
  type VerifiedCompileStoreV02,
} from "./compile-store.js";

const COMPILE_ID_ATTEMPTS = 16;

export type CompileIdentityV02 = Readonly<{
  compile_token: string;
  compile_id: MachineIdV02Value;
  compile_dir: string;
  submitted_at: string;
  work_item_id: MachineIdV02Value;
  intake_record_id: MachineIdV02Value;
  catalog_resolution_id: MachineIdV02Value;
  binding_input_id: MachineIdV02Value;
  compilation_record_id: MachineIdV02Value;
  intake_brief_id: MachineIdV02Value;
  pack_manifest_id: MachineIdV02Value;
}>;

export type CompileIdentityCommitResult<TCandidateFailure = never> =
  | { ok: true; pack_ref: MachineIdV02Value }
  | { ok: false; reason: "CANDIDATE_ABORTED"; failure: TCandidateFailure }
  | {
      ok: false;
      reason:
        | "DESTINATION_EXISTS"
        | "INVALID_OUTPUT_CAPTURE"
        | "OUTPUT_CAPTURE_FAILED"
        | "IO_HELPER_UNAVAILABLE"
        | "IO_IDENTITY_MISMATCH"
        | "IO_DURABILITY_UNCONFIRMED";
      message: string;
    };

export type CompileIdentityAllocationResultV02<TCandidateFailure = never> =
  | { ok: true; identity: CompileIdentityV02 }
  | { ok: false; reason: "CANDIDATE_ABORTED"; failure: TCandidateFailure }
  | {
      ok: false;
      reason:
        | "COMPILE_STORE_INVALID"
        | "COMPILE_ID_COLLISION_LIMIT"
        | "INVALID_OUTPUT_CAPTURE"
        | "OUTPUT_CAPTURE_FAILED"
        | "IO_HELPER_UNAVAILABLE"
        | "IO_IDENTITY_MISMATCH"
        | "IO_DURABILITY_UNCONFIRMED";
      message: string;
    };

export type CompileIdentityAllocatorOptions<TCandidateFailure = never> = Readonly<{
  now?: () => number;
  randomBytes?: (size: 8) => Uint8Array;
  /** Builds fresh candidate-bound output authority and commits it exactly once. */
  commitCandidate: (
    store: VerifiedCompileStoreV02,
    identity: CompileIdentityV02,
  ) => Promise<CompileIdentityCommitResult<TCandidateFailure>>;
}>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function machineId(value: string): MachineIdV02Value {
  return MachineIdV02.parse(value);
}

function timestampAtSecond(milliseconds: number): string {
  const value = new Date(milliseconds).toISOString();
  return IsoTimestampV02.parse(`${value.slice(0, 19)}Z`);
}


function deriveIdentity(token: string, compileDir: string, submittedAt: string): CompileIdentityV02 {
  return Object.freeze({
    compile_token: token,
    compile_id: machineId(`compile_${token}`),
    compile_dir: compileDir,
    submitted_at: submittedAt,
    work_item_id: machineId(`wi_${token}`),
    intake_record_id: machineId(`intake_${token}`),
    catalog_resolution_id: machineId(`resolution_${token}`),
    binding_input_id: machineId(`binding_${token}`),
    compilation_record_id: machineId(`compilation_${token}`),
    intake_brief_id: machineId(`brief_${token}`),
    pack_manifest_id: machineId(`pack_${token}`),
  });
}

export async function allocateAndCommitCompileIdentityV02<TCandidateFailure = never>(
  store: VerifiedCompileStoreV02,
  options: CompileIdentityAllocatorOptions<TCandidateFailure>,
): Promise<CompileIdentityAllocationResultV02<TCandidateFailure>> {
  const storeState = resolveVerifiedCompileStoreV02(store);
  if (storeState === null || !(await revalidateCompileStoreV02(store))) {
    return { ok: false, reason: "COMPILE_STORE_INVALID", message: "The compile-store authority is invalid." };
  }

  const now = options.now ?? Date.now;
  const randomBytes = options.randomBytes ?? ((size: 8) => secureRandomBytes(size));
  let milliseconds: number;
  let submittedAt: string;

  try {
    milliseconds = now();
    if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) {
      throw new RangeError("invalid compile clock");
    }
    submittedAt = timestampAtSecond(milliseconds);
  } catch {
    return {
      ok: false,
      reason: "IO_HELPER_UNAVAILABLE",
      message: "Compile identity entropy or clock generation failed.",
    };
  }

  const timestamp = milliseconds.toString(36);
  for (let attempt = 0; attempt < COMPILE_ID_ATTEMPTS; attempt += 1) {
    let entropyHex: string;
    try {
      const entropy = randomBytes(8);
      if (entropy.byteLength !== 8) throw new RangeError("invalid compile entropy length");
      entropyHex = Buffer.from(entropy).toString("hex");
    } catch {
      return {
        ok: false,
        reason: "IO_HELPER_UNAVAILABLE",
        message: "Compile identity entropy or clock generation failed.",
      };
    }

    const token = `${timestamp}_${entropyHex}`;
    const identity = deriveIdentity(token, join(storeState.path, machineId(`compile_${token}`)), submittedAt);
    let commit: CompileIdentityCommitResult<TCandidateFailure>;
    try {
      commit = await options.commitCandidate(store, identity);
    } catch {
      return {
        ok: false,
        reason: "IO_HELPER_UNAVAILABLE",
        message: "Required filesystem helper is unavailable.",
      };
    }

    if (!isRecord(commit) || typeof commit.ok !== "boolean") {
      return {
        ok: false,
        reason: "IO_HELPER_UNAVAILABLE",
        message: "Required filesystem helper is unavailable.",
      };
    }

    if (commit.ok) {
      return commit.pack_ref === identity.compile_id
        ? { ok: true, identity }
        : { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The compiler output authority or captured output is invalid." };
    }
    if (commit.reason === "CANDIDATE_ABORTED" && Object.hasOwn(commit, "failure")) {
      return { ok: false, reason: "CANDIDATE_ABORTED", failure: commit.failure };
    }
    if (commit.reason === "DESTINATION_EXISTS") continue;
    if (commit.reason === "INVALID_OUTPUT_CAPTURE") {
      return { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The compiler output authority or captured output is invalid." };
    }
    if (commit.reason === "OUTPUT_CAPTURE_FAILED") {
      return { ok: false, reason: "OUTPUT_CAPTURE_FAILED", message: "The compiler output could not be copied for persistence." };
    }
    if (commit.reason === "IO_HELPER_UNAVAILABLE") {
      return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "Required filesystem helper is unavailable." };
    }
    if (commit.reason === "IO_IDENTITY_MISMATCH") {
      return { ok: false, reason: "IO_IDENTITY_MISMATCH", message: "Filesystem identity validation failed." };
    }
    if (commit.reason === "IO_DURABILITY_UNCONFIRMED") {
      return { ok: false, reason: "IO_DURABILITY_UNCONFIRMED", message: "Filesystem durability could not be confirmed." };
    }
    return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "Required filesystem helper is unavailable." };
  }

  return {
    ok: false,
    reason: "COMPILE_ID_COLLISION_LIMIT",
    message: "Compile identity allocation exhausted its collision limit.",
  };
}

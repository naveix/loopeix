import { randomBytes as secureRandomBytes } from "node:crypto";

import { IsoTimestampV02, MachineIdV02 } from "../schema/scalars-v02.js";

const PLAN_ID_ATTEMPTS = 16;

export type PlanIdentityV02 = Readonly<{
  plan_token: string;
  run_id: string;
  created_at: string;
}>;

export type PlanIdentityCommitResult =
  | { ok: true; run_id: string }
  | {
      ok: false;
      reason:
        | "DESTINATION_EXISTS"
        | "INVALID_OUTPUT_CAPTURE"
        | "OUTPUT_CAPTURE_FAILED"
        | "OUTPUT_SCAN_FAILED"
        | "OUTPUT_HASH_FAILED"
        | "SENSITIVE_OUTPUT_REJECTED"
        | "IO_HELPER_UNAVAILABLE"
        | "IO_IDENTITY_MISMATCH"
        | "IO_DURABILITY_UNCONFIRMED";
      message: string;
    };

export type PlanIdentityAllocationResultV02 =
  | { ok: true; identity: PlanIdentityV02 }
  | {
      ok: false;
      reason:
        | "PLAN_ID_COLLISION_LIMIT"
        | "INVALID_OUTPUT_CAPTURE"
        | "OUTPUT_CAPTURE_FAILED"
        | "OUTPUT_SCAN_FAILED"
        | "OUTPUT_HASH_FAILED"
        | "SENSITIVE_OUTPUT_REJECTED"
        | "IO_HELPER_UNAVAILABLE"
        | "IO_IDENTITY_MISMATCH"
        | "IO_DURABILITY_UNCONFIRMED";
      message: string;
    };

export type PlanIdentityAllocatorOptionsV02 = Readonly<{
  now?: () => number;
  randomBytes?: (size: 8) => Uint8Array;
  commitCandidate: (identity: PlanIdentityV02) => Promise<PlanIdentityCommitResult>;
}>;

function timestampAtSecond(milliseconds: number): string {
  const value = new Date(milliseconds).toISOString();
  return IsoTimestampV02.parse(`${value.slice(0, 19)}Z`);
}

export async function allocateAndCommitPlanIdentityV02(
  options: PlanIdentityAllocatorOptionsV02,
): Promise<PlanIdentityAllocationResultV02> {
  const now = options.now ?? Date.now;
  const randomBytes = options.randomBytes ?? ((size: 8) => secureRandomBytes(size));
  let milliseconds: number;
  let createdAt: string;
  try {
    milliseconds = now();
    if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) throw new RangeError("invalid plan clock");
    createdAt = timestampAtSecond(milliseconds);
  } catch {
    return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "Plan identity entropy or clock generation failed." };
  }

  const timestamp = milliseconds.toString(36);
  for (let attempt = 0; attempt < PLAN_ID_ATTEMPTS; attempt += 1) {
    let entropyHex: string;
    try {
      const entropy = randomBytes(8);
      if (entropy.byteLength !== 8) throw new RangeError("invalid plan entropy length");
      entropyHex = Buffer.from(entropy).toString("hex");
    } catch {
      return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "Plan identity entropy or clock generation failed." };
    }
    const planToken = `${timestamp}_${entropyHex}`;
    const identity = Object.freeze({
      plan_token: planToken,
      run_id: MachineIdV02.parse(`run_${planToken}`),
      created_at: createdAt,
    });
    let committed: PlanIdentityCommitResult;
    try {
      committed = await options.commitCandidate(identity);
    } catch {
      return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "Required filesystem helper is unavailable." };
    }
    if (committed.ok) {
      return committed.run_id === identity.run_id
        ? { ok: true, identity }
        : { ok: false, reason: "INVALID_OUTPUT_CAPTURE", message: "The planned-run output authority is invalid." };
    }
    if (committed.reason === "DESTINATION_EXISTS") continue;
    return { ok: false, reason: committed.reason, message: committed.message };
  }
  return {
    ok: false,
    reason: "PLAN_ID_COLLISION_LIMIT",
    message: "Plan identity allocation exhausted its collision limit.",
  };
}

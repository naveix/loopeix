import { randomBytes as nodeRandomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

export interface RawRunDirectoryAllocation {
  run_id: string;
  run_dir: string;
}

export interface RawRunDirectoryAllocatorOptions {
  now?: () => number;
  randomBytes?: (size: number) => Uint8Array;
  maxAttempts?: number;
}

class RawRunDirectoryAllocationError extends Error {
  constructor(maxAttempts: number) {
    super(`cannot reserve raw run directory after ${maxAttempts} attempts`);
    this.name = "RawRunDirectoryAllocationError";
  }
}

function toHex(bytes: Uint8Array): string {
  if (bytes.length !== 8) {
    throw new Error(`randomBytes must return exactly 8 bytes (got ${bytes.length})`);
  }
  return Buffer.from(bytes).toString("hex");
}

function assertPositiveSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError(`${label} must be a positive safe integer`);
  }
}

function assertNonNegativeSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${label} must return a non-negative safe integer`);
  }
}

export function reserveRawRunDirectory(
  workspace: string,
  options: RawRunDirectoryAllocatorOptions = {},
): RawRunDirectoryAllocation {
  const now = options.now ?? Date.now;
  const randomBytes = options.randomBytes ?? ((size: number) => nodeRandomBytes(size));
  const maxAttempts = options.maxAttempts ?? 16;

  assertPositiveSafeInteger(maxAttempts, "maxAttempts");
  const timestampValue = now();
  assertNonNegativeSafeInteger(timestampValue, "now()");

  const runsParent = join(workspace, ".loopeix", "runs");
  const timestamp = timestampValue.toString(36);

  mkdirSync(runsParent, { recursive: true });

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const run_id = `run_${timestamp}_${toHex(randomBytes(8))}`;
    const run_dir = join(runsParent, run_id);

    try {
      mkdirSync(run_dir);
      return { run_id, run_dir };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") continue;
      throw error;
    }
  }

  throw new RawRunDirectoryAllocationError(maxAttempts);
}

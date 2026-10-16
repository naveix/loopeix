import { z } from "zod";

export const MAX_HUMAN_ID_BYTES_V02 = 128;
export const MAX_MACHINE_ID_BYTES_V02 = 160;
export const MAX_RELATIVE_RUN_PATH_BYTES_V02 = 1_024;
export const MAX_RELATIVE_RUN_PATH_SEGMENTS_V02 = 32;
export const MAX_FREE_CONTROL_STRING_BYTES_V02 = 16_384;

const HUMAN_ID_PATTERN_V02 = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const MACHINE_ID_PATTERN_V02 = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/;
const EXACT_UTC_SECOND_PATTERN_V02 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const WINDOWS_DRIVE_SEGMENT_PATTERN = /^[A-Za-z]:/;

function isUnicodeScalarString(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const nextCodeUnit = value.charCodeAt(index + 1);
      if (!(nextCodeUnit >= 0xdc00 && nextCodeUnit <= 0xdfff)) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function utf8ByteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${label} must be a positive integer.`);
  }
}

export const UnicodeScalarStringV02 = z
  .string()
  .refine(isUnicodeScalarString, { message: "must not contain an unpaired UTF-16 surrogate" });

export function boundedStringV02(maxBytes: number) {
  assertPositiveInteger(maxBytes, "maxBytes");
  return UnicodeScalarStringV02.refine((value) => utf8ByteLength(value) <= maxBytes, {
    message: `must be at most ${maxBytes} UTF-8 bytes`,
  });
}

export function boundedNonBlankStringV02(maxBytes: number) {
  return boundedStringV02(maxBytes).refine((value) => value.trim().length > 0, {
    message: "must contain at least one non-whitespace character",
  });
}

export const NonBlankStringV02 = boundedNonBlankStringV02(MAX_FREE_CONTROL_STRING_BYTES_V02);

export const FreeControlStringV02 = boundedStringV02(MAX_FREE_CONTROL_STRING_BYTES_V02);

export const HumanIdV02 = z
  .string()
  .min(1, "must be at least 1 ASCII byte")
  .max(MAX_HUMAN_ID_BYTES_V02, `must be at most ${MAX_HUMAN_ID_BYTES_V02} ASCII bytes`)
  .regex(HUMAN_ID_PATTERN_V02, "must be canonical lowercase kebab-case beginning with a letter");

export const MachineIdV02 = z
  .string()
  .min(3, "must be at least 3 ASCII bytes")
  .max(MAX_MACHINE_ID_BYTES_V02, `must be at most ${MAX_MACHINE_ID_BYTES_V02} ASCII bytes`)
  .regex(MACHINE_ID_PATTERN_V02, "must be canonical lowercase underscore form beginning with a letter");

export const IsoTimestampV02 = z
  .string()
  .length(20, "must be exactly 20 ASCII bytes")
  .regex(EXACT_UTC_SECOND_PATTERN_V02, "must use the exact UTC second form YYYY-MM-DDTHH:mm:ssZ")
  .pipe(z.iso.datetime({ offset: false, precision: 0 }));

export const RelativeRunPathV02 = boundedStringV02(MAX_RELATIVE_RUN_PATH_BYTES_V02).superRefine(
  (value, context) => {
    const segments = value.split("/");
    const invalid =
      value.length === 0 ||
      value.startsWith("/") ||
      value.includes("\\") ||
      value.includes("\0") ||
      segments.length > MAX_RELATIVE_RUN_PATH_SEGMENTS_V02 ||
      segments.some(
        (segment) =>
          segment.length === 0 ||
          segment === "." ||
          segment === ".." ||
          WINDOWS_DRIVE_SEGMENT_PATTERN.test(segment),
      );

    if (invalid) {
      context.addIssue({
        code: "custom",
        message:
          "must be a normalized run-relative path with 1..32 non-empty segments and no absolute, drive, dot, backslash, or NUL segment",
      });
    }
  },
);

export type BoundedArrayOptionsV02 = Readonly<{
  min: number;
  max: number;
}>;

export function boundedArrayV02<T extends z.ZodType>(
  element: T,
  options: BoundedArrayOptionsV02,
): z.ZodArray<T> {
  const { min, max } = options;
  if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || min < 0 || max < min) {
    throw new TypeError("min and max must define a valid integer range.");
  }
  return z.array(element).min(min).max(max);
}

export type HumanIdV02Value = z.infer<typeof HumanIdV02>;
export type MachineIdV02Value = z.infer<typeof MachineIdV02>;
export type IsoTimestampV02Value = z.infer<typeof IsoTimestampV02>;
export type RelativeRunPathV02Value = z.infer<typeof RelativeRunPathV02>;

export type CompilerWriterMemberRequest = Readonly<{
  name: string;
  bytes_base64: string;
}>;

export type CompilerWriterHelperRequest = Readonly<{
  version: "0.1";
  compile_store_identity: Readonly<{ device: string; inode: string }>;
  pack_basename: string;
  pack_members: readonly CompilerWriterMemberRequest[];
  standalone: Readonly<{
    parent_path: string;
    parent_identity: Readonly<{ device: string; inode: string }>;
    basename: string;
    bytes_base64: string;
  }> | null;
}>;

export type CompilerWriterFailureReason =
  | "DESTINATION_EXISTS"
  | "INVALID_OUTPUT_CAPTURE"
  | "IO_HELPER_UNAVAILABLE"
  | "IO_IDENTITY_MISMATCH"
  | "IO_DURABILITY_UNCONFIRMED";

export type CompilerWriterHelperResponse =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly reason: "DESTINATION_EXISTS";
      readonly message: string;
      readonly collision_destination: "compile-pack" | "standalone-loop";
    }
  | {
      readonly ok: false;
      readonly reason: Exclude<CompilerWriterFailureReason, "DESTINATION_EXISTS">;
      readonly message: string;
    };

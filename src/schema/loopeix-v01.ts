import { z } from "zod";
import {
  checkLoopeixInvariants,
  LoopeixShape,
  type Issue,
} from "./loopeix.js";

/** Frozen literal V01 family schema. The unsuffixed LoopeixShape stays broad. */
export const LoopeixV01Shape = LoopeixShape.extend({
  schema_version: z.literal("0.1"),
});

export type LoopeixV01 = z.infer<typeof LoopeixV01Shape>;

export function checkLoopeixV01Invariants(spec: LoopeixV01): Issue[] {
  return checkLoopeixInvariants(spec);
}

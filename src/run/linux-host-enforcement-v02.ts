import {
  runBoundedS37LinuxProbeV02,
  type S37LinuxProbeExecutionResultV02,
  type S37LinuxProbeRuntimeV02,
} from "./bounded-linux-probe-v02.js";
import { type S37LinuxProbeAdmissionV02 } from "./pre-spawn-capability-broker-v02.js";

export async function runS37LinuxHostProbeV02(
  admission: S37LinuxProbeAdmissionV02,
  runtime: S37LinuxProbeRuntimeV02,
): Promise<S37LinuxProbeExecutionResultV02> {
  return runBoundedS37LinuxProbeV02(admission, runtime);
}

import type { RuntimeEventV03Value } from "../schema/runtime-v03.js";
import type { ValidatedRuntimeLedgerV03 } from "./runtime-ledger-v03.js";

export type RuntimeRunStateV03 =
  | "initialized"
  | "running"
  | "paused"
  | "quarantine-required"
  | "quarantined"
  | "held"
  | "aborting"
  | "sealed";

export type RuntimeStateV03 = Readonly<{
  state: RuntimeRunStateV03;
  started: boolean;
  abort_requested: boolean;
  in_flight_action_ids: readonly string[];
}>;

export type RuntimeStateReductionResultV03 =
  | Readonly<{ ok: true; state: RuntimeStateV03 }>
  | Readonly<{ ok: false; path: string; message: string }>;

const fail = (index: number, message: string): RuntimeStateReductionResultV03 => ({
  ok: false,
  path: `event[${index}]`,
  message,
});

export function reduceRuntimeEventPrefixV03(
  events: readonly RuntimeEventV03Value[],
): RuntimeStateReductionResultV03 {
  let state: RuntimeRunStateV03 = "initialized";
  let started = false;
  let abortRequested = false;
  let terminalFreezeSeen = false;
  const inFlight = new Set<string>();
  const byReference = new Map<string, RuntimeEventV03Value>();

  for (const [index, event] of events.entries()) {
    if (index === 0) {
      if (event.event_type !== "run.initialized") return fail(index, "A V03 ledger must begin with run.initialized.");
      byReference.set(`${event.sequence}\0${event.event_hash}`, event);
      continue;
    }
    if (state === "sealed") return fail(index, "No event may follow a terminal seal.");
    if (state === "quarantine-required" && event.event_type !== "run.quarantined") {
      return fail(index, "integrity.observation-rejected must be followed immediately by its exact quarantine event.");
    }

    switch (event.event_type) {
      case "run.initialized":
        return fail(index, "run.initialized may appear only once at sequence 1.");
      case "run.started":
        if (state !== "initialized" || started) return fail(index, "run.started requires one unstarted initialized run.");
        state = "running";
        started = true;
        break;
      case "task.action-admitted":
        if (state !== "running") return fail(index, "task.action-admitted requires a running run.");
        if (inFlight.has(event.payload.action_id)) return fail(index, "An action may enter in-flight state only once.");
        inFlight.add(event.payload.action_id);
        break;
      case "task.action-settled":
        if (!inFlight.delete(event.payload.action_id)) return fail(index, "task.action-settled requires an in-flight admitted action.");
        break;
      case "run.paused":
        if (state !== "running" || inFlight.size !== 0) return fail(index, "run.paused requires a running quiescent boundary.");
        state = "paused";
        break;
      case "run.quarantined":
        if (!started) return fail(index, "run.quarantined requires a started non-terminal run.");
        if (state !== "quarantine-required") return fail(index, "run.quarantined requires the immediately preceding rejected observation.");
        state = "quarantined";
        break;
      case "integrity.observation-rejected":
        if (!started || (state !== "running" && state !== "paused")) {
          return fail(index, "integrity.observation-rejected requires a started active run.");
        }
        state = "quarantine-required";
        break;
      case "authority.grant-revoked":
        if (state !== "aborting" && state !== "quarantined") state = "held";
        break;
      case "control.abort-requested":
        abortRequested = true;
        if (state !== "quarantined") state = "aborting";
        break;
      case "run.terminal-freeze-entered":
        terminalFreezeSeen = true;
        break;
      case "process.termination-attempted": {
        const trigger = byReference.get(`${event.payload.trigger_event_ref.ledger_sequence}\0${event.payload.trigger_event_ref.event_hash}`);
        const expectedType = event.payload.trigger === "abort" ? "control.abort-requested" : "run.quarantined";
        if (trigger?.event_type !== expectedType) return fail(index, "Termination attempt must resolve to its exact abort or quarantine trigger.");
        break;
      }
      case "run.terminal-sealed":
        if (!terminalFreezeSeen) return fail(index, "Terminal seal requires a preceding terminal freeze.");
        if (inFlight.size !== 0) return fail(index, "Terminal seal requires no unresolved in-flight action.");
        state = "sealed";
        break;
      default:
        break;
    }
    byReference.set(`${event.sequence}\0${event.event_hash}`, event);
  }

  return {
    ok: true,
    state: Object.freeze({
      state,
      started,
      abort_requested: abortRequested,
      in_flight_action_ids: Object.freeze([...inFlight].sort()),
    }),
  };
}

export function reduceRuntimeStateV03(validatedPrefix: ValidatedRuntimeLedgerV03): RuntimeStateV03 {
  return validatedPrefix.state;
}

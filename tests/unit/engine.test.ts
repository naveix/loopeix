import { describe, expect, it } from "vitest";
import { parseJsonlEvents } from "../../src/index.js";

describe("parseJsonlEvents", () => {
  it("parses valid JSONL lines and skips blank + non-JSON lines", () => {
    const events = parseJsonlEvents('{"a":1}\n\n  \nnot json\n{"b":2}\n');
    expect(events).toEqual([{ a: 1 }, { b: 2 }]);
  });
  it("returns [] for empty input", () => {
    expect(parseJsonlEvents("")).toEqual([]);
    expect(parseJsonlEvents("\n \n")).toEqual([]);
  });
});

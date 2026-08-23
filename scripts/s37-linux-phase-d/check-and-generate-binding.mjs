#!/usr/bin/env node

import { readFileSync } from "node:fs";
import process from "node:process";

import { collectLocalHostCapture, evaluateS37PhaseDHost } from "./host-qualification-contract.mjs";

function usage(detail) {
  if (detail !== undefined) process.stderr.write(`${detail}\n`);
  process.stderr.write("usage: check-and-generate-binding.mjs --qualification <absolute-json-path> --manifest <absolute-json-path> --readiness-evidence <absolute-json-path> --readiness-envelope <absolute-json-path> --conformance-evidence <absolute-json-path> --receipt <absolute-json-path> [--controller-uid <positive-integer>]\n");
  process.exit(64);
}

const args = process.argv.slice(2);
let qualificationPath;
let manifestPath;
let readinessEvidencePath;
let readinessEnvelopePath;
let conformanceEvidencePath;
let receiptPath;
let controllerUid = typeof process.getuid === "function" ? process.getuid() : Number.NaN;
for (let index = 0; index < args.length; index += 2) {
  const flag = args[index];
  const value = args[index + 1];
  if (value === undefined) usage(`missing value for ${flag}`);
  if (flag === "--qualification") qualificationPath = value;
  else if (flag === "--manifest") manifestPath = value;
  else if (flag === "--readiness-evidence") readinessEvidencePath = value;
  else if (flag === "--readiness-envelope") readinessEnvelopePath = value;
  else if (flag === "--conformance-evidence") conformanceEvidencePath = value;
  else if (flag === "--receipt") receiptPath = value;
  else if (flag === "--controller-uid") controllerUid = Number(value);
  else usage(`unknown argument: ${flag}`);
}
if (qualificationPath === undefined || !qualificationPath.startsWith("/")) usage("qualification path must be absolute");
if (manifestPath !== undefined && !manifestPath.startsWith("/")) usage("manifest path must be absolute");
if (readinessEvidencePath !== undefined && !readinessEvidencePath.startsWith("/")) usage("readiness evidence path must be absolute");
if (readinessEnvelopePath !== undefined && !readinessEnvelopePath.startsWith("/")) usage("readiness envelope path must be absolute");
if (conformanceEvidencePath !== undefined && !conformanceEvidencePath.startsWith("/")) usage("conformance evidence path must be absolute");
if (receiptPath !== undefined && !receiptPath.startsWith("/")) usage("receipt path must be absolute");
if (!Number.isSafeInteger(controllerUid) || controllerUid <= 0) usage("controller UID must be a positive non-root integer");

try {
  const qualification = JSON.parse(readFileSync(qualificationPath, "utf8"));
  const phaseB = manifestPath !== undefined
    && readinessEvidencePath !== undefined
    && readinessEnvelopePath !== undefined
    && conformanceEvidencePath !== undefined
    && receiptPath !== undefined
    ? {
      manifest: JSON.parse(readFileSync(manifestPath, "utf8")),
      readiness_evidence: JSON.parse(readFileSync(readinessEvidencePath, "utf8")),
      readiness_envelope: JSON.parse(readFileSync(readinessEnvelopePath, "utf8")),
      conformance_evidence: JSON.parse(readFileSync(conformanceEvidencePath, "utf8")),
      receipt: JSON.parse(readFileSync(receiptPath, "utf8")),
    }
    : null;
  if (phaseB === null) {
    process.stderr.write("HOLD: phase-b-sealed-inputs-required\n");
    process.exit(1);
  }
  const result = evaluateS37PhaseDHost(collectLocalHostCapture(controllerUid), qualification, phaseB, new Date());
  if (!result.ok) {
    process.stderr.write(`${result.violations.map((value) => `HOLD: ${value}`).join("\n")}\n`);
    process.exit(1);
  }
  process.stdout.write(`${JSON.stringify(result.binding, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`HOLD: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}

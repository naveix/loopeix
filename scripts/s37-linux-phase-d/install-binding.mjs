#!/usr/bin/env node

import {
  constants,
  chmodSync,
  chownSync,
  closeSync,
  fchmodSync,
  fchownSync,
  fsyncSync,
  linkSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import {
  S37_PHASE_D_BINDING_PATH,
  buildS37PhaseDBindingInstallPlan,
  collectLocalHostCapture,
  evaluateS37PhaseDHost,
} from "./host-qualification-contract.mjs";

const APPLY_GATE = "--apply-exact-s37-local-product-binding";
export const INSTALL_BINDING_USAGE = `usage: install-binding.mjs --qualification <absolute-json-path> --manifest <absolute-json-path> --readiness-evidence <absolute-json-path> --readiness-envelope <absolute-json-path> --conformance-evidence <absolute-json-path> --receipt <absolute-json-path> --controller-uid <positive-integer> ${APPLY_GATE}`;

function installBindingError(detail, exitCode = 1) {
  const error = new Error(detail);
  Object.assign(error, { detail, exitCode });
  return error;
}

function requireAbsolutePath(value, label) {
  if (typeof value !== "string" || !value.startsWith("/")) {
    throw installBindingError(`${label} path must be absolute`, 64);
  }
  return value;
}

function defaultControllerUid() {
  return typeof process.getuid === "function" ? process.getuid() : Number.NaN;
}

export function parseInstallBindingArgs(args, controllerUid = defaultControllerUid()) {
  const parsed = {
    qualificationPath: undefined,
    manifestPath: undefined,
    readinessEvidencePath: undefined,
    readinessEnvelopePath: undefined,
    conformanceEvidencePath: undefined,
    receiptPath: undefined,
    controllerUid,
    applyGateSeen: false,
  };
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    if (flag === APPLY_GATE) {
      parsed.applyGateSeen = true;
      continue;
    }
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) throw installBindingError(INSTALL_BINDING_USAGE, 64);
    if (flag === "--qualification") parsed.qualificationPath = requireAbsolutePath(value, "qualification");
    else if (flag === "--manifest") parsed.manifestPath = requireAbsolutePath(value, "manifest");
    else if (flag === "--readiness-evidence") parsed.readinessEvidencePath = requireAbsolutePath(value, "readiness evidence");
    else if (flag === "--readiness-envelope") parsed.readinessEnvelopePath = requireAbsolutePath(value, "readiness envelope");
    else if (flag === "--conformance-evidence") parsed.conformanceEvidencePath = requireAbsolutePath(value, "conformance evidence");
    else if (flag === "--receipt") parsed.receiptPath = requireAbsolutePath(value, "receipt");
    else if (flag === "--controller-uid") parsed.controllerUid = Number(value);
    else throw installBindingError(INSTALL_BINDING_USAGE, 64);
    index += 1;
  }
  if (!parsed.applyGateSeen) throw installBindingError(INSTALL_BINDING_USAGE, 64);
  if (parsed.qualificationPath === undefined) throw installBindingError("qualification path must be absolute", 64);
  if (parsed.manifestPath === undefined || parsed.readinessEvidencePath === undefined
    || parsed.readinessEnvelopePath === undefined || parsed.conformanceEvidencePath === undefined
    || parsed.receiptPath === undefined) {
    throw installBindingError("phase-b-sealed-inputs-required");
  }
  if (!Number.isSafeInteger(parsed.controllerUid) || parsed.controllerUid <= 0) {
    throw installBindingError("controller UID must be a positive non-root integer", 64);
  }
  return Object.freeze(parsed);
}

function createDefaultInstallIo() {
  return Object.freeze({
    constants,
    randomBytesHex: () => randomBytes(12).toString("hex"),
    openSync,
    writeFileSync,
    fsyncSync,
    fchownSync,
    fchmodSync,
    chownSync,
    chmodSync,
    closeSync,
    linkSync,
    unlinkSync,
  });
}

function successfulInstallOutcome(plan, warnings) {
  return Object.freeze({
    ok: true,
    destination: plan.destination,
    sha256: plan.sha256,
    warnings: Object.freeze(warnings),
  });
}

function durabilityUnknownOutcome(plan, warnings, detail) {
  return Object.freeze({
    ok: false,
    terminal: "OUTCOME_UNKNOWN",
    destination: plan.destination,
    sha256: plan.sha256,
    warnings: Object.freeze(warnings),
    detail,
  });
}

function applyDescriptorMetadata(descriptor, temporaryPath, plan, io) {
  if (typeof io.fchownSync === "function") io.fchownSync(descriptor, plan.uid, plan.gid);
  else io.chownSync(temporaryPath, plan.uid, plan.gid);
  if (typeof io.fchmodSync === "function") io.fchmodSync(descriptor, plan.mode);
  else io.chmodSync(temporaryPath, plan.mode);
}

export function publishBindingPlan(plan, io = createDefaultInstallIo()) {
  const destinationDirectory = dirname(plan.destination);
  const temporaryPath = join(destinationDirectory, `.local-product-binding.${io.randomBytesHex()}.tmp`);
  const warnings = [];
  let descriptor;
  let published = false;
  try {
    descriptor = io.openSync(
      temporaryPath,
      io.constants.O_CREAT | io.constants.O_EXCL | io.constants.O_WRONLY | io.constants.O_NOFOLLOW,
      0o600,
    );
    try {
      io.writeFileSync(descriptor, plan.bytes);
      io.fsyncSync(descriptor);
      applyDescriptorMetadata(descriptor, temporaryPath, plan, io);
      io.fsyncSync(descriptor);
    } finally {
      io.closeSync(descriptor);
    }
    io.linkSync(temporaryPath, plan.destination);
    published = true;
    try {
      io.unlinkSync(temporaryPath);
    } catch {
      warnings.push(`temporary-path-cleanup-required:${temporaryPath}`);
    }
    try {
      const directoryDescriptor = io.openSync(
        destinationDirectory,
        io.constants.O_RDONLY | io.constants.O_DIRECTORY,
      );
      try {
        io.fsyncSync(directoryDescriptor);
      } finally {
        io.closeSync(directoryDescriptor);
      }
    } catch {
      return durabilityUnknownOutcome(
        plan,
        warnings,
        `directory-fsync-after-publication-failed:${destinationDirectory}`,
      );
    }
    return successfulInstallOutcome(plan, warnings);
  } catch (error) {
    if (!published) {
      try {
        io.unlinkSync(temporaryPath);
      } catch {
        // Exact temp cleanup only; original pre-publication failure remains authoritative.
      }
    }
    throw error;
  }
}

function readPhaseBInputs(paths) {
  return Object.freeze({
    manifest: JSON.parse(readFileSync(paths.manifestPath, "utf8")),
    readiness_evidence: JSON.parse(readFileSync(paths.readinessEvidencePath, "utf8")),
    readiness_envelope: JSON.parse(readFileSync(paths.readinessEnvelopePath, "utf8")),
    conformance_evidence: JSON.parse(readFileSync(paths.conformanceEvidencePath, "utf8")),
    receipt: JSON.parse(readFileSync(paths.receiptPath, "utf8")),
  });
}

export function executeInstallBinding(args = process.argv.slice(2), options = {}) {
  const parsed = parseInstallBindingArgs(args, options.controllerUid ?? defaultControllerUid());
  const runtimeProcess = options.processLike ?? process;
  // Static gate anchor: process.platform !== "linux"
  const platformIsLinux = options.processLike === undefined
    ? process.platform === "linux"
    : runtimeProcess.platform === "linux";
  if (!platformIsLinux) throw installBindingError("installer requires the qualified Linux host");
  // Static gate anchor: process.getuid() !== 0
  const isRoot = options.processLike === undefined
    ? typeof process.getuid === "function" && process.getuid() === 0
    : typeof runtimeProcess.getuid === "function" && runtimeProcess.getuid() === 0;
  if (!isRoot) {
    throw installBindingError("installer requires UID 0");
  }

  const qualification = JSON.parse(readFileSync(parsed.qualificationPath, "utf8"));
  const phaseB = readPhaseBInputs(parsed);
  const result = evaluateS37PhaseDHost(
    (options.collectLocalHostCapture ?? collectLocalHostCapture)(parsed.controllerUid),
    qualification,
    phaseB,
    new Date(),
  );
  if (!result.ok) throw installBindingError(result.violations.join(","));
  const plan = buildS37PhaseDBindingInstallPlan(result.binding);
  if (plan.destination !== S37_PHASE_D_BINDING_PATH || plan.overwrite !== false) {
    throw installBindingError("installer plan drifted");
  }
  return publishBindingPlan(plan, options.io ?? createDefaultInstallIo());
}

export function writeInstallBindingOutcome(outcome, processLike = process) {
  if (!outcome.ok) {
    processLike.exitCode = 1;
    processLike.stderr.write(`OUTCOME_UNKNOWN: published ${outcome.destination} ${outcome.sha256} ${outcome.detail}\n`);
    if (outcome.warnings.length > 0) {
      processLike.stderr.write(`${outcome.warnings.map((warning) => `WARN: ${warning}`).join("\n")}\n`);
    }
    return 1;
  }
  processLike.stdout.write(`installed ${outcome.destination} ${outcome.sha256}\n`);
  if (outcome.warnings.length > 0) {
    processLike.stderr.write(`${outcome.warnings.map((warning) => `WARN: ${warning}`).join("\n")}\n`);
  }
  return 0;
}

export function failInstallBinding(error, processLike = process) {
  const detail = error?.detail ?? (error instanceof Error ? error.message : String(error));
  const exitCode = error?.exitCode ?? 1;
  processLike.stderr.write(`HOLD: ${detail}\n`);
  processLike.exit(exitCode);
}

const isDirectExecution = process.argv[1] !== undefined
  && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isDirectExecution) {
  try {
    const exitCode = writeInstallBindingOutcome(executeInstallBinding());
    if (exitCode !== 0) process.exit(exitCode);
  } catch (error) {
    failInstallBinding(error);
  }
}

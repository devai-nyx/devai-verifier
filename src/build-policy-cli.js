#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { VerificationError, canonicalize, readJson } from './canonical.js';
import {
  buildExpectedTaskPolicy,
  readEnvironmentMap,
  readStringMap,
} from './policy-builder.js';

const requiredNames = new Set([
  'repo',
  'descriptor',
  'profile',
  'commit',
  'tree',
  'toolchain',
  'environment',
  'output',
]);
const optionalNames = new Set(['base']);

function parseArguments(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith('--') || value === undefined) {
      throw new VerificationError('USAGE', 'arguments must be --name value pairs');
    }
    const name = token.slice(2);
    if ((!requiredNames.has(name) && !optionalNames.has(name)) || values[name] !== undefined) {
      throw new VerificationError('USAGE', `unknown or duplicate argument --${name}`);
    }
    values[name] = value;
  }
  const missing = [...requiredNames].filter((name) => values[name] === undefined);
  if (missing.length > 0) {
    throw new VerificationError('USAGE', `missing arguments: ${missing.map((name) => `--${name}`).join(', ')}`);
  }
  return values;
}

function emitError(code, message, exitCode) {
  process.stderr.write(`${JSON.stringify({ ok: false, code, message })}\n`);
  process.exitCode = exitCode;
}

try {
  const values = parseArguments(process.argv.slice(2));
  const built = buildExpectedTaskPolicy({
    repo: values.repo,
    descriptor: readJson(values.descriptor, 'task descriptor'),
    profileId: values.profile,
    candidateCommit: values.commit,
    expectedTree: values.tree,
    baseCommit: values.base,
    toolchain: readStringMap(values.toolchain, 'toolchain'),
    environment: readEnvironmentMap(values.environment, 'environment'),
  });
  writeFileSync(values.output, `${canonicalize(built.taskPolicy)}\n`, { flag: 'wx' });
  process.stdout.write(
    `${JSON.stringify({
      ok: true,
      taskPolicyDigest: built.taskPolicyDigest,
      descriptorDigest: built.descriptorDigest,
      profileId: built.profileId,
      candidateTree: built.candidateTree,
      changedPaths: built.changedPaths,
      output: values.output,
    })}\n`,
  );
} catch (error) {
  if (error instanceof VerificationError) {
    emitError(error.code, error.message, error.code === 'USAGE' ? 64 : 2);
  } else {
    emitError('INTERNAL_ERROR', error instanceof Error ? error.message : String(error), 70);
  }
}

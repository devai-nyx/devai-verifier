#!/usr/bin/env node
import { VerificationError } from './canonical.js';
import { loadAndVerify } from './verify.js';

const names = new Set([
  'envelope',
  'results-dir',
  'task-policy',
  'trust',
  'repository',
  'commit',
  'tree',
  'policy-digest',
]);

function emitError(code, message, exitCode) {
  process.stderr.write(`${JSON.stringify({ ok: false, code, message })}\n`);
  process.exitCode = exitCode;
}

function parseArguments(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith('--') || value === undefined) {
      throw new VerificationError('USAGE', 'arguments must be --name value pairs');
    }
    const name = token.slice(2);
    if (!names.has(name) || values[name] !== undefined) {
      throw new VerificationError('USAGE', `unknown or duplicate argument --${name}`);
    }
    values[name] = value;
  }
  const missing = [...names].filter((name) => values[name] === undefined);
  if (missing.length > 0) {
    throw new VerificationError('USAGE', `missing arguments: ${missing.map((name) => `--${name}`).join(', ')}`);
  }
  return values;
}

try {
  const values = parseArguments(process.argv.slice(2));
  const result = loadAndVerify({
    envelopePath: values.envelope,
    resultsDir: values['results-dir'],
    taskPolicyPath: values['task-policy'],
    trustStorePath: values.trust,
    expectedRepository: values.repository,
    expectedCommit: values.commit,
    expectedTree: values.tree,
    expectedPolicyDigest: values['policy-digest'],
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  if (error instanceof VerificationError) {
    emitError(error.code, error.message, error.code === 'USAGE' ? 64 : 2);
  } else {
    emitError('INTERNAL_ERROR', error instanceof Error ? error.message : String(error), 70);
  }
}

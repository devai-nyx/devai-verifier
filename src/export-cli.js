#!/usr/bin/env node
import { VerificationError } from './canonical.js';
import { exportCandidateEvidence } from './export.js';

const required = new Set([
  'repo',
  'receipt',
  'results-dir',
  'profile',
  'commit',
  'tree',
  'toolchain',
  'environment',
  'private-key',
  'public-key',
  'signer-id',
  'output-dir',
]);
const optional = new Set(['base']);

function parse(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith('--') || value === undefined) {
      throw new VerificationError('USAGE', 'arguments must be --name value pairs');
    }
    const name = token.slice(2);
    if ((!required.has(name) && !optional.has(name)) || values[name] !== undefined) {
      throw new VerificationError('USAGE', `unknown or duplicate argument --${name}`);
    }
    values[name] = value;
  }
  const missing = [...required].filter((name) => values[name] === undefined);
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
  const values = parse(process.argv.slice(2));
  const result = exportCandidateEvidence({
    repo: values.repo,
    receiptPath: values.receipt,
    resultsDir: values['results-dir'],
    profile: values.profile,
    commit: values.commit,
    tree: values.tree,
    baseCommit: values.base,
    toolchainPath: values.toolchain,
    environmentPath: values.environment,
    privateKeyPath: values['private-key'],
    publicKeyPath: values['public-key'],
    signerId: values['signer-id'],
    outputDir: values['output-dir'],
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  if (error instanceof VerificationError) {
    emitError(error.code, error.message, error.code === 'USAGE' ? 64 : 2);
  } else {
    emitError('INTERNAL_ERROR', error instanceof Error ? error.message : String(error), 70);
  }
}

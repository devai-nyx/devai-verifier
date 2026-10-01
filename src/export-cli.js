#!/usr/bin/env node
import { VerificationError } from './canonical.js';
import { exportCandidateEvidence, preflightCandidateEvidence } from './export.js';
import { assertProfileId } from './policy-builder.js';

const required = new Set([
  'repo',
  'receipt',
  'results-dir',
  'profile',
  'commit',
  'tree',
  'toolchain',
  'environment',
  'public-key',
  'signer-id',
  'output-dir',
]);
// A receipt is exported through exactly one path: --profile selects the descriptor
// profile path, and the complete intent set selects the release-intent path
// (ADR-REL-0031). Mixing them, or supplying part of the intent set, is a usage error.
const intentPath = new Set([
  'release-intent',
  'release-profile',
  'release-stage',
  'preflight-receipt',
]);
// --private-key is required only for a signing export. A preflight verifies the same
// candidate without it, so it stays optional and is never forwarded in preflight mode.
const signing = new Set(['private-key']);
const optional = new Set(['base', 'preflight']);

function parse(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (!token?.startsWith('--') || value === undefined) {
      throw new VerificationError('USAGE', 'arguments must be --name value pairs');
    }
    const name = token.slice(2);
    const known =
      required.has(name) || intentPath.has(name) || signing.has(name) || optional.has(name);
    if (!known || values[name] !== undefined) {
      throw new VerificationError('USAGE', `unknown or duplicate argument --${name}`);
    }
    values[name] = value;
  }
  if (values.preflight !== undefined && values.preflight !== 'true') {
    throw new VerificationError('USAGE', '--preflight must be true when supplied');
  }
  const suppliedIntent = [...intentPath].filter((name) => values[name] !== undefined);
  if (values.profile !== undefined && suppliedIntent.length > 0) {
    throw new VerificationError(
      'USAGE',
      '--profile cannot be combined with the release-intent arguments',
    );
  }
  // The intent set takes the place of --profile; the profile path keeps its argument set.
  const pathArguments = [...required].flatMap((name) =>
    name === 'profile' && suppliedIntent.length > 0 ? [...intentPath] : [name],
  );
  const expected = values.preflight === 'true' ? pathArguments : [...pathArguments, ...signing];
  const missing = [...expected].filter((name) => values[name] === undefined);
  if (missing.length > 0) {
    throw new VerificationError(
      'USAGE',
      `missing arguments: ${missing.map((name) => `--${name}`).join(', ')}`,
    );
  }
  return values;
}

function emitError(code, message, exitCode) {
  process.stderr.write(`${JSON.stringify({ ok: false, code, message })}\n`);
  process.exitCode = exitCode;
}

try {
  const values = parse(process.argv.slice(2));
  const preflight = values.preflight === 'true';
  const intent = values['release-intent'] !== undefined;
  // A profile id is checked against its grammar before any input is read.
  if (!intent) assertProfileId(values.profile);
  const options = {
    repo: values.repo,
    receiptPath: values.receipt,
    resultsDir: values['results-dir'],
    profile: values.profile,
    commit: values.commit,
    tree: values.tree,
    baseCommit: values.base,
    toolchainPath: values.toolchain,
    environmentPath: values.environment,
    privateKeyPath: preflight ? undefined : values['private-key'],
    publicKeyPath: values['public-key'],
    signerId: values['signer-id'],
    outputDir: values['output-dir'],
    ...(intent && {
      releaseIntentPath: values['release-intent'],
      releaseProfilePath: values['release-profile'],
      releaseStage: values['release-stage'],
      preflightReceiptPath: values['preflight-receipt'],
    }),
  };
  const result = preflight
    ? {
        ok: true,
        preflight: true,
        taskPolicyDigest: preflightCandidateEvidence(options).built.taskPolicyDigest,
      }
    : exportCandidateEvidence(options);
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  if (error instanceof VerificationError) {
    emitError(error.code, error.message, error.code === 'USAGE' ? 64 : 2);
  } else {
    emitError('INTERNAL_ERROR', error instanceof Error ? error.message : String(error), 70);
  }
}

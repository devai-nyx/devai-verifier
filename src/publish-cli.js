#!/usr/bin/env node
import { VerificationError } from './canonical.js';
import { publishCandidateEvidence } from './publish.js';

const required = new Set(['repo', 'bundle', 'trust']);
const optional = new Set(['default-branch', 'remote', 'tag-prefix', 'workflow']);

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

try {
  const values = parse(process.argv.slice(2));
  const result = publishCandidateEvidence({
    repo: values.repo,
    bundleDir: values.bundle,
    trustStorePath: values.trust,
    remote: values.remote,
    tagPrefix: values['tag-prefix'],
    workflow: values.workflow,
    defaultBranch: values['default-branch'],
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  if (error instanceof VerificationError) {
    process.stderr.write(`${JSON.stringify({ ok: false, code: error.code, message: error.message })}\n`);
    process.exitCode = error.code === 'USAGE' ? 64 : 2;
  } else {
    process.stderr.write(`${JSON.stringify({ ok: false, code: 'INTERNAL_ERROR', message: String(error) })}\n`);
    process.exitCode = 70;
  }
}

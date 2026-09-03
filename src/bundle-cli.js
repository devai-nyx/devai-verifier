#!/usr/bin/env node
import { VerificationError } from './canonical.js';
import { verifyPreparedBundle } from './publish.js';

const required = new Set(['bundle', 'trust', 'repository', 'commit', 'tree', 'policy-digest']);
const optional = new Set(['binding', 'signer-id', 'trust-root-id', 'trust-store-digest', 'key-id']);

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
    throw new VerificationError(
      'USAGE',
      `missing arguments: ${missing.map((name) => `--${name}`).join(', ')}`,
    );
  }
  return values;
}

try {
  const values = parse(process.argv.slice(2));
  const result = verifyPreparedBundle({
    bundleDir: values.bundle,
    trustStorePath: values.trust,
    expectedRepository: values.repository,
    expectedCommit: values.commit,
    expectedTree: values.tree,
    expectedPolicyDigest: values['policy-digest'],
    expectedSignerId: values['signer-id'],
    expectedTrustRootId: values['trust-root-id'],
    expectedTrustStoreDigest: values['trust-store-digest'],
    expectedKeyId: values['key-id'],
    bindingMode: values.binding ?? 'exact-commit',
  });
  process.stdout.write(`${JSON.stringify({ ...result.verified, manifest: result.manifest })}\n`);
} catch (error) {
  if (error instanceof VerificationError) {
    process.stderr.write(
      `${JSON.stringify({ ok: false, code: error.code, message: error.message })}\n`,
    );
    process.exitCode = error.code === 'USAGE' ? 64 : 2;
  } else {
    process.stderr.write(
      `${JSON.stringify({ ok: false, code: 'INTERNAL_ERROR', message: String(error) })}\n`,
    );
    process.exitCode = 70;
  }
}

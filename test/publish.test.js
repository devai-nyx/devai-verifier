import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { canonicalBytes, canonicalize, sha256Hex } from '../src/canonical.js';
import { publishCandidateEvidence, verifyPreparedBundle } from '../src/publish.js';
import { PAYLOAD_TYPE } from '../src/verify.js';

const temporaryDirectories = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function git(repo, args) {
  return execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim();
}

function put(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, typeof value === 'string' ? value : `${canonicalize(value)}\n`);
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'devai-publish-test-'));
  temporaryDirectories.push(root);
  const remote = join(root, 'remote.git');
  const repo = join(root, 'candidate');
  mkdirSync(remote);
  mkdirSync(repo);
  git(remote, ['init', '--quiet', '--bare']);
  git(repo, ['init', '--quiet', '-b', 'main']);
  git(repo, ['config', 'user.name', 'Verifier Test']);
  git(repo, ['config', 'user.email', 'verifier@example.invalid']);
  put(join(repo, 'candidate.txt'), 'candidate\n');
  git(repo, ['add', '-A']);
  git(repo, ['commit', '--quiet', '-m', 'candidate']);
  git(repo, ['remote', 'add', 'origin', remote]);
  const commit = git(repo, ['rev-parse', 'HEAD']);
  const tree = git(repo, ['rev-parse', 'HEAD^{tree}']);
  const keys = generateKeyPairSync('ed25519');
  const taskKey = sha256Hex(Buffer.from('task'));
  const policy = {
    schemaVersion: '1.1.0',
    repositoryId: 'fixture/repository',
    requiredNodes: [
      { nodeId: 'test:rc', taskKey, dependencies: [], outputContract: { kind: 'none' } },
    ],
  };
  const policyDigest = sha256Hex(policy);
  const result = {
    schemaVersion: '1.0.0',
    nodeId: 'test:rc',
    taskKey,
    status: 'PASS',
    inputDigest: sha256Hex(Buffer.from('input')),
    dependencyResultDigests: {},
    outputDigests: {
      stdout: sha256Hex(Buffer.from('')),
      stderr: sha256Hex(Buffer.from('')),
    },
    startedAt: '2026-08-16T00:00:00.000Z',
    finishedAt: '2026-08-16T00:00:01.000Z',
  };
  const resultDigest = sha256Hex(result);
  const receipt = {
    schemaVersion: '1.1.0',
    repository: { id: 'fixture/repository', commit, tree },
    profile: 'rc',
    taskPolicyDigest: policyDigest,
    createdAt: '2026-08-16T00:00:02.000Z',
    tasks: [{ nodeId: 'test:rc', taskKey, resultDigest }],
  };
  const payload = canonicalBytes(receipt);
  const envelope = {
    schemaVersion: '1.0.0',
    payloadType: PAYLOAD_TYPE,
    payload: payload.toString('base64'),
    signatures: [
      {
        signerId: 'stynx-inspector-workstation-01',
        signature: sign(null, payload, keys.privateKey).toString('base64'),
      },
    ],
  };
  const trust = {
    schemaVersion: '1.0.0',
    trustedSigners: [
      {
        signerId: 'stynx-inspector-workstation-01',
        publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      },
    ],
    revokedSignerIds: [],
  };
  const bundle = join(root, 'bundle');
  put(join(bundle, 'envelope.json'), envelope);
  put(join(bundle, 'task-policy.json'), policy);
  put(join(bundle, 'results', `${resultDigest}.json`), result);
  put(join(bundle, 'manifest.json'), {
    schemaVersion: '1.1.0',
    repositoryId: 'fixture/repository',
    commit,
    tree,
    profile: 'rc',
    signerId: 'stynx-inspector-workstation-01',
    taskPolicyDigest: policyDigest,
    envelopeDigest: sha256Hex(envelope),
    resultDigests: [resultDigest],
    artifacts: [],
  });
  const trustStorePath = join(root, 'trust.json');
  put(trustStorePath, trust);
  return { root, remote, repo, bundle, trustStorePath, commit, tree, keys, receipt };
}

function options(state, dispatched) {
  return {
    repo: state.repo,
    bundleDir: state.bundle,
    trustStorePath: state.trustStorePath,
    resolveRemoteRepositoryId: () => 'fixture/repository',
    dispatchVerification: (request) => dispatched.push(request),
  };
}

function expectCode(code, action) {
  assert.throws(action, (error) => error?.code === code);
}

describe('protected evidence publication', () => {
  it('reverifies, publishes one immutable tag, dispatches, and is idempotent for identical bytes', () => {
    const state = fixture();
    const dispatched = [];
    assert.equal(
      verifyPreparedBundle({ bundleDir: state.bundle, trustStorePath: state.trustStorePath }).verified.ok,
      true,
    );
    const first = publishCandidateEvidence(options(state, dispatched));
    assert.equal(first.published, true);
    assert.equal(first.tag, `devai-local-evidence/${state.tree}`);
    assert.match(git(state.remote, ['show-ref', '--tags']), /refs\/tags\/devai-local-evidence\//u);

    const second = publishCandidateEvidence(options(state, dispatched));
    assert.equal(second.published, false);
    assert.equal(dispatched.length, 2);
    assert.equal(dispatched[0].candidateCommit, state.commit);
  });

  it('accepts a byte-identical merged-main tree only in exact-tree mode', () => {
    const state = fixture();
    const mergedCommit = 'c'.repeat(40);
    expectCode('COMMIT_MISMATCH', () =>
      verifyPreparedBundle({
        bundleDir: state.bundle,
        trustStorePath: state.trustStorePath,
        expectedRepository: 'fixture/repository',
        expectedCommit: mergedCommit,
        expectedTree: state.tree,
        expectedPolicyDigest: JSON.parse(readFileSync(join(state.bundle, 'manifest.json'), 'utf8'))
          .taskPolicyDigest,
      }),
    );
    const verified = verifyPreparedBundle({
      bundleDir: state.bundle,
      trustStorePath: state.trustStorePath,
      expectedRepository: 'fixture/repository',
      expectedCommit: mergedCommit,
      expectedTree: state.tree,
      expectedPolicyDigest: JSON.parse(readFileSync(join(state.bundle, 'manifest.json'), 'utf8'))
        .taskPolicyDigest,
      bindingMode: 'exact-tree',
    });
    assert.equal(verified.verified.binding, 'exact-tree');
    assert.equal(verified.verified.evidenceCommit, state.commit);
  });

  it('rejects extra files and an existing tag with different valid evidence bytes', () => {
    const extra = fixture();
    put(join(extra.bundle, 'unexpected.txt'), 'unexpected\n');
    expectCode('BUNDLE_POPULATION_MISMATCH', () =>
      verifyPreparedBundle({ bundleDir: extra.bundle, trustStorePath: extra.trustStorePath }),
    );

    const state = fixture();
    publishCandidateEvidence(options(state, []));
    state.receipt.createdAt = '2026-08-16T00:00:03.000Z';
    const payload = canonicalBytes(state.receipt);
    const envelope = JSON.parse(readFileSync(join(state.bundle, 'envelope.json'), 'utf8'));
    envelope.payload = payload.toString('base64');
    envelope.signatures[0].signature = sign(null, payload, state.keys.privateKey).toString('base64');
    put(join(state.bundle, 'envelope.json'), envelope);
    const manifest = JSON.parse(readFileSync(join(state.bundle, 'manifest.json'), 'utf8'));
    manifest.envelopeDigest = sha256Hex(envelope);
    put(join(state.bundle, 'manifest.json'), manifest);
    expectCode('TAG_COLLISION', () => publishCandidateEvidence(options(state, [])));
  });
});

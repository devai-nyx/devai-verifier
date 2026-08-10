import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { canonicalize, sha256Hex } from '../src/canonical.js';
import { exportCandidateEvidence } from '../src/export.js';
import { buildExpectedTaskPolicy } from '../src/policy-builder.js';
import { loadAndVerify } from '../src/verify.js';

const temporaryDirectories = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function git(repo, args) {
  return execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim();
}

function put(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

function expectCode(code, action) {
  assert.throws(action, (error) => error?.code === code);
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'devai-export-test-'));
  temporaryDirectories.push(root);
  const repo = join(root, 'candidate');
  mkdirSync(repo);
  git(repo, ['init', '--quiet', '-b', 'main']);
  git(repo, ['config', 'user.name', 'Verifier Test']);
  git(repo, ['config', 'user.email', 'verifier@example.invalid']);
  const descriptor = {
    schemaVersion: '1.0.0',
    descriptorVersion: 'fixture-1',
    repositoryId: 'fixture/repository',
    fallbackNodeId: null,
    dynamicFallbackSelectors: [],
    tasks: [
      {
        nodeId: 'test:one',
        dependencies: [],
        argv: ['node', '--test'],
        cwd: '.',
        runner: 'node-test-v1',
        inputSelectors: [{ kind: 'exact', pattern: 'input.txt' }],
        toolchainKeys: ['node'],
        allowlistedEnv: [],
        outputContract: { kind: 'node-test', requiredResult: 'pass' },
      },
    ],
    profiles: [{ profileId: 'rc', mode: 'fixed', requiredNodes: ['test:one'] }],
  };
  put(join(repo, 'input.txt'), 'input\n');
  put(join(repo, 'test-tasks.json'), `${JSON.stringify(descriptor, null, 2)}\n`);
  git(repo, ['add', '-A']);
  git(repo, ['commit', '--quiet', '-m', 'candidate']);
  const commit = git(repo, ['rev-parse', 'HEAD']);
  const tree = git(repo, ['rev-parse', 'HEAD^{tree}']);
  const toolchain = join(root, 'toolchain.json');
  const environment = join(root, 'environment.json');
  put(toolchain, '{"node":"v24.5.0"}\n');
  put(environment, '{}\n');
  const built = buildExpectedTaskPolicy({
    repo,
    descriptor,
    profileId: 'rc',
    candidateCommit: commit,
    expectedTree: tree,
    toolchain: { node: 'v24.5.0' },
    environment: {},
  });
  const result = {
    schemaVersion: '1.0.0',
    nodeId: 'test:one',
    taskKey: built.taskPolicy.requiredNodes[0].taskKey,
    status: 'PASS',
    inputDigest: '1'.repeat(64),
    dependencyResultDigests: {},
    outputDigests: { stdout: '2'.repeat(64) },
    startedAt: '2026-08-10T00:00:00.000Z',
    finishedAt: '2026-08-10T00:00:01.000Z',
  };
  const resultDigest = sha256Hex(result);
  const resultsDir = join(root, 'runner-results');
  mkdirSync(resultsDir);
  put(join(resultsDir, `${resultDigest}.json`), canonicalize(result));
  const receipt = {
    schemaVersion: '1.0.0',
    repository: { id: descriptor.repositoryId, commit, tree },
    profile: 'rc',
    taskPolicyDigest: built.taskPolicyDigest,
    createdAt: '2026-08-10T00:00:02.000Z',
    tasks: [{ nodeId: 'test:one', taskKey: result.taskKey, resultDigest }],
  };
  const receiptPath = join(root, 'receipt.json');
  put(receiptPath, canonicalize(receipt));
  const keys = generateKeyPairSync('ed25519');
  const privateKeyPath = join(root, 'private.pem');
  const publicKeyPath = join(root, 'public.pem');
  put(privateKeyPath, keys.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  put(publicKeyPath, keys.publicKey.export({ type: 'spki', format: 'pem' }));
  return {
    root,
    repo,
    commit,
    tree,
    toolchain,
    environment,
    resultsDir,
    receiptPath,
    privateKeyPath,
    publicKeyPath,
    outputDir: join(root, 'exported'),
    built,
  };
}

function exportOptions(state) {
  return {
    repo: state.repo,
    receiptPath: state.receiptPath,
    resultsDir: state.resultsDir,
    profile: 'rc',
    commit: state.commit,
    tree: state.tree,
    toolchainPath: state.toolchain,
    environmentPath: state.environment,
    privateKeyPath: state.privateKeyPath,
    publicKeyPath: state.publicKeyPath,
    signerId: 'local-rc-signer',
    outputDir: state.outputDir,
  };
}

describe('trusted candidate evidence export', () => {
  it('independently rebuilds policy, signs, exports only required results, and verifies', () => {
    const state = fixture();
    const result = exportCandidateEvidence(exportOptions(state));
    assert.deepEqual(result.verifiedNodes, ['test:one']);
    assert.equal(result.taskPolicyDigest, state.built.taskPolicyDigest);
    const verified = loadAndVerify({
      envelopePath: join(state.outputDir, 'envelope.json'),
      resultsDir: join(state.outputDir, 'results'),
      taskPolicyPath: join(state.outputDir, 'task-policy.json'),
      trustStorePath: join(state.outputDir, 'trust-store.json'),
      expectedRepository: 'fixture/repository',
      expectedCommit: state.commit,
      expectedTree: state.tree,
      expectedPolicyDigest: state.built.taskPolicyDigest,
    });
    assert.equal(verified.ok, true);
    assert.match(readFileSync(join(state.outputDir, 'manifest.json'), 'utf8'), /local-rc-signer/u);
  });

  it('refuses dirty candidates before signing', () => {
    const state = fixture();
    put(join(state.repo, 'dirty.txt'), 'dirty\n');
    expectCode('DIRTY_CANDIDATE', () => exportCandidateEvidence(exportOptions(state)));
    assert.equal(readFileSync(state.receiptPath, 'utf8').length > 0, true);
  });

  it('refuses stale task policy and result bindings', () => {
    const state = fixture();
    const receipt = JSON.parse(readFileSync(state.receiptPath, 'utf8'));
    receipt.taskPolicyDigest = 'f'.repeat(64);
    put(state.receiptPath, canonicalize(receipt));
    expectCode('POLICY_DIGEST_MISMATCH', () => exportCandidateEvidence(exportOptions(state)));
  });

  it('refuses candidate-controlled keys and mismatched key pairs', () => {
    const state = fixture();
    const inRepo = join(state.repo, 'candidate-key.pem');
    put(inRepo, readFileSync(state.privateKeyPath));
    git(state.repo, ['add', 'candidate-key.pem']);
    git(state.repo, ['commit', '--quiet', '-m', 'candidate-controlled key']);
    const candidateCommit = git(state.repo, ['rev-parse', 'HEAD']);
    const candidateTree = git(state.repo, ['rev-parse', 'HEAD^{tree}']);
    expectCode('TRUST_BOUNDARY_INVALID', () =>
      exportCandidateEvidence({
        ...exportOptions(state),
        commit: candidateCommit,
        tree: candidateTree,
        privateKeyPath: inRepo,
      }),
    );

    const mismatchState = fixture();
    const other = generateKeyPairSync('ed25519');
    put(mismatchState.publicKeyPath, other.publicKey.export({ type: 'spki', format: 'pem' }));
    expectCode('KEY_MISMATCH', () => exportCandidateEvidence(exportOptions(mismatchState)));
  });
});

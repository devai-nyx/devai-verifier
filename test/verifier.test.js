import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalBytes, sha256Hex } from '../src/canonical.js';
import { PAYLOAD_TYPE, verifyCandidateEvidence } from '../src/verify.js';

const COMMIT = 'a'.repeat(40);
const TREE = 'b'.repeat(40);
const NOW = '2026-08-10T18:00:00.000Z';
const CLI = resolve(import.meta.dirname, '../src/cli.js');
const temporaryDirectories = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function keyPair() {
  return generateKeyPairSync('ed25519');
}

function result(nodeId, taskKey, dependencyResultDigests = {}, status = 'PASS') {
  return {
    schemaVersion: '1.0.0',
    nodeId,
    taskKey,
    status,
    inputDigest: sha256Hex(Buffer.from(`input:${nodeId}`)),
    dependencyResultDigests,
    outputDigests: { report: sha256Hex(Buffer.from(`output:${nodeId}`)) },
    startedAt: NOW,
    finishedAt: NOW,
  };
}

function signedEnvelope(receipt, privateKey, signerId = 'owner-workstation') {
  const payload = canonicalBytes(receipt);
  return {
    schemaVersion: '1.0.0',
    payloadType: PAYLOAD_TYPE,
    payload: payload.toString('base64'),
    signatures: [{ signerId, signature: sign(null, payload, privateKey).toString('base64') }],
  };
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'devai-verifier-'));
  temporaryDirectories.push(root);
  const resultsDir = join(root, 'results');
  mkdirSync(resultsDir);
  const approved = keyPair();
  const forged = keyPair();
  const taskKeys = {
    unit: sha256Hex(Buffer.from('task:unit')),
    contract: sha256Hex(Buffer.from('task:contract')),
  };
  const unit = result('unit:core', taskKeys.unit);
  const unitDigest = sha256Hex(unit);
  const contract = result('contract:cli', taskKeys.contract, { 'unit:core': unitDigest });
  const contractDigest = sha256Hex(contract);
  const taskPolicy = {
    schemaVersion: '1.0.0',
    repositoryId: 'devaii',
    requiredNodes: [
      { nodeId: 'unit:core', taskKey: taskKeys.unit, dependencies: [] },
      { nodeId: 'contract:cli', taskKey: taskKeys.contract, dependencies: ['unit:core'] },
    ],
  };
  const policyDigest = sha256Hex(taskPolicy);
  const receipt = {
    schemaVersion: '1.0.0',
    repository: { id: 'devaii', commit: COMMIT, tree: TREE },
    profile: 'affected',
    taskPolicyDigest: policyDigest,
    createdAt: NOW,
    tasks: [
      { nodeId: 'unit:core', taskKey: taskKeys.unit, resultDigest: unitDigest },
      { nodeId: 'contract:cli', taskKey: taskKeys.contract, resultDigest: contractDigest },
    ],
  };
  const trustStore = {
    schemaVersion: '1.0.0',
    trustedSigners: [
      {
        signerId: 'owner-workstation',
        publicKeyPem: approved.publicKey.export({ type: 'spki', format: 'pem' }),
      },
    ],
    revokedSignerIds: [],
  };
  writeFileSync(join(resultsDir, `${unitDigest}.json`), JSON.stringify(unit));
  writeFileSync(join(resultsDir, `${contractDigest}.json`), JSON.stringify(contract));
  return {
    root,
    resultsDir,
    approved,
    forged,
    taskKeys,
    taskPolicy,
    policyDigest,
    receipt,
    trustStore,
    envelope: signedEnvelope(receipt, approved.privateKey),
  };
}

function verify(state, overrides = {}) {
  return verifyCandidateEvidence({
    envelope: state.envelope,
    resultsDir: state.resultsDir,
    taskPolicy: state.taskPolicy,
    trustStore: state.trustStore,
    expectedRepository: 'devaii',
    expectedCommit: COMMIT,
    expectedTree: TREE,
    expectedPolicyDigest: state.policyDigest,
    ...overrides,
  });
}

function replaceResult(state, nodeId, nextResult) {
  const task = state.receipt.tasks.find((entry) => entry.nodeId === nodeId);
  const previous = join(state.resultsDir, `${task.resultDigest}.json`);
  try {
    unlinkSync(previous);
  } catch {}
  task.resultDigest = sha256Hex(nextResult);
  writeFileSync(join(state.resultsDir, `${task.resultDigest}.json`), JSON.stringify(nextResult));
  const dependent = state.receipt.tasks.find((entry) => entry.nodeId === 'contract:cli');
  if (nodeId === 'unit:core' && dependent !== undefined) {
    const dependentPath = join(state.resultsDir, `${dependent.resultDigest}.json`);
    const value = JSON.parse(readFileSync(dependentPath, 'utf8'));
    unlinkSync(dependentPath);
    value.dependencyResultDigests['unit:core'] = task.resultDigest;
    dependent.resultDigest = sha256Hex(value);
    writeFileSync(join(state.resultsDir, `${dependent.resultDigest}.json`), JSON.stringify(value));
  }
  state.envelope = signedEnvelope(state.receipt, state.approved.privateKey);
}

function expectCode(code, action) {
  assert.throws(action, (error) => error?.code === code);
}

describe('candidate-independent evidence verification', () => {
  it('accepts an exact canonical receipt with complete current PASS results', () => {
    const state = fixture();
    const verified = verify(state);
    assert.deepEqual(verified.verifiedNodes, ['contract:cli', 'unit:core']);
    assert.equal(verified.signerId, 'owner-workstation');
  });

  it('rejects a forged key and a changed signed receipt', () => {
    const forged = fixture();
    forged.envelope = signedEnvelope(forged.receipt, forged.forged.privateKey);
    expectCode('SIGNATURE_INVALID', () => verify(forged));

    const changed = fixture();
    const payload = structuredClone(changed.receipt);
    payload.profile = 'rc';
    changed.envelope.payload = canonicalBytes(payload).toString('base64');
    expectCode('SIGNATURE_INVALID', () => verify(changed));
  });

  it('rejects omitted and unknown nodes even when a trusted signer signs them', () => {
    for (const mutate of [
      (receipt) => receipt.tasks.pop(),
      (receipt) =>
        receipt.tasks.push({
          nodeId: 'unknown:extra',
          taskKey: 'c'.repeat(64),
          resultDigest: 'd'.repeat(64),
        }),
    ]) {
      const state = fixture();
      mutate(state.receipt);
      state.envelope = signedEnvelope(state.receipt, state.approved.privateKey);
      expectCode('NODE_POPULATION_MISMATCH', () => verify(state));
    }
  });

  it('rejects wrong repository, commit, tree, and policy bindings', () => {
    const cases = [
      ['REPOSITORY_MISMATCH', { expectedRepository: 'another-repository' }],
      ['COMMIT_MISMATCH', { expectedCommit: 'c'.repeat(40) }],
      ['TREE_MISMATCH', { expectedTree: 'd'.repeat(40) }],
      ['POLICY_DIGEST_MISMATCH', { expectedPolicyDigest: 'e'.repeat(64) }],
    ];
    for (const [code, overrides] of cases) {
      const state = fixture();
      expectCode(code, () => verify(state, overrides));
    }
  });

  it('accepts a different commit only in explicit exact-tree mode', () => {
    const state = fixture();
    const mergedCommit = 'c'.repeat(40);
    expectCode('COMMIT_MISMATCH', () => verify(state, { expectedCommit: mergedCommit }));
    const verified = verify(state, {
      expectedCommit: mergedCommit,
      bindingMode: 'exact-tree',
    });
    assert.equal(verified.binding, 'exact-tree');
    assert.equal(verified.commit, mergedCommit);
    assert.equal(verified.evidenceCommit, COMMIT);

    expectCode('TREE_MISMATCH', () =>
      verify(state, {
        expectedCommit: mergedCommit,
        expectedTree: 'd'.repeat(40),
        bindingMode: 'exact-tree',
      }),
    );
  });

  it('accepts schema 1.1 policies with immutable output contracts', () => {
    const state = fixture();
    state.taskPolicy.schemaVersion = '1.1.0';
    for (const node of state.taskPolicy.requiredNodes) {
      node.outputContract = { kind: 'none' };
    }
    state.policyDigest = sha256Hex(state.taskPolicy);
    state.receipt.schemaVersion = '1.1.0';
    state.receipt.taskPolicyDigest = state.policyDigest;
    state.envelope = signedEnvelope(state.receipt, state.approved.privateKey);
    assert.equal(verify(state).ok, true);

    delete state.taskPolicy.requiredNodes[0].outputContract;
    expectCode('SCHEMA_INVALID', () => verify(state));
  });

  it('rejects revoked and untrusted signers', () => {
    const revoked = fixture();
    revoked.trustStore.revokedSignerIds.push('owner-workstation');
    expectCode('SIGNER_REVOKED', () => verify(revoked));

    const untrusted = fixture();
    untrusted.envelope.signatures[0].signerId = 'unknown-signer';
    expectCode('SIGNER_UNTRUSTED', () => verify(untrusted));
  });

  it('rejects missing, FAIL, ABORTED, and unknown task results', () => {
    const missing = fixture();
    const missingTask = missing.receipt.tasks[0];
    unlinkSync(join(missing.resultsDir, `${missingTask.resultDigest}.json`));
    expectCode('INPUT_MISSING', () => verify(missing));

    for (const status of ['FAIL', 'ABORTED', 'UNKNOWN']) {
      const state = fixture();
      replaceResult(state, 'unit:core', result('unit:core', state.taskKeys.unit, {}, status));
      expectCode('TASK_STATUS_NOT_PASS', () => verify(state));
    }
  });

  it('rejects stale task keys, stale dependencies, malformed JSON, and changed result bytes', () => {
    const stale = fixture();
    stale.receipt.tasks[0].taskKey = 'f'.repeat(64);
    stale.envelope = signedEnvelope(stale.receipt, stale.approved.privateKey);
    expectCode('TASK_KEY_STALE', () => verify(stale));

    const dependency = fixture();
    const contractTask = dependency.receipt.tasks.find((entry) => entry.nodeId === 'contract:cli');
    const contractPath = join(dependency.resultsDir, `${contractTask.resultDigest}.json`);
    const contract = JSON.parse(readFileSync(contractPath, 'utf8'));
    unlinkSync(contractPath);
    contract.dependencyResultDigests['unit:core'] = '0'.repeat(64);
    contractTask.resultDigest = sha256Hex(contract);
    writeFileSync(join(dependency.resultsDir, `${contractTask.resultDigest}.json`), JSON.stringify(contract));
    dependency.envelope = signedEnvelope(dependency.receipt, dependency.approved.privateKey);
    expectCode('DEPENDENCY_MISMATCH', () => verify(dependency));

    const malformed = fixture();
    const malformedTask = malformed.receipt.tasks[0];
    writeFileSync(join(malformed.resultsDir, `${malformedTask.resultDigest}.json`), '{');
    expectCode('MALFORMED_JSON', () => verify(malformed));

    const changed = fixture();
    const changedTask = changed.receipt.tasks[0];
    writeFileSync(join(changed.resultsDir, `${changedTask.resultDigest}.json`), '{}');
    expectCode('RESULT_DIGEST_MISMATCH', () => verify(changed));
  });
});

describe('CLI exit contract', () => {
  function writeInputs(state) {
    const paths = {
      envelope: join(state.root, 'envelope.json'),
      policy: join(state.root, 'policy.json'),
      trust: join(state.root, 'trust.json'),
    };
    writeFileSync(paths.envelope, JSON.stringify(state.envelope));
    writeFileSync(paths.policy, JSON.stringify(state.taskPolicy));
    writeFileSync(paths.trust, JSON.stringify(state.trustStore));
    return paths;
  }

  function args(state, paths) {
    return [
      CLI,
      '--envelope',
      paths.envelope,
      '--results-dir',
      state.resultsDir,
      '--task-policy',
      paths.policy,
      '--trust',
      paths.trust,
      '--repository',
      'devaii',
      '--commit',
      COMMIT,
      '--tree',
      TREE,
      '--policy-digest',
      state.policyDigest,
    ];
  }

  it('uses exit 0/stdout for PASS and exit 2/stderr for rejection', () => {
    const state = fixture();
    const paths = writeInputs(state);
    const pass = spawnSync(process.execPath, args(state, paths), { encoding: 'utf8' });
    assert.equal(pass.status, 0, pass.stderr);
    assert.equal(pass.stderr, '');
    assert.equal(JSON.parse(pass.stdout).ok, true);

    state.envelope.signatures[0].signature = Buffer.from('forged').toString('base64');
    writeFileSync(paths.envelope, JSON.stringify(state.envelope));
    const rejected = spawnSync(process.execPath, args(state, paths), { encoding: 'utf8' });
    assert.equal(rejected.status, 2);
    assert.equal(rejected.stdout, '');
    assert.equal(JSON.parse(rejected.stderr).code, 'SIGNATURE_INVALID');
  });

  it('uses exit 64 for invalid usage', () => {
    const result = spawnSync(process.execPath, [CLI, '--unknown', 'value'], { encoding: 'utf8' });
    assert.equal(result.status, 64);
    assert.equal(result.stdout, '');
    assert.equal(JSON.parse(result.stderr).code, 'USAGE');
  });
});

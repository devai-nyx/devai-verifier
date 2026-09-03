import { generateKeyPairSync, sign } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalBytes, canonicalize, sha256Hex } from '../src/canonical.js';
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
    signatures: [
      {
        signerId,
        signature: sign(null, payload, privateKey).toString('base64'),
      },
    ],
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
  const contract = result('contract:cli', taskKeys.contract, {
    'unit:core': unitDigest,
  });
  const contractDigest = sha256Hex(contract);
  const taskPolicy = {
    schemaVersion: '1.0.0',
    repositoryId: 'devaii',
    requiredNodes: [
      { nodeId: 'unit:core', taskKey: taskKeys.unit, dependencies: [] },
      {
        nodeId: 'contract:cli',
        taskKey: taskKeys.contract,
        dependencies: ['unit:core'],
      },
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
      {
        nodeId: 'contract:cli',
        taskKey: taskKeys.contract,
        resultDigest: contractDigest,
      },
    ],
  };
  const trustStore = {
    schemaVersion: '1.0.0',
    trustedSigners: [
      {
        signerId: 'owner-workstation',
        publicKeyPem: approved.publicKey.export({
          type: 'spki',
          format: 'pem',
        }),
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

function composedEvidenceFixture() {
  const root = mkdtempSync(join(tmpdir(), 'devai-composed-verifier-'));
  temporaryDirectories.push(root);
  const resultsDir = join(root, 'results');
  const artifactsDir = join(root, 'artifacts');
  mkdirSync(resultsDir);
  const approved = keyPair();
  const taskKey = sha256Hex(Buffer.from('task:mutation'));
  const baseline = {
    commit: 'c'.repeat(40),
    tree: 'd'.repeat(40),
    summaryBytes: 512,
    summarySha256: 'e'.repeat(64),
  };
  const packageContracts = [0, 1].map((index) => {
    const stem = `package-${index}`;
    return {
      packageName: `@fixture/${stem}`,
      workspace: `packages/${stem}`,
      resultPath: `mutation/${stem}.result.json`,
      reportPath: `mutation/${stem}.stryker.json`,
      thresholds: { break: 90, high: 100, low: 90 },
    };
  });
  const outputContract = {
    kind: 'mutation-report-set-v1',
    expectedPackageCount: 2,
    summaryPath: 'mutation/summary.json',
    packages: packageContracts,
    paths: [
      'mutation/summary.json',
      ...packageContracts.flatMap((entry) => [entry.resultPath, entry.reportPath]),
    ],
  };
  const summaryPackages = [];
  const outputDigests = {
    stderr: sha256Hex(Buffer.from('stderr')),
    stdout: sha256Hex(Buffer.from('stdout')),
  };
  function putArtifact(path, value) {
    const bytes = Buffer.from(`${canonicalize(value)}\n`);
    mkdirSync(dirname(join(artifactsDir, path)), { recursive: true });
    writeFileSync(join(artifactsDir, path), bytes);
    outputDigests[path] = sha256Hex(bytes);
  }
  for (const [index, contract] of packageContracts.entries()) {
    const fresh = index === 0;
    const report = {
      schemaVersion: '1',
      projectRoot: '.',
      thresholds: contract.thresholds,
      files: {
        [`src/package-${index}.ts`]: {
          language: 'typescript',
          mutants: [{ id: String(index), status: 'Killed' }],
        },
      },
      testFiles: {},
      config: {},
      framework: { name: 'StrykerJS', branding: {} },
    };
    const reportDigest = sha256Hex(Buffer.from(canonicalize(report)));
    const process = { errorAbsent: true, signal: null, status: 0 };
    const packageResult = {
      schemaVersion: '1.0.0',
      kind: 'mutation-package-result-v1',
      packageName: contract.packageName,
      workspace: contract.workspace,
      passed: true,
      durationMs: index + 1,
      toolVersions: { stryker: '9.6.1' },
      thresholds: contract.thresholds,
      score: 100,
      statusTotals: {
        CompileError: 0,
        Ignored: 0,
        Killed: 1,
        NoCoverage: 0,
        Pending: 0,
        RuntimeError: 0,
        Survived: 0,
        Timeout: 0,
      },
      reportDigest,
      ...(fresh && { process }),
    };
    const resultDigest = sha256Hex(Buffer.from(canonicalize(packageResult)));
    summaryPackages.push({
      baselineCommit: fresh ? null : baseline.commit,
      baselineTree: fresh ? null : baseline.tree,
      durationMs: index + 1,
      inputProjectionDigest: sha256Hex(Buffer.from(`input:${index}`)),
      packageName: contract.packageName,
      passed: true,
      ...(fresh && { process }),
      provenance: fresh ? 'fresh' : 'reused',
      reportDigest,
      reportPath: contract.reportPath,
      resultDigest,
      resultPath: contract.resultPath,
      score: 100,
      statusTotals: packageResult.statusTotals,
      targetCensus: { targetFileCount: 1, totalMutants: 1 },
      thresholds: contract.thresholds,
      workspace: contract.workspace,
    });
    putArtifact(contract.reportPath, report);
    putArtifact(contract.resultPath, packageResult);
  }
  const summary = {
    schemaVersion: '1.0.0',
    kind: 'mutation-composed-report-set-v1',
    candidate: { commit: COMMIT, tree: TREE },
    baseline,
    semanticRebindComparison: {
      kind: 'root-manifest-unchanged-with-historical-input-v1',
      allowedScriptTransitions: [],
      canonicalContractBytes: 128,
      canonicalContractSha256: 'f'.repeat(64),
      comparison: {
        historicalMutationInputTreeEntries: 'match-explicit-historical-candidate-mode-type-oid',
        otherMutationInputTreeEntries: 'identical-mode-type-oid',
        rootManifest: 'source-and-target-identical',
      },
      sourceRootManifest: {
        bytes: 100,
        gitBlobOid: '1'.repeat(40),
        sha256: '2'.repeat(64),
      },
      targetRootManifest: {
        bytes: 100,
        gitBlobOid: '1'.repeat(40),
        sha256: '2'.repeat(64),
      },
    },
    complete: true,
    passed: true,
    packages: summaryPackages,
    aggregate: {
      packageCount: 2,
      freshPackageCount: 1,
      reusedPackageCount: 1,
      durationMs: 3,
      freshDurationMs: 1,
      score: 100,
      statusTotals: {
        CompileError: 0,
        Ignored: 0,
        Killed: 2,
        NoCoverage: 0,
        Pending: 0,
        RuntimeError: 0,
        Survived: 0,
        Timeout: 0,
      },
    },
  };
  putArtifact(outputContract.summaryPath, summary);
  const taskResult = result('test:mutation', taskKey);
  taskResult.outputDigests = outputDigests;
  let resultDigest = sha256Hex(taskResult);
  writeFileSync(join(resultsDir, `${resultDigest}.json`), JSON.stringify(taskResult));
  const taskPolicy = {
    schemaVersion: '1.1.0',
    repositoryId: 'devaii',
    requiredNodes: [{ nodeId: 'test:mutation', taskKey, dependencies: [], outputContract }],
  };
  const policyDigest = sha256Hex(taskPolicy);
  const receipt = {
    schemaVersion: '1.1.0',
    repository: { id: 'devaii', commit: COMMIT, tree: TREE },
    profile: 'rc',
    taskPolicyDigest: policyDigest,
    createdAt: NOW,
    tasks: [{ nodeId: 'test:mutation', taskKey, resultDigest }],
  };
  const trustStore = {
    schemaVersion: '1.0.0',
    trustedSigners: [
      {
        signerId: 'owner-workstation',
        publicKeyPem: approved.publicKey.export({
          type: 'spki',
          format: 'pem',
        }),
      },
    ],
    revokedSignerIds: [],
  };
  const state = {
    root,
    resultsDir,
    artifactsDir,
    approved,
    taskKey,
    taskPolicy,
    policyDigest,
    receipt,
    trustStore,
    envelope: signedEnvelope(receipt, approved.privateKey),
    summary,
    taskResult,
    outputContract,
  };
  state.rewriteSummary = () => {
    const summaryBytes = Buffer.from(`${canonicalize(state.summary)}\n`);
    writeFileSync(join(state.artifactsDir, state.outputContract.summaryPath), summaryBytes);
    state.taskResult.outputDigests[state.outputContract.summaryPath] = sha256Hex(summaryBytes);
    unlinkSync(join(state.resultsDir, `${resultDigest}.json`));
    resultDigest = sha256Hex(state.taskResult);
    state.receipt.tasks[0].resultDigest = resultDigest;
    writeFileSync(join(state.resultsDir, `${resultDigest}.json`), JSON.stringify(state.taskResult));
    state.envelope = signedEnvelope(state.receipt, state.approved.privateKey);
  };
  return state;
}

/**
 * Builds signed schema 1.1 evidence for a single all-fresh `mutation-report-set-v2`
 * package. `extension` renames every declared mutation artifact so the same canonical
 * JSON documents can be verified under a filename an extension-based media-type guess
 * would treat as opaque.
 */
function signedMutationV2Fixture({ extension = 'json', replacement, summarySha256 } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'devai-mutation-v2-verifier-'));
  temporaryDirectories.push(root);
  const resultsDir = join(root, 'results');
  const artifactsDir = join(root, 'artifacts');
  mkdirSync(resultsDir);
  const approved = keyPair();
  const taskKey = sha256Hex(Buffer.from('task:mutation-v2'));
  const packageName = '@fixture/package-0';
  const workspace = 'packages/package-0';
  const thresholds = { break: 90, high: 100, low: 90 };
  const summaryPath = `mutation/summary.${extension}`;
  const reportPath = `mutation/package-0.stryker.${extension}`;
  const resultPath = `mutation/package-0.result.${extension}`;
  const statusTotals = {
    CompileError: 0,
    Ignored: 0,
    Killed: 1,
    NoCoverage: 0,
    Pending: 0,
    RuntimeError: 0,
    Survived: 0,
    Timeout: 0,
  };
  const process = { errorAbsent: true, signal: null, status: 0 };
  const report = {
    schemaVersion: '1',
    projectRoot: '.',
    thresholds,
    files: {
      'src/package-0.ts': {
        language: 'typescript',
        mutants: [
          {
            id: '0',
            status: 'Killed',
            ...(replacement !== undefined && { replacement }),
          },
        ],
      },
    },
    testFiles: {},
    config: {},
    framework: { name: 'StrykerJS', branding: {} },
  };
  const reportDigest = sha256Hex(Buffer.from(canonicalize(report)));
  const packageResult = {
    schemaVersion: '1.0.0',
    kind: 'mutation-package-result-v1',
    packageName,
    workspace,
    passed: true,
    durationMs: 5,
    toolVersions: { stryker: '9.6.1' },
    thresholds,
    score: 100,
    statusTotals,
    reportDigest,
    process,
  };
  const resultDigest = sha256Hex(Buffer.from(canonicalize(packageResult)));
  const evidenceRef = {
    baselineCommit: null,
    baselineTree: null,
    inputProjectionDigest: sha256Hex(Buffer.from(`input:${packageName}`)),
    kind: 'mutation-package-evidence-ref-v2',
    packageName,
    provenance: 'fresh',
    reportDigest,
    reportPath,
    resultDigest,
    resultPath,
    workspace,
  };
  const evidenceRefDigest = sha256Hex(evidenceRef);
  const summary = {
    schemaVersion: '2.0.0',
    kind: 'mutation-composed-report-set-v2',
    candidate: { commit: COMMIT, tree: TREE },
    baseline: {
      commit: 'c'.repeat(40),
      tree: 'd'.repeat(40),
      summaryBytes: 512,
      summarySha256: summarySha256 ?? 'e'.repeat(64),
    },
    semanticRebindComparison: {
      kind: 'root-manifest-unchanged-with-historical-input-v1',
      allowedScriptTransitions: [],
      canonicalContractBytes: 128,
      canonicalContractSha256: 'f'.repeat(64),
      comparison: {
        historicalMutationInputTreeEntries: 'match-explicit-historical-candidate-mode-type-oid',
        otherMutationInputTreeEntries: 'identical-mode-type-oid',
        rootManifest: 'source-and-target-identical',
      },
      sourceRootManifest: {
        bytes: 100,
        gitBlobOid: '1'.repeat(40),
        sha256: '2'.repeat(64),
      },
      targetRootManifest: {
        bytes: 100,
        gitBlobOid: '1'.repeat(40),
        sha256: '2'.repeat(64),
      },
    },
    complete: true,
    passed: true,
    packages: [
      {
        baselineCommit: null,
        baselineTree: null,
        durationMs: 5,
        evidenceRef,
        evidenceRefDigest,
        inputProjectionDigest: evidenceRef.inputProjectionDigest,
        packageName,
        passed: true,
        process,
        provenance: 'fresh',
        reportDigest,
        reportPath,
        resultDigest,
        resultPath,
        score: 100,
        statusTotals,
        targetCensus: { targetFileCount: 1, totalMutants: 1 },
        thresholds,
        workspace,
      },
    ],
    aggregate: {
      packageCount: 1,
      freshPackageCount: 1,
      reusedPackageCount: 0,
      durationMs: 5,
      freshDurationMs: 5,
      reusedDurationMs: 0,
      score: 100,
      statusTotals,
      evidenceSetDigest: sha256Hex([evidenceRefDigest]),
    },
  };
  const outputDigests = {
    stderr: sha256Hex(Buffer.from('stderr')),
    stdout: sha256Hex(Buffer.from('stdout')),
  };
  for (const [path, value] of [
    [reportPath, report],
    [resultPath, packageResult],
    [summaryPath, summary],
  ]) {
    const bytes = Buffer.from(`${canonicalize(value)}\n`);
    mkdirSync(dirname(join(artifactsDir, path)), { recursive: true });
    writeFileSync(join(artifactsDir, path), bytes);
    outputDigests[path] = sha256Hex(bytes);
  }
  const taskResult = result('test:mutation', taskKey);
  taskResult.outputDigests = outputDigests;
  const taskResultDigest = sha256Hex(taskResult);
  writeFileSync(join(resultsDir, `${taskResultDigest}.json`), JSON.stringify(taskResult));
  const taskPolicy = {
    schemaVersion: '1.1.0',
    repositoryId: 'devaii',
    requiredNodes: [
      {
        nodeId: 'test:mutation',
        taskKey,
        dependencies: [],
        outputContract: {
          kind: 'mutation-report-set-v2',
          schemaVersion: '2.0.0',
          expectedPackageCount: 1,
          summaryPath,
          packages: [{ packageName, workspace, reportPath, resultPath, thresholds }],
          paths: [summaryPath, resultPath, reportPath],
        },
      },
    ],
  };
  const policyDigest = sha256Hex(taskPolicy);
  const receipt = {
    schemaVersion: '1.1.0',
    repository: { id: 'devaii', commit: COMMIT, tree: TREE },
    profile: 'rc',
    taskPolicyDigest: policyDigest,
    createdAt: NOW,
    tasks: [{ nodeId: 'test:mutation', taskKey, resultDigest: taskResultDigest }],
  };
  return {
    root,
    resultsDir,
    artifactsDir,
    approved,
    taskPolicy,
    policyDigest,
    receipt,
    statusTotals,
    evidenceSetDigest: summary.aggregate.evidenceSetDigest,
    trustStore: {
      schemaVersion: '1.0.0',
      trustedSigners: [
        {
          signerId: 'owner-workstation',
          publicKeyPem: approved.publicKey.export({
            type: 'spki',
            format: 'pem',
          }),
        },
      ],
      revokedSignerIds: [],
    },
    envelope: signedEnvelope(receipt, approved.privateKey),
  };
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

  it('rejects a signed mutation output contract that declares no artifact paths', () => {
    function signedPolicy(outputContract) {
      const state = fixture();
      state.taskPolicy.schemaVersion = '1.1.0';
      for (const node of state.taskPolicy.requiredNodes) node.outputContract = { kind: 'none' };
      state.taskPolicy.requiredNodes[0].outputContract = outputContract;
      state.policyDigest = sha256Hex(state.taskPolicy);
      state.receipt.schemaVersion = '1.1.0';
      state.receipt.taskPolicyDigest = state.policyDigest;
      state.envelope = signedEnvelope(state.receipt, state.approved.privateKey);
      return state;
    }
    const roster = {
      expectedPackageCount: 1,
      packages: [
        {
          packageName: '@fixture/package-0',
          workspace: 'packages/package-0',
          resultPath: 'mutation/package-0.result.json',
          reportPath: 'mutation/package-0.stryker.json',
          thresholds: { break: 90, high: 100, low: 90 },
        },
      ],
      summaryPath: 'mutation/summary.json',
    };
    const cases = [
      ['SCHEMA_INVALID', { kind: 'mutation-report-set-v2', schemaVersion: '2.0.0', ...roster }],
      ['SCHEMA_INVALID', { kind: 'mutation-report-set-v2' }],
      ['SCHEMA_INVALID', { kind: 'mutation-report-set-v1', ...roster }],
      ['MUTATION_VERSION_UNSUPPORTED', { kind: 'mutation-report-set-v3', ...roster }],
    ];
    for (const [code, outputContract] of cases) {
      const state = signedPolicy(outputContract);
      expectCode(code, () => verify(state, { artifactsDir: state.root }));
    }
  });

  it('passes the signed receipt candidate into composed mutation verification', () => {
    const state = composedEvidenceFixture();
    const verified = verify(state, { artifactsDir: state.artifactsDir });
    assert.deepEqual(verified.verifiedMutation, [
      {
        nodeId: 'test:mutation',
        packageCount: 2,
        score: 100,
        statusTotals: {
          CompileError: 0,
          Ignored: 0,
          Killed: 2,
          NoCoverage: 0,
          Pending: 0,
          RuntimeError: 0,
          Survived: 0,
          Timeout: 0,
        },
      },
    ]);

    state.summary.candidate.commit = '9'.repeat(40);
    state.rewriteSummary();
    expectCode('MUTATION_SUMMARY_MISMATCH', () =>
      verify(state, { artifactsDir: state.artifactsDir }),
    );
  });

  it('inspects signed v2 mutation documents declared under an opaque extension', () => {
    for (const extension of ['json', 'bin']) {
      const clean = signedMutationV2Fixture({ extension });
      const verified = verify(clean, { artifactsDir: clean.artifactsDir });
      assert.deepEqual(verified.verifiedMutation, [
        {
          nodeId: 'test:mutation',
          packageCount: 1,
          score: 100,
          statusTotals: clean.statusTotals,
          evidenceSetDigest: clean.evidenceSetDigest,
        },
      ]);

      const credential = signedMutationV2Fixture({
        extension,
        replacement: `gho_${'a'.repeat(36)}`,
      });
      expectCode('ARTIFACT_CREDENTIAL_MATERIAL', () =>
        verify(credential, { artifactsDir: credential.artifactsDir }),
      );

      const hostPath = signedMutationV2Fixture({
        extension,
        summarySha256: '/Volumes/Thiamat/stynx/mutation/summary.json',
      });
      expectCode('ARTIFACT_HOST_PATH', () =>
        verify(hostPath, { artifactsDir: hostPath.artifactsDir }),
      );
    }
  });

  it('rejects revoked and untrusted signers', () => {
    const revoked = fixture();
    revoked.trustStore.revokedSignerIds.push('owner-workstation');
    expectCode('SIGNER_REVOKED', () => verify(revoked));

    const untrusted = fixture();
    untrusted.envelope.signatures[0].signerId = 'unknown-signer';
    expectCode('SIGNER_UNTRUSTED', () => verify(untrusted));
  });

  it('rejects missing, symlinked, FAIL, ABORTED, and unknown task results', () => {
    const missing = fixture();
    const missingTask = missing.receipt.tasks[0];
    unlinkSync(join(missing.resultsDir, `${missingTask.resultDigest}.json`));
    expectCode('INPUT_MISSING', () => verify(missing));

    // The link points at the very bytes the receipt digest commits to, so a verifier
    // that followed it would report success on a file outside the results directory.
    const linked = fixture();
    const linkedPath = join(linked.resultsDir, `${linked.receipt.tasks[0].resultDigest}.json`);
    const external = join(linked.root, 'external-result.json');
    renameSync(linkedPath, external);
    symlinkSync(external, linkedPath);
    assert.throws(
      () => verify(linked),
      (error) =>
        error.code === 'RESULT_INVALID' &&
        error.message === 'task result unit:core must be a regular non-symlink file',
    );

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
    writeFileSync(
      join(dependency.resultsDir, `${contractTask.resultDigest}.json`),
      JSON.stringify(contract),
    );
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
    const pass = spawnSync(process.execPath, args(state, paths), {
      encoding: 'utf8',
    });
    assert.equal(pass.status, 0, pass.stderr);
    assert.equal(pass.stderr, '');
    assert.equal(JSON.parse(pass.stdout).ok, true);

    state.envelope.signatures[0].signature = Buffer.from('forged').toString('base64');
    writeFileSync(paths.envelope, JSON.stringify(state.envelope));
    const rejected = spawnSync(process.execPath, args(state, paths), {
      encoding: 'utf8',
    });
    assert.equal(rejected.status, 2);
    assert.equal(rejected.stdout, '');
    assert.equal(JSON.parse(rejected.stderr).code, 'SIGNATURE_INVALID');
  });

  it('uses exit 64 for invalid usage', () => {
    const result = spawnSync(process.execPath, [CLI, '--unknown', 'value'], {
      encoding: 'utf8',
    });
    assert.equal(result.status, 64);
    assert.equal(result.stdout, '');
    assert.equal(JSON.parse(result.stderr).code, 'USAGE');
  });
});

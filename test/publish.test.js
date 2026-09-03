import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import fs from 'node:fs';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { canonicalBytes, canonicalize, sha256Hex } from '../src/canonical.js';
import {
  assertMutationWriteBoundary,
  publishCandidateEvidence,
  verifyPreparedBundle,
} from '../src/publish.js';
import { PAYLOAD_TYPE } from '../src/verify.js';

const temporaryDirectories = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function git(repo, args) {
  return execFileSync('git', ['-C', repo, ...args], {
    encoding: 'utf8',
  }).trim();
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
      {
        nodeId: 'test:rc',
        taskKey,
        dependencies: [],
        outputContract: {
          kind: 'files',
          paths: ['generated.json'],
          requiredResult: 'pass',
        },
      },
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
      'generated.json': sha256Hex(Buffer.from('{"proof":true}\n')),
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
  put(join(bundle, 'artifacts', 'generated.json'), '{"proof":true}\n');
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
    artifacts: [
      {
        path: 'generated.json',
        mediaType: 'application/json',
        sha256: sha256Hex(Buffer.from('{"proof":true}\n')),
      },
    ],
  });
  const trustStorePath = join(root, 'trust.json');
  put(trustStorePath, trust);
  return {
    root,
    remote,
    repo,
    bundle,
    trustStorePath,
    commit,
    tree,
    keys,
    receipt,
  };
}

function mutationV2Artifacts(commit, tree) {
  const thresholds = { break: 90, high: 100, low: 90 };
  const packageName = '@fixture/core';
  const workspace = 'packages/core';
  const summaryPath = 'mutation/summary.json';
  const reportPath = 'mutation/packages-core.stryker.json';
  const resultPath = 'mutation/packages-core.result.json';
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
      'src/core.ts': {
        language: 'typescript',
        mutants: [{ id: '0', status: 'Killed' }],
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
    durationMs: 7,
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
    candidate: { commit, tree },
    baseline: {
      commit: 'f'.repeat(40),
      tree: '9'.repeat(40),
      summaryBytes: 2048,
      summarySha256: '8'.repeat(64),
    },
    semanticRebindComparison: {
      kind: 'root-manifest-unchanged-with-historical-input-v1',
      allowedScriptTransitions: [],
      canonicalContractBytes: 597,
      canonicalContractSha256: '7'.repeat(64),
      comparison: {
        historicalMutationInputTreeEntries: 'match-explicit-historical-candidate-mode-type-oid',
        otherMutationInputTreeEntries: 'identical-mode-type-oid',
        rootManifest: 'source-and-target-identical',
      },
      sourceRootManifest: {
        bytes: 512,
        gitBlobOid: '1'.repeat(40),
        sha256: '2'.repeat(64),
      },
      targetRootManifest: {
        bytes: 512,
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
        durationMs: 7,
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
      durationMs: 7,
      freshDurationMs: 7,
      reusedDurationMs: 0,
      score: 100,
      statusTotals,
      evidenceSetDigest: sha256Hex([evidenceRefDigest]),
    },
  };
  return {
    contract: {
      kind: 'mutation-report-set-v2',
      schemaVersion: '2.0.0',
      expectedPackageCount: 1,
      summaryPath,
      packages: [{ packageName, workspace, reportPath, resultPath, thresholds }],
      paths: [summaryPath, resultPath, reportPath],
    },
    files: {
      [reportPath]: report,
      [resultPath]: packageResult,
      [summaryPath]: summary,
    },
    statusTotals,
    summary,
  };
}

/**
 * Builds a prepared schema 1.1 bundle carrying a mutation-report-set-v2 output
 * contract. `seal()` rewrites every outer digest, receipt, and signature, so a
 * tampered mutation summary reaches the verifier through an otherwise intact
 * signed chain. No Git repository or remote is involved.
 */
function mutationBundleFixture() {
  const root = mkdtempSync(join(tmpdir(), 'devai-publish-mutation-'));
  temporaryDirectories.push(root);
  const commit = 'a'.repeat(40);
  const tree = 'b'.repeat(40);
  const keys = generateKeyPairSync('ed25519');
  const signerId = 'stynx-inspector-workstation-01';
  const taskKey = sha256Hex(Buffer.from('task:mutation'));
  const bundle = join(root, 'bundle');
  const trustStorePath = join(root, 'trust.json');
  put(trustStorePath, {
    schemaVersion: '1.0.0',
    trustedSigners: [
      {
        signerId,
        publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      },
    ],
    revokedSignerIds: [],
  });
  const set = mutationV2Artifacts(commit, tree);
  const policy = {
    schemaVersion: '1.1.0',
    repositoryId: 'fixture/repository',
    requiredNodes: [
      {
        nodeId: 'test:mutation',
        taskKey,
        dependencies: [],
        outputContract: set.contract,
      },
    ],
  };
  const policyDigest = sha256Hex(policy);
  put(join(bundle, 'task-policy.json'), policy);
  const state = { root, bundle, trustStorePath, commit, tree, set };
  state.seal = () => {
    const outputDigests = {
      stderr: sha256Hex(Buffer.from('')),
      stdout: sha256Hex(Buffer.from('')),
    };
    const artifacts = [];
    for (const path of [...set.contract.paths].sort()) {
      const bytes = Buffer.from(`${canonicalize(state.set.files[path])}\n`);
      put(join(bundle, 'artifacts', path), bytes.toString('utf8'));
      outputDigests[path] = sha256Hex(bytes);
      artifacts.push({
        path,
        mediaType: 'application/json',
        sha256: sha256Hex(bytes),
      });
    }
    const result = {
      schemaVersion: '1.0.0',
      nodeId: 'test:mutation',
      taskKey,
      status: 'PASS',
      inputDigest: sha256Hex(Buffer.from('input')),
      dependencyResultDigests: {},
      outputDigests,
      startedAt: '2026-08-16T00:00:00.000Z',
      finishedAt: '2026-08-16T00:00:01.000Z',
    };
    const resultDigest = sha256Hex(result);
    rmSync(join(bundle, 'results'), { recursive: true, force: true });
    put(join(bundle, 'results', `${resultDigest}.json`), result);
    const receipt = {
      schemaVersion: '1.1.0',
      repository: { id: 'fixture/repository', commit, tree },
      profile: 'rc',
      taskPolicyDigest: policyDigest,
      createdAt: '2026-08-16T00:00:02.000Z',
      tasks: [{ nodeId: 'test:mutation', taskKey, resultDigest }],
    };
    const payload = canonicalBytes(receipt);
    const envelope = {
      schemaVersion: '1.0.0',
      payloadType: PAYLOAD_TYPE,
      payload: payload.toString('base64'),
      signatures: [
        {
          signerId,
          signature: sign(null, payload, keys.privateKey).toString('base64'),
        },
      ],
    };
    put(join(bundle, 'envelope.json'), envelope);
    put(join(bundle, 'manifest.json'), {
      schemaVersion: '1.1.0',
      repositoryId: 'fixture/repository',
      commit,
      tree,
      profile: 'rc',
      signerId,
      taskPolicyDigest: policyDigest,
      envelopeDigest: sha256Hex(envelope),
      resultDigests: [resultDigest],
      artifacts,
    });
  };
  state.seal();
  return state;
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
  it('keeps v1 and draft v2 mutation evidence read-only at the publication boundary', () => {
    for (const outputContract of [
      { kind: 'mutation-report-set-v1' },
      { kind: 'mutation-report-set-v2', schemaVersion: '2.0.0' },
    ]) {
      expectCode('MUTATION_VERSION_UNSUPPORTED', () =>
        assertMutationWriteBoundary({ requiredNodes: [{ outputContract }] }),
      );
    }
    assert.doesNotThrow(() =>
      assertMutationWriteBoundary({
        requiredNodes: [
          {
            outputContract: {
              kind: 'mutation-report-set-v2',
              schemaVersion: '2.1.0',
            },
          },
        ],
      }),
    );
  });

  it('reverifies, publishes one immutable tag, dispatches, and is idempotent for identical bytes', () => {
    const state = fixture();
    const dispatched = [];
    assert.equal(
      verifyPreparedBundle({
        bundleDir: state.bundle,
        trustStorePath: state.trustStorePath,
      }).verified.ok,
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

  it('publishes the captured snapshot when the source bundle changes after verification', () => {
    const state = fixture();
    const sourceArtifact = join(state.bundle, 'artifacts', 'generated.json');
    const capturedBytes = Buffer.from('{"proof":true}\n');
    // verifyPreparedBundle reads manifest, policy, envelope, result, artifact,
    // then trust store. Switch the source immediately after capture. The former
    // publication handoff reread this path while building proof and would either
    // reject or tag B; the proof must contain the captured A bytes.
    const captureReadCount = 6;
    const originalReadFileSync = fs.readFileSync;
    let reads = 0;
    let substituted = false;
    fs.readFileSync = (...args) => {
      const bytes = originalReadFileSync(...args);
      reads += 1;
      if (reads === captureReadCount) {
        writeFileSync(sourceArtifact, '{"proof":false}\n');
        substituted = true;
      }
      return bytes;
    };
    syncBuiltinESMExports();
    try {
      const published = publishCandidateEvidence(options(state, []));
      assert.equal(substituted, true);
      assert.equal(published.published, true);
      const taggedArtifact = execFileSync('git', [
        '-C',
        state.remote,
        'show',
        `${published.tag}:artifacts/generated.json`,
      ]);
      assert.deepEqual(taggedArtifact, capturedBytes);
    } finally {
      fs.readFileSync = originalReadFileSync;
      syncBuiltinESMExports();
    }
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
      verifyPreparedBundle({
        bundleDir: extra.bundle,
        trustStorePath: extra.trustStorePath,
      }),
    );

    const state = fixture();
    publishCandidateEvidence(options(state, []));
    state.receipt.createdAt = '2026-08-16T00:00:03.000Z';
    const payload = canonicalBytes(state.receipt);
    const envelope = JSON.parse(readFileSync(join(state.bundle, 'envelope.json'), 'utf8'));
    envelope.payload = payload.toString('base64');
    envelope.signatures[0].signature = sign(null, payload, state.keys.privateKey).toString(
      'base64',
    );
    put(join(state.bundle, 'envelope.json'), envelope);
    const manifest = JSON.parse(readFileSync(join(state.bundle, 'manifest.json'), 'utf8'));
    manifest.envelopeDigest = sha256Hex(envelope);
    put(join(state.bundle, 'manifest.json'), manifest);
    expectCode('TAG_COLLISION', () => publishCandidateEvidence(options(state, [])));
  });

  it('rechecks artifact content safety before publication', () => {
    const state = fixture();
    const artifactPath = join(state.bundle, 'artifacts', 'generated.json');
    const manifestPath = join(state.bundle, 'manifest.json');
    const value = `${JSON.stringify({ token: `gho_${'a'.repeat(36)}` })}\n`;
    put(artifactPath, value);
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.artifacts[0].sha256 = sha256Hex(Buffer.from(value));
    put(manifestPath, manifest);
    expectCode('ARTIFACT_CREDENTIAL_MATERIAL', () =>
      verifyPreparedBundle({
        bundleDir: state.bundle,
        trustStorePath: state.trustStorePath,
      }),
    );
  });

  for (const [_name, replacement] of [
    ['null policy', null],
    ['non-array requiredNodes', { requiredNodes: null }],
    ['null requiredNodes member', { requiredNodes: [null] }],
  ]) {
    it(`rejects a malformed canonical task policy as SCHEMA_INVALID before v2.1 inspection: ${_name}`, () => {
      const state = fixture();
      const policyPath = join(state.bundle, 'task-policy.json');
      const policy = JSON.parse(readFileSync(policyPath, 'utf8'));
      put(policyPath, replacement === null ? replacement : { ...policy, ...replacement });
      expectCode('SCHEMA_INVALID', () =>
        verifyPreparedBundle({
          bundleDir: state.bundle,
          trustStorePath: state.trustStorePath,
        }),
      );
    });
  }
});

describe('offline mutation-report-set-v2 bundle verification', () => {
  it('reverifies a prepared v2 mutation bundle without Git, network, or a candidate checkout', () => {
    const state = mutationBundleFixture();
    const { verified } = verifyPreparedBundle({
      bundleDir: state.bundle,
      trustStorePath: state.trustStorePath,
    });
    assert.equal(verified.ok, true);
    assert.deepEqual(verified.verifiedMutation, [
      {
        nodeId: 'test:mutation',
        packageCount: 1,
        score: 100,
        statusTotals: state.set.statusTotals,
        evidenceSetDigest: state.set.summary.aggregate.evidenceSetDigest,
      },
    ]);
  });

  it('rejects a fully resealed bundle whose evidence set digest no longer binds its references', () => {
    const state = mutationBundleFixture();
    state.set.summary.aggregate.evidenceSetDigest = '0'.repeat(64);
    state.seal();
    expectCode('ARTIFACT_DIGEST_MISMATCH', () =>
      verifyPreparedBundle({
        bundleDir: state.bundle,
        trustStorePath: state.trustStorePath,
      }),
    );
  });

  it('rejects a fully resealed bundle whose evidence reference leaves the package roster', () => {
    const state = mutationBundleFixture();
    const entry = state.set.summary.packages[0];
    entry.evidenceRef.workspace = 'packages/elsewhere';
    entry.workspace = 'packages/elsewhere';
    entry.evidenceRefDigest = sha256Hex(entry.evidenceRef);
    state.set.summary.aggregate.evidenceSetDigest = sha256Hex([entry.evidenceRefDigest]);
    state.seal();
    expectCode('MUTATION_ROSTER_MISMATCH', () =>
      verifyPreparedBundle({
        bundleDir: state.bundle,
        trustStorePath: state.trustStorePath,
      }),
    );
  });
});

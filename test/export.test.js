import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { canonicalize, sha256Hex } from '../src/canonical.js';
import { exportCandidateEvidence, preflightCandidateEvidence } from '../src/export.js';
import { buildExpectedTaskPolicy } from '../src/policy-builder.js';
import { loadAndVerify } from '../src/verify.js';

const EXPORT_CLI = resolve(import.meta.dirname, '../src/export-cli.js');
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

function put(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

function expectCode(code, action) {
  assert.throws(action, (error) => error?.code === code);
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

function fixture({
  allowlistedEnv = [],
  environmentValue = {},
  portable = false,
  artifactContent = '{"proof":true}\n',
  mutation = false,
  patchMutationSummary,
} = {}) {
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
        allowlistedEnv,
        outputContract: mutation
          ? mutationV2Artifacts('0'.repeat(40), '0'.repeat(40)).contract
          : portable
            ? {
                kind: 'files',
                paths: ['generated.json'],
                requiredResult: 'pass',
              }
            : { kind: 'node-test', requiredResult: 'pass' },
      },
    ],
    profiles: [{ profileId: 'rc', mode: 'fixed', requiredNodes: ['test:one'] }],
  };
  put(join(repo, 'input.txt'), 'input\n');
  if (portable) put(join(repo, 'generated.json'), artifactContent);
  // Mutation evidence is generated, not committed, so the candidate stays clean and the
  // summary can bind the exact candidate commit and tree without referring to itself.
  if (mutation) put(join(repo, '.gitignore'), 'mutation/\n');
  put(join(repo, 'test-tasks.json'), `${JSON.stringify(descriptor, null, 2)}\n`);
  git(repo, ['add', '-A']);
  git(repo, ['commit', '--quiet', '-m', 'candidate']);
  const commit = git(repo, ['rev-parse', 'HEAD']);
  const tree = git(repo, ['rev-parse', 'HEAD^{tree}']);
  const mutationSet = mutation ? mutationV2Artifacts(commit, tree) : undefined;
  if (mutationSet !== undefined) {
    patchMutationSummary?.(mutationSet.summary);
    for (const [path, value] of Object.entries(mutationSet.files)) {
      put(join(repo, path), `${canonicalize(value)}\n`);
    }
  }
  const toolchain = join(root, 'toolchain.json');
  const environment = join(root, 'environment.json');
  put(toolchain, '{"node":"v24.5.0"}\n');
  put(environment, `${JSON.stringify(environmentValue)}\n`);
  const built = buildExpectedTaskPolicy({
    repo,
    descriptor,
    profileId: 'rc',
    candidateCommit: commit,
    expectedTree: tree,
    toolchain: { node: 'v24.5.0' },
    environment: environmentValue,
    policySchemaVersion: portable || mutation ? '1.1.0' : '1.0.0',
  });
  const result = {
    schemaVersion: '1.0.0',
    nodeId: 'test:one',
    taskKey: built.taskPolicy.requiredNodes[0].taskKey,
    status: 'PASS',
    inputDigest: '1'.repeat(64),
    dependencyResultDigests: {},
    outputDigests: {
      stdout: '2'.repeat(64),
      ...((portable || mutation) && { stderr: '3'.repeat(64) }),
      ...(portable && {
        'generated.json': sha256Hex(readFileSync(join(repo, 'generated.json'))),
      }),
      ...(mutationSet !== undefined &&
        Object.fromEntries(
          Object.keys(mutationSet.files).map((path) => [
            path,
            sha256Hex(readFileSync(join(repo, path))),
          ]),
        )),
    },
    startedAt: '2026-08-10T00:00:00.000Z',
    finishedAt: '2026-08-10T00:00:01.000Z',
  };
  const resultDigest = sha256Hex(result);
  const resultsDir = join(root, 'runner-results');
  mkdirSync(resultsDir);
  put(join(resultsDir, `${resultDigest}.json`), canonicalize(result));
  const receipt = {
    schemaVersion: portable || mutation ? '1.1.0' : '1.0.0',
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
  const trustStorePath = join(root, 'trust-store.json');
  put(privateKeyPath, keys.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  put(publicKeyPath, keys.publicKey.export({ type: 'spki', format: 'pem' }));
  put(
    trustStorePath,
    canonicalize({
      schemaVersion: '1.0.0',
      trustedSigners: [
        {
          signerId: 'local-rc-signer',
          publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        },
      ],
      revokedSignerIds: [],
    }),
  );
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
    trustStorePath,
    outputDir: join(root, 'exported'),
    built,
    mutationSet,
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

/**
 * A private key path that cannot be read at all. Any attempt to load, parse, derive
 * from, or sign with it fails, so a preflight that succeeds against this sentinel
 * proves the private key was never accessed.
 */
function absentPrivateKey(state) {
  return join(state.root, 'never-created-private.pem');
}

/**
 * A private key file that exists but holds no key. Reaching the signing step with it
 * throws, so the code a failing export reports tells us whether verification ran first.
 */
function invalidPrivateKey(state) {
  const path = join(state.root, 'invalid-private.pem');
  put(path, 'not a private key\n');
  return path;
}

/**
 * A preload that makes every private-key and signing primitive throw. An export run
 * against it exits 70 with FORBIDDEN_CRYPTO_OPERATION the moment it touches one, so any
 * other reported code proves the failure happened before the protected key was used.
 */
function cryptoTripwire(state) {
  const path = join(state.root, 'crypto-tripwire.cjs');
  put(
    path,
    [
      "const crypto = require('node:crypto');",
      "const { syncBuiltinESMExports } = require('node:module');",
      "for (const name of ['createPrivateKey', 'generateKeyPairSync', 'sign']) {",
      '  crypto[name] = () => { throw new Error(`FORBIDDEN_CRYPTO_OPERATION:${name}`); };',
      '}',
      'syncBuiltinESMExports();',
      '',
    ].join('\n'),
  );
  return path;
}

function exportCliArguments(state) {
  return [
    '--repo',
    state.repo,
    '--receipt',
    state.receiptPath,
    '--results-dir',
    state.resultsDir,
    '--profile',
    'rc',
    '--commit',
    state.commit,
    '--tree',
    state.tree,
    '--toolchain',
    state.toolchain,
    '--environment',
    state.environment,
    '--public-key',
    state.publicKeyPath,
    '--signer-id',
    'local-rc-signer',
    '--output-dir',
    state.outputDir,
  ];
}

describe('trusted candidate evidence export', () => {
  it('validates the complete export chain without writing an evidence bundle', () => {
    const state = fixture({ portable: true });
    const result = preflightCandidateEvidence(exportOptions(state));
    assert.equal(result.artifactPaths.length, 1);
    assert.equal(existsSync(state.outputDir), false);
  });

  it('runs the full verification semantics in preflight without touching the private key', () => {
    for (const privateKeyPath of [absentPrivateKey, invalidPrivateKey]) {
      const state = fixture({ portable: true });
      const options = {
        ...exportOptions(state),
        privateKeyPath: privateKeyPath(state),
      };
      const preflight = preflightCandidateEvidence(options);

      assert.equal(preflight.verified.ok, true);
      assert.deepEqual(preflight.verified.verifiedNodes, ['test:one']);
      // Preflight verifies receipt semantics without manufacturing or authenticating a
      // signature, so it must not claim that the configured signer was verified.
      assert.equal(Object.hasOwn(preflight.verified, 'signerId'), false);
      assert.deepEqual(preflight.verified.verifiedArtifacts, preflight.artifactPaths);
      assert.deepEqual(preflight.verified.verifiedMutation, []);
      assert.equal(existsSync(state.outputDir), false);

      // The very same options fail as soon as the export path reaches the key, which
      // is what makes the successful preflight above evidence of non-access.
      assert.throws(() => exportCandidateEvidence(options));
      assert.equal(existsSync(state.outputDir), false);
    }

    const missing = fixture();
    expectCode('INPUT_MISSING', () =>
      exportCandidateEvidence({
        ...exportOptions(missing),
        privateKeyPath: absentPrivateKey(missing),
      }),
    );
  });

  it('preflights the omitted private key the export CLI leaves out entirely', () => {
    const state = fixture({ portable: true });
    const options = { ...exportOptions(state), privateKeyPath: undefined };
    assert.equal(preflightCandidateEvidence(options).verified.ok, true);
    assert.equal(existsSync(state.outputDir), false);
    expectCode('SCHEMA_INVALID', () => exportCandidateEvidence(options));
    assert.equal(existsSync(state.outputDir), false);
  });

  it('runs CLI preflight with signing and private-key crypto operations disabled', () => {
    const state = fixture({ portable: true });
    const tripwire = cryptoTripwire(state);
    const common = exportCliArguments(state);
    const preflight = spawnSync(
      process.execPath,
      ['--require', tripwire, EXPORT_CLI, ...common, '--preflight', 'true'],
      { encoding: 'utf8' },
    );
    assert.equal(preflight.status, 0, preflight.stderr);
    assert.equal(JSON.parse(preflight.stdout).preflight, true);
    assert.equal(existsSync(state.outputDir), false);

    const signing = spawnSync(
      process.execPath,
      ['--require', tripwire, EXPORT_CLI, ...common, '--private-key', state.privateKeyPath],
      { encoding: 'utf8' },
    );
    assert.equal(signing.status, 70);
    assert.match(JSON.parse(signing.stderr).message, /FORBIDDEN_CRYPTO_OPERATION/u);
    assert.equal(existsSync(state.outputDir), false);
  });

  it('refuses a symlinked task result in preflight and before any signing operation', () => {
    const state = fixture();
    const receipt = JSON.parse(readFileSync(state.receiptPath, 'utf8'));
    const resultPath = join(state.resultsDir, `${receipt.tasks[0].resultDigest}.json`);
    // The link target keeps the exact bytes the receipt digest commits to, so the only
    // thing left for the verifier to refuse is the symbolic link itself.
    const external = join(state.root, 'external-result.json');
    renameSync(resultPath, external);
    symlinkSync(external, resultPath);

    assert.throws(
      () => preflightCandidateEvidence(exportOptions(state)),
      (error) =>
        error.code === 'RESULT_INVALID' &&
        error.message === 'task result test:one must be a regular non-symlink file',
    );
    assert.equal(existsSync(state.outputDir), false);

    const tripwire = cryptoTripwire(state);
    const common = exportCliArguments(state);
    const preflight = spawnSync(
      process.execPath,
      ['--require', tripwire, EXPORT_CLI, ...common, '--preflight', 'true'],
      { encoding: 'utf8' },
    );
    assert.equal(preflight.status, 2);
    assert.equal(preflight.stdout, '');
    assert.equal(JSON.parse(preflight.stderr).code, 'RESULT_INVALID');
    assert.equal(existsSync(state.outputDir), false);

    // A signing export refuses the same result with the same code: had it reached the
    // private key or the signature, the tripwire would have exited 70 instead.
    const signing = spawnSync(
      process.execPath,
      ['--require', tripwire, EXPORT_CLI, ...common, '--private-key', state.privateKeyPath],
      { encoding: 'utf8' },
    );
    assert.equal(signing.status, 2);
    assert.equal(signing.stdout, '');
    assert.equal(JSON.parse(signing.stderr).code, 'RESULT_INVALID');
    assert.equal(existsSync(state.outputDir), false);
  });

  it('rejects stale result digests and legacy mutation evidence before any signing', () => {
    const stale = fixture({ portable: true });
    const receipt = JSON.parse(readFileSync(stale.receiptPath, 'utf8'));
    const resultPath = join(stale.resultsDir, `${receipt.tasks[0].resultDigest}.json`);
    const taskResult = JSON.parse(readFileSync(resultPath, 'utf8'));
    taskResult.finishedAt = '2026-08-10T00:00:09.000Z';
    put(resultPath, canonicalize(taskResult));
    expectCode('RESULT_DIGEST_MISMATCH', () =>
      exportCandidateEvidence({
        ...exportOptions(stale),
        privateKeyPath: absentPrivateKey(stale),
      }),
    );
    assert.equal(existsSync(stale.outputDir), false);

    const malformed = fixture({
      mutation: true,
      patchMutationSummary: (summary) => delete summary.aggregate.reusedDurationMs,
    });
    expectCode('MUTATION_VERSION_UNSUPPORTED', () =>
      exportCandidateEvidence({
        ...exportOptions(malformed),
        privateKeyPath: absentPrivateKey(malformed),
      }),
    );
    assert.equal(existsSync(malformed.outputDir), false);
  });

  it('fails a missing output parent with a stable preflight code before signing or execution', () => {
    const state = fixture();
    const missingParent = join(state.root, 'missing', 'evidence');
    expectCode('OUTPUT_PARENT_MISSING', () =>
      preflightCandidateEvidence({
        ...exportOptions(state),
        outputDir: missingParent,
      }),
    );
    assert.equal(existsSync(missingParent), false);
  });

  it('independently rebuilds policy, signs, exports only required results, and verifies', () => {
    const state = fixture();
    const result = exportCandidateEvidence(exportOptions(state));
    assert.deepEqual(result.verifiedNodes, ['test:one']);
    assert.equal(result.taskPolicyDigest, state.built.taskPolicyDigest);
    const verified = loadAndVerify({
      envelopePath: join(state.outputDir, 'envelope.json'),
      resultsDir: join(state.outputDir, 'results'),
      taskPolicyPath: join(state.outputDir, 'task-policy.json'),
      trustStorePath: state.trustStorePath,
      expectedRepository: 'fixture/repository',
      expectedCommit: state.commit,
      expectedTree: state.tree,
      expectedPolicyDigest: state.built.taskPolicyDigest,
    });
    assert.equal(verified.ok, true);
    assert.match(readFileSync(join(state.outputDir, 'manifest.json'), 'utf8'), /local-rc-signer/u);
  });

  it('exports distinct policies for absent and explicitly empty allowlisted environment values', () => {
    const absent = fixture({
      allowlistedEnv: ['CI'],
      environmentValue: { CI: null },
    });
    const empty = fixture({
      allowlistedEnv: ['CI'],
      environmentValue: { CI: '' },
    });

    const absentResult = exportCandidateEvidence(exportOptions(absent));
    const emptyResult = exportCandidateEvidence(exportOptions(empty));

    assert.equal(absentResult.taskPolicyDigest, absent.built.taskPolicyDigest);
    assert.equal(emptyResult.taskPolicyDigest, empty.built.taskPolicyDigest);
    assert.notEqual(absentResult.taskPolicyDigest, emptyResult.taskPolicyDigest);
  });

  it('exports and independently verifies exactly the declared schema 1.1 artifacts', () => {
    const state = fixture({ portable: true });
    const result = exportCandidateEvidence(exportOptions(state));
    assert.equal(result.ok, true);
    assert.equal(existsSync(join(state.outputDir, 'trust-store.json')), false);
    assert.equal(
      readFileSync(join(state.outputDir, 'artifacts/generated.json'), 'utf8'),
      '{"proof":true}\n',
    );
    const manifest = JSON.parse(readFileSync(join(state.outputDir, 'manifest.json'), 'utf8'));
    assert.deepEqual(manifest.artifacts, [
      {
        path: 'generated.json',
        mediaType: 'application/json',
        sha256: sha256Hex(readFileSync(join(state.repo, 'generated.json'))),
      },
    ]);
    const verified = loadAndVerify({
      envelopePath: join(state.outputDir, 'envelope.json'),
      resultsDir: join(state.outputDir, 'results'),
      artifactsDir: join(state.outputDir, 'artifacts'),
      taskPolicyPath: join(state.outputDir, 'task-policy.json'),
      trustStorePath: state.trustStorePath,
      expectedRepository: 'fixture/repository',
      expectedCommit: state.commit,
      expectedTree: state.tree,
      expectedPolicyDigest: state.built.taskPolicyDigest,
    });
    assert.deepEqual(verified.verifiedArtifacts, ['generated.json']);

    put(join(state.outputDir, 'artifacts/generated.json'), '{"proof":false}\n');
    expectCode('ARTIFACT_DIGEST_MISMATCH', () =>
      loadAndVerify({
        envelopePath: join(state.outputDir, 'envelope.json'),
        resultsDir: join(state.outputDir, 'results'),
        artifactsDir: join(state.outputDir, 'artifacts'),
        taskPolicyPath: join(state.outputDir, 'task-policy.json'),
        trustStorePath: state.trustStorePath,
        expectedRepository: 'fixture/repository',
        expectedCommit: state.commit,
        expectedTree: state.tree,
        expectedPolicyDigest: state.built.taskPolicyDigest,
      }),
    );
  });

  it('atomically refuses credential-shaped material and workstation paths', () => {
    for (const [code, value] of [
      ['ARTIFACT_CREDENTIAL_MATERIAL', `gho_${'a'.repeat(36)}`],
      ['ARTIFACT_HOST_PATH', '/Users/inspector/stynx/report.json'],
    ]) {
      const state = fixture({
        portable: true,
        artifactContent: `${JSON.stringify({ value })}\n`,
      });
      expectCode(code, () => exportCandidateEvidence(exportOptions(state)));
      assert.equal(existsSync(state.outputDir), false);
    }
  });

  it('keeps draft mutation-report-set-v2 evidence read-only at preflight and export', () => {
    const preflighted = fixture({ mutation: true });
    expectCode('MUTATION_VERSION_UNSUPPORTED', () =>
      preflightCandidateEvidence(exportOptions(preflighted)),
    );
    assert.equal(existsSync(preflighted.outputDir), false);

    const state = fixture({ mutation: true });
    expectCode('MUTATION_VERSION_UNSUPPORTED', () => exportCandidateEvidence(exportOptions(state)));
    assert.equal(existsSync(state.outputDir), false);
  });

  it('refuses legacy mutation artifacts before opening or signing them', () => {
    const state = fixture({
      mutation: true,
      patchMutationSummary: (summary) => {
        summary.baseline.summarySha256 = '/Users/inspector/stynx/mutation/summary.json';
      },
    });
    expectCode('MUTATION_VERSION_UNSUPPORTED', () =>
      preflightCandidateEvidence(exportOptions(state)),
    );
    assert.equal(existsSync(state.outputDir), false);
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

// ADR-REL-0031: the release-intent export path.
//
// A release run selects its nodes by capability from a pinned release intent and a
// release verification profile, and writes a certify receipt whose task policy is the
// release form (schema 1.2.0 with an inputProjection). The exporter must reconstruct
// that policy from the pins the release preflight receipt carries, never from the task
// set the receipt claims, and refuse every drift with its own code.

const INTENT_SENTINEL = 'export-ran-a-task';
const PREFLIGHT_CAPABILITIES = [
  'formatting-hygiene',
  'lint',
  'type-integrity',
  'schema-consistency',
  'secret-scan',
  'path-portability',
  'package-integrity',
  'exact-candidate',
];
// A stable patch (1.0.0 -> 1.0.1, support current) selects the preflight floor plus these.
const CERTIFY_ONLY_CAPABILITIES = ['affected-checks', 'dependent-checks', 'build-integrity'];
const RELEASE_INPUT_PROJECTION = {
  schemaVersion: '1.0.0',
  source: 'exact-candidate-tree',
  excludedPrefixes: ['.devai/state/', 'record/', 'scratch/'],
};
const INTENT_TOOLCHAIN = { node: 'v24.5.0' };

function intentTask(nodeId, dependencies, inputSelectors) {
  return {
    nodeId,
    dependencies,
    // Executing this task would leave a sentinel beside the candidate. The exporter
    // must never execute a task, so the sentinel's absence proves no second run.
    argv: ['node', '-e', `require('node:fs').writeFileSync('../${INTENT_SENTINEL}', '${nodeId}')`],
    cwd: '.',
    runner: 'node-test-v1',
    inputSelectors,
    toolchainKeys: ['node'],
    allowlistedEnv: [],
    outputContract: { kind: 'node-test', requiredResult: 'pass' },
  };
}

function intentDescriptor() {
  return {
    schemaVersion: '1.0.0',
    descriptorVersion: 'intent-fixture-1',
    repositoryId: 'fixture/repository',
    fallbackNodeId: null,
    dynamicFallbackSelectors: [],
    tasks: [
      intentTask(
        'prepare',
        [],
        [
          { kind: 'exact', pattern: 'package.json' },
          { kind: 'exact', pattern: 'test-tasks.json' },
        ],
      ),
      intentTask('unit', ['prepare'], [{ kind: 'prefix', pattern: 'src/' }]),
      intentTask('docs', [], [{ kind: 'prefix', pattern: 'docs/' }]),
    ],
    profiles: [
      {
        profileId: 'affected',
        mode: 'affected',
        requiredNodes: ['prepare'],
        eligibleNodes: ['prepare', 'unit', 'docs'],
      },
      // Fixed profiles whose node sets equal the certify and preflight selections. They
      // are the independent oracle below and are never named on the intent path.
      { profileId: 'rc', mode: 'fixed', requiredNodes: ['prepare', 'unit'] },
      { profileId: 'preflight-floor', mode: 'fixed', requiredNodes: ['prepare'] },
    ],
  };
}

function intentReleaseProfile() {
  return {
    schemaVersion: '1.0.0',
    policy_id: 'fixture.release',
    policy_version: '1.0.0',
    release_unit: 'fixture/repository',
    version_source: 'package.json',
    default_support: 'current',
    capability_tasks: {
      ...Object.fromEntries(PREFLIGHT_CAPABILITIES.map((capability) => [capability, ['prepare']])),
      ...Object.fromEntries(CERTIFY_ONLY_CAPABILITIES.map((capability) => [capability, ['unit']])),
    },
    risk_capabilities: {},
    mutation_roster: [],
  };
}

function gitIdentity(repo, revision) {
  return {
    commit: git(repo, ['rev-parse', revision]),
    tree: git(repo, ['rev-parse', `${revision}^{tree}`]),
  };
}

function commitAll(repo, message) {
  git(repo, ['add', '-A']);
  git(repo, ['commit', '--quiet', '-m', message]);
  return gitIdentity(repo, 'HEAD');
}

/** SHA-256 of the exact candidate tree outside the harness-mutated prefixes. */
function inputProjectionDigest(repo, commit) {
  const output = execFileSync('git', ['-C', repo, 'ls-tree', '-r', '-z', '--full-tree', commit]);
  const entries = [];
  for (const record of output.toString('utf8').split('\0')) {
    if (record === '') continue;
    const [, mode, type, objectId, path] = /^(\d+) ([a-z]+) ([0-9a-f]+)\t(.+)$/u.exec(record);
    if (RELEASE_INPUT_PROJECTION.excludedPrefixes.some((prefix) => path.startsWith(prefix))) {
      continue;
    }
    const content = execFileSync('git', ['-C', repo, 'cat-file', 'blob', objectId]);
    entries.push({ path, mode, type, contentDigest: sha256Hex(content) });
  }
  entries.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  return sha256Hex(entries);
}

/**
 * The release task policy the run would have pinned, computed without the intent path:
 * with no mutation binding, protected executable identity, or preflight probe node
 * selected, a release task key is the fixed-profile task key, so the release form is the
 * schema 1.1 policy of the same node set, re-versioned to 1.2.0 with the input projection.
 */
function releaseOracle(state, profileId) {
  const built = buildExpectedTaskPolicy({
    repo: state.repo,
    descriptor: intentDescriptor(),
    profileId,
    candidateCommit: state.candidate.commit,
    expectedTree: state.candidate.tree,
    toolchain: INTENT_TOOLCHAIN,
    environment: {},
    policySchemaVersion: '1.1.0',
  });
  const taskPolicy = {
    ...built.taskPolicy,
    schemaVersion: '1.2.0',
    inputProjection: {
      ...RELEASE_INPUT_PROJECTION,
      digest: inputProjectionDigest(state.repo, state.candidate.commit),
    },
  };
  return { taskPolicy, taskPolicyDigest: sha256Hex(taskPolicy) };
}

function intentResult(state, node, dependencyDigests) {
  const result = {
    schemaVersion: '1.0.0',
    nodeId: node.nodeId,
    taskKey: node.taskKey,
    status: 'PASS',
    inputDigest: '1'.repeat(64),
    dependencyResultDigests: Object.fromEntries(
      node.dependencies.map((dependency) => [dependency, dependencyDigests[dependency]]),
    ),
    outputDigests: { stdout: '2'.repeat(64), stderr: '3'.repeat(64) },
    startedAt: '2026-10-01T00:00:00.000Z',
    finishedAt: '2026-10-01T00:00:01.000Z',
  };
  const digest = sha256Hex(result);
  put(join(state.resultsDir, `${digest}.json`), canonicalize(result));
  return digest;
}

function writeIntentInputs(state, { repin = false } = {}) {
  if (repin) {
    state.preflight.releaseIntentDigest = sha256Hex(state.intent);
    state.preflight.releaseProfileDigest = sha256Hex(state.releaseProfile);
  }
  // The intent and the profile are written pretty-printed, not canonically: their pins are
  // digests of canonical JSON, so formatting never changes an export's result.
  put(state.paths.intent, `${JSON.stringify(state.intent, null, 2)}\n`);
  put(state.paths.releaseProfile, `${JSON.stringify(state.releaseProfile, null, 2)}\n`);
  put(state.paths.preflightReceipt, canonicalize(state.preflight));
  put(state.paths.receipt, canonicalize(state.receipt));
}

function intentFixture() {
  const root = mkdtempSync(join(tmpdir(), 'devai-export-intent-'));
  temporaryDirectories.push(root);
  const repo = join(root, 'candidate');
  mkdirSync(repo);
  git(repo, ['init', '--quiet', '-b', 'main']);
  git(repo, ['config', 'user.name', 'Verifier Test']);
  git(repo, ['config', 'user.email', 'verifier@example.invalid']);
  put(join(repo, '.gitignore'), '.devai/state/\n');
  put(join(repo, 'docs/notes.md'), '# Notes\n');
  const genesis = commitAll(repo, 'genesis');
  put(join(repo, 'package.json'), '{"name":"fixture","version":"1.0.0"}\n');
  put(join(repo, 'src/a.js'), 'export const value = 1;\n');
  put(join(repo, 'test-tasks.json'), `${JSON.stringify(intentDescriptor(), null, 2)}\n`);
  const base = commitAll(repo, 'base');
  put(join(repo, 'package.json'), '{"name":"fixture","version":"1.0.1"}\n');
  put(join(repo, 'src/a.js'), 'export const value = 2;\n');
  const candidate = commitAll(repo, 'candidate');

  const state = {
    root,
    repo,
    genesis,
    base,
    candidate,
    resultsDir: join(root, 'runner-results'),
    outputDir: join(root, 'exported'),
    paths: {
      intent: join(root, 'release-intent.json'),
      releaseProfile: join(root, 'release-profile.json'),
      preflightReceipt: join(root, 'release-preflight-receipt.json'),
      receipt: join(root, 'candidate-receipt.json'),
      toolchain: join(root, 'toolchain.json'),
      environment: join(root, 'environment.json'),
      privateKey: join(root, 'private.pem'),
      publicKey: join(root, 'public.pem'),
      trustStore: join(root, 'trust-store.json'),
    },
  };
  mkdirSync(state.resultsDir);
  put(state.paths.toolchain, `${JSON.stringify(INTENT_TOOLCHAIN)}\n`);
  put(state.paths.environment, '{}\n');
  const keys = generateKeyPairSync('ed25519');
  put(state.paths.privateKey, keys.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  put(state.paths.publicKey, keys.publicKey.export({ type: 'spki', format: 'pem' }));
  put(
    state.paths.trustStore,
    canonicalize({
      schemaVersion: '1.0.0',
      trustedSigners: [
        {
          signerId: 'local-rc-signer',
          publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        },
      ],
      revokedSignerIds: [],
    }),
  );

  state.oracle = {
    certify: releaseOracle(state, 'rc'),
    preflight: releaseOracle(state, 'preflight-floor'),
  };
  const digests = {};
  const nodes = state.oracle.certify.taskPolicy.requiredNodes;
  for (const node of nodes) digests[node.nodeId] = intentResult(state, node, digests);
  state.resultDigests = digests;

  state.intent = {
    schemaVersion: '1.0.0',
    release_unit: 'fixture/repository',
    current_version: '1.0.0',
    target_version: '1.0.1',
    support: 'current',
    changed_paths: ['package.json', 'src/a.js'],
    changed_packages: [],
    candidate: { ...candidate },
    base: { ...base },
  };
  state.releaseProfile = intentReleaseProfile();
  state.preflight = {
    schemaVersion: '1.0.0',
    repository: { id: 'fixture/repository', ...candidate },
    base: { ...base },
    releaseIntentDigest: sha256Hex(state.intent),
    releaseProfileDigest: sha256Hex(state.releaseProfile),
    taskPolicyDigest: state.oracle.preflight.taskPolicyDigest,
    toolchainDigest: sha256Hex(INTENT_TOOLCHAIN),
    checks: PREFLIGHT_CAPABILITIES.map((capability) => ({
      capability,
      status: 'executed',
      reasonCode: 'capability-selected',
      resultDigest: digests.prepare,
    })),
    verdict: 'pass',
    blockingReasons: [],
    createdAt: '2026-10-01T00:00:02.000Z',
  };
  state.receipt = {
    schemaVersion: '1.1.0',
    repository: { id: 'fixture/repository', ...candidate },
    profile: 'rc',
    taskPolicyDigest: state.oracle.certify.taskPolicyDigest,
    createdAt: '2026-10-01T00:00:03.000Z',
    tasks: nodes.map((node) => ({
      nodeId: node.nodeId,
      taskKey: node.taskKey,
      resultDigest: digests[node.nodeId],
    })),
  };
  writeIntentInputs(state);
  return state;
}

function intentCliArguments(state, overrides = {}) {
  const values = {
    repo: state.repo,
    receipt: state.paths.receipt,
    'results-dir': state.resultsDir,
    'release-intent': state.paths.intent,
    'release-profile': state.paths.releaseProfile,
    'release-stage': 'certify',
    'preflight-receipt': state.paths.preflightReceipt,
    base: state.base.commit,
    commit: state.candidate.commit,
    tree: state.candidate.tree,
    toolchain: state.paths.toolchain,
    environment: state.paths.environment,
    'private-key': state.paths.privateKey,
    'public-key': state.paths.publicKey,
    'signer-id': 'local-rc-signer',
    'output-dir': state.outputDir,
    ...overrides,
  };
  return Object.entries(values)
    .filter(([, value]) => value !== undefined)
    .flatMap(([name, value]) => [`--${name}`, value]);
}

function runIntentExport(state, overrides = {}) {
  return spawnSync(process.execPath, [EXPORT_CLI, ...intentCliArguments(state, overrides)], {
    cwd: state.root,
    encoding: 'utf8',
  });
}

function assertNothingExported(state) {
  assert.equal(existsSync(state.outputDir), false);
  assert.deepEqual(
    readdirSync(state.root).filter((name) => name.startsWith('.devai-evidence-export-')),
    [],
  );
  assert.equal(existsSync(join(state.root, INTENT_SENTINEL)), false);
}

function assertIntentRefusal(state, code, overrides = {}) {
  const run = runIntentExport(state, overrides);
  assert.equal(run.stdout, '', `${code}: no result line on refusal`);
  assert.notEqual(run.stderr, '', `${code}: a coded refusal line is required`);
  const refusal = JSON.parse(run.stderr);
  assert.equal(refusal.ok, false);
  assert.equal(refusal.code, code, `expected ${code}, got ${run.stderr}`);
  assert.equal(run.status, code === 'USAGE' ? 64 : 2);
  assertNothingExported(state);
  return refusal;
}

describe('release-intent certify export (ADR-REL-0031)', () => {
  it('exports the certify receipt of a release-intent run without executing any task (IA-001)', () => {
    const state = intentFixture();
    const resultsBefore = readdirSync(state.resultsDir).sort();
    const run = runIntentExport(state);
    assert.equal(run.status, 0, run.stderr);
    const result = JSON.parse(run.stdout);
    assert.equal(result.ok, true);
    // The digest the run pinned in its certify receipt is the digest the exporter
    // reconstructs, and both equal the independent oracle.
    assert.equal(result.taskPolicyDigest, state.receipt.taskPolicyDigest);
    assert.equal(result.taskPolicyDigest, state.oracle.certify.taskPolicyDigest);
    assert.notEqual(result.taskPolicyDigest, state.oracle.preflight.taskPolicyDigest);
    assert.deepEqual(result.verifiedNodes, ['prepare', 'unit']);
    const exportedPolicy = JSON.parse(
      readFileSync(join(state.outputDir, 'task-policy.json'), 'utf8'),
    );
    assert.deepEqual(exportedPolicy, state.oracle.certify.taskPolicy);
    assert.equal(exportedPolicy.schemaVersion, '1.2.0');
    const verified = loadAndVerify({
      envelopePath: join(state.outputDir, 'envelope.json'),
      resultsDir: join(state.outputDir, 'results'),
      taskPolicyPath: join(state.outputDir, 'task-policy.json'),
      trustStorePath: state.paths.trustStore,
      expectedRepository: 'fixture/repository',
      expectedCommit: state.candidate.commit,
      expectedTree: state.candidate.tree,
      expectedPolicyDigest: state.oracle.certify.taskPolicyDigest,
    });
    assert.equal(verified.ok, true);
    assert.deepEqual(readdirSync(join(state.outputDir, 'results')).sort(), resultsBefore);
    // No task ran during export: no sentinel, no new result, a clean candidate.
    assert.equal(existsSync(join(state.root, INTENT_SENTINEL)), false);
    assert.deepEqual(readdirSync(state.resultsDir).sort(), resultsBefore);
    assert.equal(git(state.repo, ['status', '--porcelain=v1', '--untracked-files=all']), '');

    // The reconstruction is deterministic: a second export of the same pins is identical.
    const again = runIntentExport(state, { 'output-dir': join(state.root, 'exported-again') });
    assert.equal(again.status, 0, again.stderr);
    assert.equal(JSON.parse(again.stdout).taskPolicyDigest, result.taskPolicyDigest);
    assert.equal(
      readFileSync(join(state.root, 'exported-again', 'task-policy.json'), 'utf8'),
      readFileSync(join(state.outputDir, 'task-policy.json'), 'utf8'),
    );
  });

  it('refuses an intent altered after the run instead of trusting the receipt (IA-002)', () => {
    for (const alter of [
      (intent) => {
        intent.changed_packages = ['@fixture/extra'];
      },
      (intent) => {
        intent.support = 'lts';
      },
      (intent) => {
        intent.target_version = '1.0.2';
      },
    ]) {
      const state = intentFixture();
      alter(state.intent);
      writeIntentInputs(state);
      assertIntentRefusal(state, 'INTENT_DIGEST_MISMATCH');
    }
  });

  it('refuses an intent whose reconstructed release decision is not ready (IA-002)', () => {
    const state = intentFixture();
    // A stable target on the beta channel blocks the decision; the preflight pin is moved
    // with it so that nothing but the decision itself is wrong.
    state.intent.channel = 'beta';
    writeIntentInputs(state, { repin: true });
    const refusal = assertIntentRefusal(state, 'INTENT_DECISION_BLOCKED');
    assert.match(refusal.message, /channel-mismatch/u);
  });

  it('refuses a stage other than certify and a preflight-stage receipt (IA-003)', () => {
    const wrongStage = intentFixture();
    assertIntentRefusal(wrongStage, 'INTENT_STAGE_MISMATCH', { 'release-stage': 'preflight' });

    const preflightAsReceipt = intentFixture();
    assertIntentRefusal(preflightAsReceipt, 'INTENT_STAGE_MISMATCH', {
      receipt: preflightAsReceipt.paths.preflightReceipt,
    });

    // A candidate receipt built for the preflight stage: its digest is the preflight-stage
    // reconstruction and its tasks are exactly the preflight population.
    const preflightPolicy = intentFixture();
    const prepare = preflightPolicy.oracle.preflight.taskPolicy.requiredNodes[0];
    preflightPolicy.receipt.taskPolicyDigest = preflightPolicy.oracle.preflight.taskPolicyDigest;
    preflightPolicy.receipt.tasks = [
      {
        nodeId: prepare.nodeId,
        taskKey: prepare.taskKey,
        resultDigest: preflightPolicy.resultDigests.prepare,
      },
    ];
    writeIntentInputs(preflightPolicy);
    assertIntentRefusal(preflightPolicy, 'INTENT_STAGE_MISMATCH');
  });

  it('refuses a stale release policy and a receipt built against another policy (IA-003)', () => {
    const edited = intentFixture();
    edited.releaseProfile.policy_version = '1.0.1';
    writeIntentInputs(edited);
    assertIntentRefusal(edited, 'INTENT_POLICY_STALE');

    const otherUnit = intentFixture();
    otherUnit.releaseProfile.release_unit = 'fixture/other';
    writeIntentInputs(otherUnit, { repin: true });
    assertIntentRefusal(otherUnit, 'INTENT_POLICY_STALE');

    const staleReceipt = intentFixture();
    staleReceipt.receipt.taskPolicyDigest = 'f'.repeat(64);
    writeIntentInputs(staleReceipt);
    assertIntentRefusal(staleReceipt, 'POLICY_DIGEST_MISMATCH');
  });

  it('refuses a base that is not the intent base (IA-004)', () => {
    const otherBase = intentFixture();
    assertIntentRefusal(otherBase, 'INTENT_BASE_MISMATCH', { base: otherBase.genesis.commit });

    const preflightBase = intentFixture();
    preflightBase.preflight.base = { ...preflightBase.genesis };
    writeIntentInputs(preflightBase);
    assertIntentRefusal(preflightBase, 'INTENT_BASE_MISMATCH');

    const unresolvedTree = intentFixture();
    unresolvedTree.intent.base = {
      commit: unresolvedTree.base.commit,
      tree: unresolvedTree.genesis.tree,
    };
    unresolvedTree.preflight.base = { ...unresolvedTree.intent.base };
    writeIntentInputs(unresolvedTree, { repin: true });
    assertIntentRefusal(unresolvedTree, 'INTENT_BASE_MISMATCH');
  });

  it('refuses a candidate that is not the intent candidate (IA-004)', () => {
    const preflightCandidate = intentFixture();
    preflightCandidate.preflight.repository = {
      id: 'fixture/repository',
      ...preflightCandidate.base,
    };
    writeIntentInputs(preflightCandidate);
    assertIntentRefusal(preflightCandidate, 'INTENT_CANDIDATE_MISMATCH');

    const intentCandidate = intentFixture();
    intentCandidate.intent.candidate = { ...intentCandidate.base };
    writeIntentInputs(intentCandidate, { repin: true });
    assertIntentRefusal(intentCandidate, 'INTENT_CANDIDATE_MISMATCH');

    const otherRepository = intentFixture();
    otherRepository.preflight.repository.id = 'fixture/other';
    writeIntentInputs(otherRepository);
    assertIntentRefusal(otherRepository, 'INTENT_CANDIDATE_MISMATCH');
  });

  it('refuses a node population that is not exactly the reconstruction (IA-004)', () => {
    const subset = intentFixture();
    subset.receipt.tasks = subset.receipt.tasks.filter((task) => task.nodeId !== 'unit');
    writeIntentInputs(subset);
    assertIntentRefusal(subset, 'INTENT_POPULATION_INCOMPLETE');

    const superset = intentFixture();
    const docs = { nodeId: 'docs', taskKey: 'd'.repeat(64), dependencies: [] };
    superset.receipt.tasks.push({
      nodeId: 'docs',
      taskKey: docs.taskKey,
      resultDigest: intentResult(superset, docs, {}),
    });
    writeIntentInputs(superset);
    assertIntentRefusal(superset, 'INTENT_POPULATION_INCOMPLETE');

    const staleKey = intentFixture();
    staleKey.receipt.tasks = staleKey.receipt.tasks.map((task) =>
      task.nodeId === 'unit' ? { ...task, taskKey: 'e'.repeat(64) } : task,
    );
    writeIntentInputs(staleKey);
    assertIntentRefusal(staleKey, 'INTENT_POPULATION_INCOMPLETE');
  });

  it('refuses a mixed or incomplete path selection as usage before reading inputs', () => {
    const state = intentFixture();
    assertIntentRefusal(state, 'USAGE', { profile: 'rc' });
    for (const omitted of [
      'release-intent',
      'release-profile',
      'release-stage',
      'preflight-receipt',
    ]) {
      assertIntentRefusal(state, 'USAGE', { [omitted]: undefined });
    }
    // Usage is decided before any input is read: an unreadable intent is still USAGE.
    assertIntentRefusal(state, 'USAGE', {
      profile: 'rc',
      'release-intent': join(state.root, 'missing-intent.json'),
    });
  });

  it('distinguishes a path passed as a profile id from an unknown id (IA-005)', () => {
    const state = fixture();
    const withProfile = (profile) =>
      exportCliArguments(state).map((value, index, all) =>
        all[index - 1] === '--profile' ? profile : value,
      );
    const refuse = (profile, code, cwd = state.root) => {
      const run = spawnSync(
        process.execPath,
        [EXPORT_CLI, ...withProfile(profile), '--private-key', state.privateKeyPath],
        { cwd, encoding: 'utf8' },
      );
      assert.equal(run.status, 2, run.stderr);
      assert.equal(run.stdout, '');
      assert.equal(JSON.parse(run.stderr).code, code, `${profile}: ${run.stderr}`);
      assert.equal(existsSync(state.outputDir), false);
    };
    refuse(state.receiptPath, 'PROFILE_ID_INVALID');
    refuse('profiles/rc', 'PROFILE_ID_INVALID');
    refuse('profiles\\rc', 'PROFILE_ID_INVALID');
    // A bare name that names a readable file in the working directory is a path too.
    refuse('receipt.json', 'PROFILE_ID_INVALID', state.root);
    refuse('not-declared', 'PROFILE_UNKNOWN');

    // The profile path is unchanged: the same profile-driven receipt still exports.
    const exported = spawnSync(
      process.execPath,
      [EXPORT_CLI, ...withProfile('rc'), '--private-key', state.privateKeyPath],
      { cwd: state.root, encoding: 'utf8' },
    );
    assert.equal(exported.status, 0, exported.stderr);
    const result = JSON.parse(exported.stdout);
    assert.equal(result.profile, 'rc');
    assert.equal(result.taskPolicyDigest, state.built.taskPolicyDigest);
    assert.deepEqual(
      JSON.parse(readFileSync(join(state.outputDir, 'task-policy.json'), 'utf8')),
      state.built.taskPolicy,
    );
  });
});

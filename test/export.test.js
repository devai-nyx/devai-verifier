import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
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
  return execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim();
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
    files: { 'src/core.ts': { language: 'typescript', mutants: [{ id: '0', status: 'Killed' }] } },
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
      sourceRootManifest: { bytes: 512, gitBlobOid: '1'.repeat(40), sha256: '2'.repeat(64) },
      targetRootManifest: { bytes: 512, gitBlobOid: '1'.repeat(40), sha256: '2'.repeat(64) },
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
    files: { [reportPath]: report, [resultPath]: packageResult, [summaryPath]: summary },
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
            ? { kind: 'files', paths: ['generated.json'], requiredResult: 'pass' }
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
      const options = { ...exportOptions(state), privateKeyPath: privateKeyPath(state) };
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
      preflightCandidateEvidence({ ...exportOptions(state), outputDir: missingParent }),
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
    const absent = fixture({ allowlistedEnv: ['CI'], environmentValue: { CI: null } });
    const empty = fixture({ allowlistedEnv: ['CI'], environmentValue: { CI: '' } });

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
    assert.equal(readFileSync(join(state.outputDir, 'artifacts/generated.json'), 'utf8'), '{"proof":true}\n');
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
    expectCode('MUTATION_VERSION_UNSUPPORTED', () => preflightCandidateEvidence(exportOptions(state)));
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

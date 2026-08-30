import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { canonicalize, sha256Hex } from '../src/canonical.js';
import { MUTANT_STATUSES, validateMutationContract, verifyMutationReportSet } from '../src/mutation.js';

const temporaryDirectories = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function put(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${canonicalize(value)}\n`);
}

function totals(overrides = {}) {
  return Object.fromEntries(MUTANT_STATUSES.map((status) => [status, overrides[status] ?? 0]));
}

function fixture() {
  const artifactsDir = mkdtempSync(join(tmpdir(), 'devai-mutation-proof-'));
  temporaryDirectories.push(artifactsDir);
  const packageContract = {
    packageName: '@stynx/core',
    workspace: 'packages/core',
    resultPath: 'mutation/packages-core.result.json',
    reportPath: 'mutation/packages-core.stryker.json',
    thresholds: { high: 95, low: 85, break: 50 },
  };
  const contract = {
    kind: 'mutation-report-set-v1',
    expectedPackageCount: 1,
    summaryPath: 'mutation/summary.json',
    packages: [packageContract],
    paths: [
      'mutation/summary.json',
      'mutation/packages-core.result.json',
      'mutation/packages-core.stryker.json',
    ],
  };
  const report = {
    schemaVersion: '1',
    projectRoot: '.',
    thresholds: packageContract.thresholds,
    files: {
      'src/core.ts': {
        language: 'typescript',
        mutants: [
          { id: '0', status: 'Killed', replacement: '/[a-z]+/u' },
          { id: '1', status: 'Survived' },
          { id: '2', status: 'CompileError' },
        ],
      },
    },
    testFiles: {},
    config: {},
    framework: { name: 'StrykerJS', branding: {} },
  };
  const reportBytes = Buffer.from(canonicalize(report));
  const result = {
    schemaVersion: '1.0.0',
    kind: 'mutation-package-result-v1',
    packageName: '@stynx/core',
    workspace: 'packages/core',
    passed: true,
    durationMs: 1234,
    toolVersions: { stryker: '9.1.1', vitestRunner: '3.2.4' },
    thresholds: packageContract.thresholds,
    score: 50,
    statusTotals: totals({ Killed: 1, Survived: 1, CompileError: 1 }),
    reportDigest: sha256Hex(reportBytes),
  };
  const resultBytes = Buffer.from(canonicalize(result));
  const summary = {
    schemaVersion: '1.0.0',
    kind: 'mutation-report-set-v1',
    complete: true,
    passed: true,
    packages: [
      {
        packageName: '@stynx/core',
        workspace: 'packages/core',
        resultPath: packageContract.resultPath,
        reportPath: packageContract.reportPath,
        resultDigest: sha256Hex(resultBytes),
        reportDigest: sha256Hex(reportBytes),
        score: 50,
        passed: true,
      },
    ],
    aggregate: {
      packageCount: 1,
      durationMs: 1234,
      score: 50,
      statusTotals: totals({ Killed: 1, Survived: 1, CompileError: 1 }),
    },
  };
  put(join(artifactsDir, packageContract.reportPath), report);
  put(join(artifactsDir, packageContract.resultPath), result);
  put(join(artifactsDir, contract.summaryPath), summary);
  return { artifactsDir, contract, packageContract, report, result, summary };
}

function successfulProcess() {
  return { errorAbsent: true, signal: null, status: 0 };
}

function rewriteStandardResult(state) {
  const resultBytes = Buffer.from(canonicalize(state.result));
  state.summary.packages[0].resultDigest = sha256Hex(resultBytes);
  put(join(state.artifactsDir, state.packageContract.resultPath), state.result);
  put(join(state.artifactsDir, state.contract.summaryPath), state.summary);
}

function composedFixture() {
  const artifactsDir = mkdtempSync(join(tmpdir(), 'devai-composed-mutation-proof-'));
  temporaryDirectories.push(artifactsDir);
  const baseline = {
    commit: 'a'.repeat(40),
    tree: 'b'.repeat(40),
    summaryBytes: 4096,
    summarySha256: 'c'.repeat(64),
  };
  const candidate = { commit: 'd'.repeat(40), tree: 'e'.repeat(40) };
  const packages = [];
  const packageContracts = [];
  const paths = ['mutation/summary.json'];
  let durationMs = 0;
  let freshDurationMs = 0;
  for (let index = 0; index < 38; index += 1) {
    const stem = `package-${String(index).padStart(2, '0')}`;
    const packageName = `@fixture/${stem}`;
    const workspace = `packages/${stem}`;
    const resultPath = `mutation/${stem}.result.json`;
    const reportPath = `mutation/${stem}.stryker.json`;
    const thresholds = { high: 100, low: 90, break: 90 };
    const packageContract = { packageName, workspace, resultPath, reportPath, thresholds };
    packageContracts.push(packageContract);
    paths.push(resultPath, reportPath);
    const report = {
      schemaVersion: '1',
      projectRoot: '.',
      thresholds,
      files: {
        [`src/${stem}.ts`]: {
          language: 'typescript',
          mutants: [{ id: String(index), status: 'Killed' }],
        },
      },
      testFiles: {},
      config: {},
      framework: { name: 'StrykerJS', branding: {} },
    };
    const reportBytes = Buffer.from(canonicalize(report));
    const fresh = index < 4;
    const packageDurationMs = index + 1;
    const result = {
      schemaVersion: '1.0.0',
      kind: 'mutation-package-result-v1',
      packageName,
      workspace,
      passed: true,
      durationMs: packageDurationMs,
      toolVersions: { stryker: '9.6.1' },
      thresholds,
      score: 100,
      statusTotals: totals({ Killed: 1 }),
      reportDigest: sha256Hex(reportBytes),
      ...(fresh && { process: successfulProcess() }),
    };
    const resultBytes = Buffer.from(canonicalize(result));
    const entry = {
      baselineCommit: fresh ? null : baseline.commit,
      baselineTree: fresh ? null : baseline.tree,
      durationMs: packageDurationMs,
      inputProjectionDigest: sha256Hex(Buffer.from(`input:${packageName}`)),
      packageName,
      passed: true,
      ...(fresh && { process: successfulProcess() }),
      provenance: fresh ? 'fresh' : 'reused',
      reportDigest: sha256Hex(reportBytes),
      reportPath,
      resultDigest: sha256Hex(resultBytes),
      resultPath,
      score: 100,
      statusTotals: totals({ Killed: 1 }),
      targetCensus: { targetFileCount: 1, totalMutants: 1 },
      thresholds,
      workspace,
    };
    durationMs += packageDurationMs;
    if (fresh) freshDurationMs += packageDurationMs;
    packages.push(entry);
    put(join(artifactsDir, reportPath), report);
    put(join(artifactsDir, resultPath), result);
  }
  const contract = {
    kind: 'mutation-report-set-v1',
    expectedPackageCount: packageContracts.length,
    summaryPath: 'mutation/summary.json',
    packages: packageContracts,
    paths,
  };
  const summary = {
    schemaVersion: '1.0.0',
    kind: 'mutation-composed-report-set-v1',
    candidate,
    baseline,
    semanticRebindComparison: {
      kind: 'root-manifest-unchanged-with-historical-input-v1',
      allowedScriptTransitions: [],
      canonicalContractBytes: 597,
      canonicalContractSha256: 'f'.repeat(64),
      comparison: {
        historicalMutationInputTreeEntries:
          'match-explicit-historical-candidate-mode-type-oid',
        otherMutationInputTreeEntries: 'identical-mode-type-oid',
        rootManifest: 'source-and-target-identical',
      },
      sourceRootManifest: {
        bytes: 10790,
        gitBlobOid: '1'.repeat(40),
        sha256: '2'.repeat(64),
      },
      targetRootManifest: {
        bytes: 10790,
        gitBlobOid: '1'.repeat(40),
        sha256: '2'.repeat(64),
      },
    },
    complete: true,
    passed: true,
    packages,
    aggregate: {
      packageCount: 38,
      freshPackageCount: 4,
      reusedPackageCount: 34,
      durationMs,
      freshDurationMs,
      score: 100,
      statusTotals: totals({ Killed: 38 }),
    },
  };
  put(join(artifactsDir, contract.summaryPath), summary);
  return { artifactsDir, baseline, candidate, contract, packages, summary };
}

function expectCode(code, action) {
  assert.throws(action, (error) => error?.code === code);
}

describe('mutation-report-set-v1 verification', () => {
  it('recomputes roster, report digests, scores, thresholds, and aggregate totals', () => {
    const state = fixture();
    assert.deepEqual(verifyMutationReportSet(state.contract, state.artifactsDir), {
      packageCount: 1,
      score: 50,
      statusTotals: totals({ Killed: 1, Survived: 1, CompileError: 1 }),
    });
  });

  it('keeps the standard schema valid with absent or successful process metadata', () => {
    const absent = fixture();
    assert.equal(verifyMutationReportSet(absent.contract, absent.artifactsDir).packageCount, 1);

    const present = fixture();
    present.result.process = successfulProcess();
    rewriteStandardResult(present);
    assert.equal(verifyMutationReportSet(present.contract, present.artifactsDir).packageCount, 1);
  });

  it('rejects malformed and unsuccessful process metadata fail closed', () => {
    const cases = [
      [null, 'MUTATION_REPORT_INVALID'],
      [{}, 'SCHEMA_INVALID'],
      [{ ...successfulProcess(), extra: true }, 'SCHEMA_INVALID'],
      [{ ...successfulProcess(), status: 1 }, 'MUTATION_REPORT_INVALID'],
      [{ ...successfulProcess(), status: '0' }, 'MUTATION_REPORT_INVALID'],
      [{ ...successfulProcess(), signal: 'SIGTERM' }, 'MUTATION_REPORT_INVALID'],
      [{ ...successfulProcess(), errorAbsent: false }, 'MUTATION_REPORT_INVALID'],
      [{ ...successfulProcess(), errorAbsent: 'true' }, 'MUTATION_REPORT_INVALID'],
    ];
    for (const [process, code] of cases) {
      const state = fixture();
      state.result.process = process;
      rewriteStandardResult(state);
      expectCode(code, () => verifyMutationReportSet(state.contract, state.artifactsDir));
    }
  });

  it('rejects partial rosters, changed reports, threshold failures, and absolute paths', () => {
    const partial = fixture();
    partial.contract.expectedPackageCount = 2;
    expectCode('SCHEMA_INVALID', () => validateMutationContract(partial.contract, 'contract'));

    const changed = fixture();
    changed.report.files['src/core.ts'].mutants[0].status = 'Survived';
    put(join(changed.artifactsDir, changed.packageContract.reportPath), changed.report);
    expectCode('ARTIFACT_DIGEST_MISMATCH', () =>
      verifyMutationReportSet(changed.contract, changed.artifactsDir),
    );

    const failed = fixture();
    failed.contract.packages[0].thresholds.break = 51;
    failed.report.thresholds.break = 51;
    failed.result.thresholds.break = 51;
    failed.result.passed = false;
    const reportBytes = Buffer.from(canonicalize(failed.report));
    failed.result.reportDigest = sha256Hex(reportBytes);
    put(join(failed.artifactsDir, failed.packageContract.reportPath), failed.report);
    put(join(failed.artifactsDir, failed.packageContract.resultPath), failed.result);
    expectCode('MUTATION_THRESHOLD_FAILED', () =>
      verifyMutationReportSet(failed.contract, failed.artifactsDir),
    );

    const absolute = fixture();
    absolute.report.projectRoot = '/Users/inspector/stynx/packages/core';
    put(join(absolute.artifactsDir, absolute.packageContract.reportPath), absolute.report);
    expectCode('MUTATION_REPORT_INVALID', () =>
      verifyMutationReportSet(absolute.contract, absolute.artifactsDir),
    );
  });
});

describe('mutation-composed-report-set-v1 verification', () => {
  it('accepts and recomputes an exact 4-fresh/34-reused composition', () => {
    const state = composedFixture();
    assert.deepEqual(
      verifyMutationReportSet(state.contract, state.artifactsDir, {
        candidateCommit: state.candidate.commit,
        candidateTree: state.candidate.tree,
      }),
      {
        packageCount: 38,
        score: 100,
        statusTotals: totals({ Killed: 38 }),
      },
    );
  });

  it('binds exact candidate, baseline, and semantic-rebind shapes', () => {
    for (const mutate of [
      (state) => (state.summary.candidate.commit = '0'.repeat(40)),
      (state) => (state.summary.baseline.extra = true),
      (state) => (state.summary.semanticRebindComparison.comparison.extra = 'forbidden'),
      (state) => (state.summary.semanticRebindComparison.sourceRootManifest.bytes = -1),
    ]) {
      const state = composedFixture();
      mutate(state);
      put(join(state.artifactsDir, state.contract.summaryPath), state.summary);
      expectCode('MUTATION_SUMMARY_MISMATCH', () =>
        verifyMutationReportSet(state.contract, state.artifactsDir, {
          candidateCommit: state.candidate.commit,
          candidateTree: state.candidate.tree,
        }),
      );
    }
  });

  it('enforces fresh/reused provenance, baseline binding, and process presence', () => {
    for (const mutate of [
      (state) => delete state.summary.packages[0].process,
      (state) => (state.summary.packages[4].process = successfulProcess()),
      (state) => (state.summary.packages[0].baselineCommit = state.baseline.commit),
      (state) => (state.summary.packages[4].baselineTree = null),
      (state) => (state.summary.packages[4].provenance = 'fresh'),
    ]) {
      const state = composedFixture();
      mutate(state);
      put(join(state.artifactsDir, state.contract.summaryPath), state.summary);
      expectCode('MUTATION_SUMMARY_MISMATCH', () =>
        verifyMutationReportSet(state.contract, state.artifactsDir, {
          candidateCommit: state.candidate.commit,
          candidateTree: state.candidate.tree,
        }),
      );
    }
  });

  it('recomputes paths, digests, thresholds, targets, metrics, durations, and aggregates', () => {
    for (const mutate of [
      (state) => (state.summary.packages[0].reportPath = 'mutation/wrong.json'),
      (state) => (state.summary.packages[0].resultDigest = '0'.repeat(64)),
      (state) => (state.summary.packages[0].thresholds.break = 91),
      (state) => (state.summary.packages[0].targetCensus.totalMutants = 2),
      (state) => (state.summary.packages[0].score = 99),
      (state) => (state.summary.packages[0].statusTotals.Killed = 2),
      (state) => (state.summary.packages[0].durationMs += 1),
      (state) => (state.summary.aggregate.freshPackageCount = 5),
      (state) => (state.summary.aggregate.reusedPackageCount = 33),
      (state) => (state.summary.aggregate.freshDurationMs += 1),
      (state) => (state.summary.aggregate.durationMs += 1),
    ]) {
      const state = composedFixture();
      mutate(state);
      put(join(state.artifactsDir, state.contract.summaryPath), state.summary);
      expectCode('MUTATION_SUMMARY_MISMATCH', () =>
        verifyMutationReportSet(state.contract, state.artifactsDir, {
          candidateCommit: state.candidate.commit,
          candidateTree: state.candidate.tree,
        }),
      );
    }
  });

  it('retains canonical JSON and exact artifact-roster protections for compositions', () => {
    const noncanonical = composedFixture();
    writeFileSync(
      join(noncanonical.artifactsDir, noncanonical.contract.summaryPath),
      JSON.stringify(noncanonical.summary, null, 2),
    );
    expectCode('NON_CANONICAL_JSON', () =>
      verifyMutationReportSet(noncanonical.contract, noncanonical.artifactsDir, {
        candidateCommit: noncanonical.candidate.commit,
        candidateTree: noncanonical.candidate.tree,
      }),
    );

    const roster = composedFixture();
    roster.contract.paths.pop();
    expectCode('SCHEMA_INVALID', () => validateMutationContract(roster.contract, 'contract'));
  });
});

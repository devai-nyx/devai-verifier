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
          { id: '0', status: 'Killed' },
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

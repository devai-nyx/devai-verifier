import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  VerificationError,
  assertExactKeys,
  assertObject,
  assertString,
  assertUniqueStrings,
  canonicalize,
  sha256Hex,
} from './canonical.js';

const PACKAGE_NAME = /^@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*$/u;
const PORTABLE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\\)(?!.*\0)[^/]+(?:\/[^/]+)*$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const MUTANT_STATUSES = [
  'CompileError',
  'Ignored',
  'Killed',
  'NoCoverage',
  'Pending',
  'RuntimeError',
  'Survived',
  'Timeout',
];

function assertNonnegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new VerificationError('MUTATION_REPORT_INVALID', `${label} must be a nonnegative integer`);
  }
}

function assertFiniteNumber(value, label) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new VerificationError('MUTATION_REPORT_INVALID', `${label} must be a finite number`);
  }
}

function validateThresholds(value, label) {
  assertExactKeys(value, ['break', 'high', 'low'], label);
  for (const key of ['break', 'high', 'low']) assertFiniteNumber(value[key], `${label}.${key}`);
  if (
    value.break < 0 ||
    value.break > 100 ||
    value.high < 0 ||
    value.high > 100 ||
    value.low < 0 ||
    value.low > 100 ||
    value.low > value.high
  ) {
    throw new VerificationError('MUTATION_REPORT_INVALID', `${label} ordering is invalid`);
  }
}

function validateStatusTotals(value, label) {
  assertExactKeys(value, MUTANT_STATUSES, label);
  for (const status of MUTANT_STATUSES) assertNonnegativeInteger(value[status], `${label}.${status}`);
}

function readCanonicalJson(path, label) {
  let text;
  let value;
  try {
    text = readFileSync(path, 'utf8');
    value = JSON.parse(text);
  } catch (error) {
    throw new VerificationError('MUTATION_REPORT_INVALID', `${label} is unreadable: ${error.message}`);
  }
  if (text !== canonicalize(value) && text !== `${canonicalize(value)}\n`) {
    throw new VerificationError('NON_CANONICAL_JSON', `${label} is not canonical JSON`);
  }
  return { value, bytes: Buffer.from(text.endsWith('\n') ? text.slice(0, -1) : text, 'utf8') };
}

function containsAbsolutePath(value) {
  if (typeof value === 'string') {
    return value.startsWith('/') || /^[A-Za-z]:[\\/]/u.test(value) || value.startsWith('file:///');
  }
  if (Array.isArray(value)) return value.some(containsAbsolutePath);
  if (value !== null && typeof value === 'object') return Object.values(value).some(containsAbsolutePath);
  return false;
}

function reportMetrics(report, label) {
  assertObject(report, label);
  assertObject(report.files, `${label}.files`);
  assertObject(report.thresholds, `${label}.thresholds`);
  validateThresholds(report.thresholds, `${label}.thresholds`);
  if (report.projectRoot !== '.') {
    throw new VerificationError('MUTATION_REPORT_INVALID', `${label}.projectRoot must be normalized to .`);
  }
  if (containsAbsolutePath(report)) {
    throw new VerificationError('MUTATION_REPORT_INVALID', `${label} contains an absolute workstation path`);
  }
  const totals = Object.fromEntries(MUTANT_STATUSES.map((status) => [status, 0]));
  for (const [file, fileResult] of Object.entries(report.files)) {
    assertString(file, `${label} file`, PORTABLE_PATH);
    assertObject(fileResult, `${label}.files.${file}`);
    if (!Array.isArray(fileResult.mutants)) {
      throw new VerificationError('MUTATION_REPORT_INVALID', `${label}.files.${file}.mutants must be an array`);
    }
    for (const mutant of fileResult.mutants) {
      assertObject(mutant, `${label} mutant`);
      if (!MUTANT_STATUSES.includes(mutant.status)) {
        throw new VerificationError('MUTATION_REPORT_INVALID', `${label} has unknown mutant status`);
      }
      totals[mutant.status] += 1;
    }
  }
  const detected = totals.Killed + totals.Timeout;
  const scored = detected + totals.Survived + totals.NoCoverage;
  const score = scored === 0 ? 100 : (detected / scored) * 100;
  return { totals, score };
}

function validatePackageContract(entry, label) {
  assertExactKeys(
    entry,
    ['packageName', 'reportPath', 'resultPath', 'thresholds', 'workspace'],
    label,
  );
  assertString(entry.packageName, `${label}.packageName`, PACKAGE_NAME);
  assertString(entry.workspace, `${label}.workspace`, PORTABLE_PATH);
  assertString(entry.reportPath, `${label}.reportPath`, PORTABLE_PATH);
  assertString(entry.resultPath, `${label}.resultPath`, PORTABLE_PATH);
  validateThresholds(entry.thresholds, `${label}.thresholds`);
}

export function validateMutationContract(contract, label) {
  assertExactKeys(
    contract,
    ['expectedPackageCount', 'kind', 'packages', 'paths', 'summaryPath'],
    label,
  );
  if (contract.kind !== 'mutation-report-set-v1') {
    throw new VerificationError('SCHEMA_INVALID', `${label}.kind is unsupported`);
  }
  assertNonnegativeInteger(contract.expectedPackageCount, `${label}.expectedPackageCount`);
  if (contract.expectedPackageCount === 0 || !Array.isArray(contract.packages)) {
    throw new VerificationError('SCHEMA_INVALID', `${label}.packages must be nonempty`);
  }
  assertString(contract.summaryPath, `${label}.summaryPath`, PORTABLE_PATH);
  const packageNames = [];
  const workspaces = [];
  const declaredPaths = [contract.summaryPath];
  for (const [index, entry] of contract.packages.entries()) {
    validatePackageContract(entry, `${label}.packages[${index}]`);
    packageNames.push(entry.packageName);
    workspaces.push(entry.workspace);
    declaredPaths.push(entry.resultPath, entry.reportPath);
  }
  if (contract.packages.length !== contract.expectedPackageCount) {
    throw new VerificationError('SCHEMA_INVALID', `${label} package count differs`);
  }
  assertUniqueStrings(packageNames, `${label} package names`);
  assertUniqueStrings(workspaces, `${label} workspaces`);
  assertUniqueStrings(declaredPaths, `${label} artifact paths`);
  assertUniqueStrings(contract.paths, `${label}.paths`);
  const expected = [...declaredPaths].sort();
  const actual = [...contract.paths].sort();
  if (actual.length !== expected.length || actual.some((path, index) => path !== expected[index])) {
    throw new VerificationError('SCHEMA_INVALID', `${label}.paths differs from the mutation artifact roster`);
  }
}

function validatePackageResult(result, contract, report, reportDigest, metrics, label) {
  assertExactKeys(
    result,
    [
      'durationMs',
      'kind',
      'packageName',
      'passed',
      'reportDigest',
      'schemaVersion',
      'score',
      'statusTotals',
      'thresholds',
      'toolVersions',
      'workspace',
    ],
    label,
  );
  if (result.schemaVersion !== '1.0.0' || result.kind !== 'mutation-package-result-v1') {
    throw new VerificationError('MUTATION_REPORT_INVALID', `${label} schema or kind is unsupported`);
  }
  if (result.packageName !== contract.packageName || result.workspace !== contract.workspace) {
    throw new VerificationError('MUTATION_ROSTER_MISMATCH', `${label} package identity differs`);
  }
  validateThresholds(result.thresholds, `${label}.thresholds`);
  if (canonicalize(result.thresholds) !== canonicalize(contract.thresholds) || canonicalize(report.thresholds) !== canonicalize(contract.thresholds)) {
    throw new VerificationError('MUTATION_THRESHOLD_MISMATCH', `${label} thresholds differ from policy`);
  }
  assertFiniteNumber(result.score, `${label}.score`);
  validateStatusTotals(result.statusTotals, `${label}.statusTotals`);
  assertNonnegativeInteger(result.durationMs, `${label}.durationMs`);
  assertString(result.reportDigest, `${label}.reportDigest`, SHA256);
  assertObject(result.toolVersions, `${label}.toolVersions`);
  if (Object.keys(result.toolVersions).length === 0) {
    throw new VerificationError('MUTATION_REPORT_INVALID', `${label}.toolVersions must be nonempty`);
  }
  for (const [tool, version] of Object.entries(result.toolVersions)) {
    assertString(tool, `${label} tool`);
    assertString(version, `${label}.${tool}`);
  }
  if (result.reportDigest !== reportDigest) {
    throw new VerificationError('ARTIFACT_DIGEST_MISMATCH', `${label} report digest differs`);
  }
  if (canonicalize(result.statusTotals) !== canonicalize(metrics.totals) || result.score !== metrics.score) {
    throw new VerificationError('MUTATION_METRIC_MISMATCH', `${label} metrics do not match the canonical report`);
  }
  const passed = metrics.score >= contract.thresholds.break;
  if (result.passed !== passed || !passed) {
    throw new VerificationError('MUTATION_THRESHOLD_FAILED', `${label} does not satisfy the break threshold`);
  }
}

export function verifyMutationReportSet(contract, artifactsDir) {
  validateMutationContract(contract, 'mutation output contract');
  const summaryFile = readCanonicalJson(join(artifactsDir, contract.summaryPath), 'mutation summary');
  const summary = summaryFile.value;
  const aggregateTotals = Object.fromEntries(MUTANT_STATUSES.map((status) => [status, 0]));
  const summaryEntries = [];
  let durationMs = 0;
  for (const packageContract of contract.packages) {
    const reportFile = readCanonicalJson(
      join(artifactsDir, packageContract.reportPath),
      `mutation report ${packageContract.packageName}`,
    );
    const resultFile = readCanonicalJson(
      join(artifactsDir, packageContract.resultPath),
      `mutation result ${packageContract.packageName}`,
    );
    const reportDigest = sha256Hex(reportFile.bytes);
    const resultDigest = sha256Hex(resultFile.bytes);
    const metrics = reportMetrics(reportFile.value, `mutation report ${packageContract.packageName}`);
    validatePackageResult(
      resultFile.value,
      packageContract,
      reportFile.value,
      reportDigest,
      metrics,
      `mutation result ${packageContract.packageName}`,
    );
    for (const status of MUTANT_STATUSES) aggregateTotals[status] += metrics.totals[status];
    durationMs += resultFile.value.durationMs;
    summaryEntries.push({
      packageName: packageContract.packageName,
      workspace: packageContract.workspace,
      resultPath: packageContract.resultPath,
      reportPath: packageContract.reportPath,
      resultDigest,
      reportDigest,
      score: metrics.score,
      passed: true,
    });
  }
  const detected = aggregateTotals.Killed + aggregateTotals.Timeout;
  const scored = detected + aggregateTotals.Survived + aggregateTotals.NoCoverage;
  const aggregateScore = scored === 0 ? 100 : (detected / scored) * 100;
  const expectedSummary = {
    schemaVersion: '1.0.0',
    kind: 'mutation-report-set-v1',
    complete: true,
    passed: true,
    packages: summaryEntries,
    aggregate: {
      packageCount: contract.expectedPackageCount,
      durationMs,
      score: aggregateScore,
      statusTotals: aggregateTotals,
    },
  };
  if (canonicalize(summary) !== canonicalize(expectedSummary)) {
    throw new VerificationError('MUTATION_SUMMARY_MISMATCH', 'mutation summary does not match reports');
  }
  return {
    packageCount: contract.expectedPackageCount,
    score: aggregateScore,
    statusTotals: aggregateTotals,
  };
}

export { MUTANT_STATUSES };

import {
  VerificationError,
  canonicalBytes,
  canonicalize,
  framedDigest,
  sha256Hex,
} from './canonical-json.js';

export const MUTATION_V21_SCHEMA = '2.1.0';
export const MUTATION_V21_CONTRACT = 'mutation-report-set-v2';

const PACKAGE_NAME = /^@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const GIT_OBJECT = /^(?!0+$)(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const MUTANT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u;
const TOOL_VERSION = /^[A-Za-z0-9][A-Za-z0-9._+:-]*$/u;
const MUTATOR_NAME = /^[^\u0000-\u001f\u007f/\\]+$/u;
const SIGNAL = /^SIG[A-Z0-9]{1,20}$/u;
const RECEIPT_ID = /^MSV2-[0-9a-f]{16}$/u;

const INPUT_BINDINGS = [
  'source',
  'tests',
  'manifests',
  'mutationConfiguration',
  'runner',
  'roster',
  'thresholds',
  'sanitizer',
  'lockfile',
  'environment',
  'toolchain',
  'semanticRebind',
];
const STATUSES = [
  'CompileError',
  'Ignored',
  'Killed',
  'NoCoverage',
  'Pending',
  'RuntimeError',
  'Survived',
  'Timeout',
];
const REASONS = [
  'no-mutatable-production-surface',
  'package-excluded-by-approved-release-profile',
];

const DOMAINS = Object.freeze({
  outputContract: 'devai:mutation-output-contract:v2.1',
  packageResultSet: 'devai:mutation-package-result-set:v2.1',
  compositionEntry: 'devai:mutation-composition-entry:v2.1',
  evidenceRef: 'devai:mutation-evidence-ref:v2.1',
  input: 'devai:mutation-input:v2.1',
  composition: 'devai:mutation-composition:v2.1',
  semanticReceipt: 'devai:mutation-semantic-receipt:v2.1',
});

function fail(code, message) {
  throw new VerificationError(code, message);
}

function object(value, label, code = 'SCHEMA_INVALID') {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(code, `${label} must be an object`);
  }
}

function exact(value, keys, label, code = 'SCHEMA_INVALID') {
  object(value, label, code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(code, `${label} has an invalid field population`);
  }
}

function string(value, label, pattern, code = 'SCHEMA_INVALID') {
  if (typeof value !== 'string' || (pattern !== undefined && !pattern.test(value))) {
    fail(code, `${label} is invalid`);
  }
}

function boolean(value, label, code = 'SCHEMA_INVALID') {
  if (typeof value !== 'boolean') fail(code, `${label} must be boolean`);
}

function safeCount(value, label, code = 'MUTATION_REPORT_INVALID') {
  if (!Number.isSafeInteger(value) || value < 0) fail(code, `${label} must be a safe count`);
}

function finite(value, label, code = 'MUTATION_REPORT_INVALID') {
  if (typeof value !== 'number' || !Number.isFinite(value)) fail(code, `${label} must be finite`);
}

function checkedAdd(left, right, label) {
  const result = left + right;
  if (!Number.isSafeInteger(result)) fail('MUTATION_REPORT_INVALID', `${label} exceeds safe integer range`);
  return result;
}

function sameNumber(actual, expected) {
  return Object.is(actual, expected) && !Object.is(actual, -0);
}

function validatePortable(path, label, code = 'SCHEMA_INVALID') {
  if (
    typeof path !== 'string' ||
    path.length === 0 ||
    path !== path.normalize('NFC') ||
    path.startsWith('/') ||
    /^[A-Za-z]:/u.test(path) ||
    path.startsWith('//') ||
    path.includes('\\') ||
    /[\u0000-\u001f\u007f]/u.test(path)
  ) {
    fail(code, `${label} is not a canonical portable path`);
  }
  if (path.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')) {
    fail(code, `${label} is not a canonical portable path`);
  }
}

function validateCandidate(candidate, label) {
  exact(candidate, ['releaseUnit', 'commit', 'tree'], label);
  string(candidate.releaseUnit, `${label}.releaseUnit`);
  if (candidate.releaseUnit.length > 200) fail('SCHEMA_INVALID', `${label}.releaseUnit is too long`);
  string(candidate.commit, `${label}.commit`, GIT_OBJECT);
  string(candidate.tree, `${label}.tree`, GIT_OBJECT);
}

function validatePopulation(binding, label) {
  exact(
    binding,
    ['canonicalization', 'memberCount', 'populationDigest', 'selectionRuleDigest'],
    label,
    'MUTATION_REUSE_DENIED',
  );
  if (binding.canonicalization !== 'rfc8785-jcs-utf8') {
    fail('MUTATION_REUSE_DENIED', `${label} canonicalization is unsupported`);
  }
  safeCount(binding.memberCount, `${label}.memberCount`, 'MUTATION_REUSE_DENIED');
  string(binding.populationDigest, `${label}.populationDigest`, SHA256, 'MUTATION_REUSE_DENIED');
  string(
    binding.selectionRuleDigest,
    `${label}.selectionRuleDigest`,
    SHA256,
    'MUTATION_REUSE_DENIED',
  );
}

function validateInputProjection(projection, packageName, workspace, label) {
  object(projection, label, 'MUTATION_INPUT_IDENTITY_MISSING');
  for (const key of ['schemaVersion', 'kind', 'packageName', 'workspace', 'bindings']) {
    if (!Object.hasOwn(projection, key)) {
      fail('MUTATION_INPUT_IDENTITY_MISSING', `${label}.${key} is missing`);
    }
  }
  object(projection.bindings, `${label}.bindings`, 'MUTATION_INPUT_IDENTITY_MISSING');
  for (const binding of INPUT_BINDINGS) {
    if (!Object.hasOwn(projection.bindings, binding)) {
      fail('MUTATION_INPUT_IDENTITY_MISSING', `${label}.bindings.${binding} is missing`);
    }
  }
  exact(
    projection,
    ['schemaVersion', 'kind', 'packageName', 'workspace', 'bindings'],
    label,
    'MUTATION_REUSE_DENIED',
  );
  exact(projection.bindings, INPUT_BINDINGS, `${label}.bindings`, 'MUTATION_REUSE_DENIED');
  if (
    projection.schemaVersion !== MUTATION_V21_SCHEMA ||
    projection.kind !== 'mutation-input-projection-v2'
  ) {
    fail('MUTATION_VERSION_UNSUPPORTED', `${label} declares an unsupported version`);
  }
  if (projection.packageName !== packageName || projection.workspace !== workspace) {
    fail('MUTATION_INPUT_DIGEST_MISMATCH', `${label} package identity differs`);
  }
  for (const binding of INPUT_BINDINGS) {
    validatePopulation(projection.bindings[binding], `${label}.bindings.${binding}`);
  }
}

function validateThresholds(thresholds, label, full = true) {
  const keys = full ? ['break', 'high', 'low', 'scoreMin', 'survivedMax'] : ['break', 'high', 'low'];
  exact(thresholds, keys, label, 'MUTATION_THRESHOLD_MISMATCH');
  for (const key of ['break', 'high', 'low', ...(full ? ['scoreMin'] : [])]) {
    finite(thresholds[key], `${label}.${key}`, 'MUTATION_THRESHOLD_MISMATCH');
    if (thresholds[key] < 0 || thresholds[key] > 100) {
      fail('MUTATION_THRESHOLD_MISMATCH', `${label}.${key} is out of range`);
    }
  }
  if (thresholds.low > thresholds.high) {
    fail('MUTATION_THRESHOLD_MISMATCH', `${label} ordering is invalid`);
  }
  if (full) safeCount(thresholds.survivedMax, `${label}.survivedMax`, 'MUTATION_THRESHOLD_MISMATCH');
}

function validateStatusTotals(totals, label) {
  exact(totals, STATUSES, label, 'MUTATION_REPORT_INVALID');
  for (const status of STATUSES) safeCount(totals[status], `${label}.${status}`);
}

function emptyTotals() {
  return Object.fromEntries(STATUSES.map((status) => [status, 0]));
}

function reportMetrics(report, label) {
  exact(
    report,
    [
      'schemaVersion',
      'kind',
      'strykerSchemaVersion',
      'projectRoot',
      'thresholds',
      'files',
      'testFiles',
      'config',
      'framework',
    ],
    label,
    'MUTATION_REPORT_INVALID',
  );
  if (
    report.schemaVersion !== MUTATION_V21_SCHEMA ||
    report.kind !== 'mutation-normalized-stryker-report-v2' ||
    report.strykerSchemaVersion !== '1' ||
    report.projectRoot !== '.'
  ) {
    fail('MUTATION_VERSION_UNSUPPORTED', `${label} declares an unsupported normalized report`);
  }
  validateThresholds(report.thresholds, `${label}.thresholds`, false);
  exact(report.config, [], `${label}.config`, 'MUTATION_REPORT_INVALID');
  exact(report.framework, ['name'], `${label}.framework`, 'MUTATION_REPORT_INVALID');
  if (report.framework.name !== 'StrykerJS') fail('MUTATION_REPORT_INVALID', `${label}.framework is invalid`);
  object(report.files, `${label}.files`, 'MUTATION_REPORT_INVALID');
  object(report.testFiles, `${label}.testFiles`, 'MUTATION_REPORT_INVALID');
  for (const [path, value] of Object.entries(report.testFiles)) {
    validatePortable(path, `${label}.testFiles path`, 'MUTATION_REPORT_INVALID');
    exact(value, [], `${label}.testFiles.${path}`, 'MUTATION_REPORT_INVALID');
  }

  const totals = emptyTotals();
  const mutantIds = new Set();
  for (const [path, file] of Object.entries(report.files)) {
    validatePortable(path, `${label}.files path`, 'MUTATION_REPORT_INVALID');
    exact(file, ['language', 'mutants'], `${label}.files.${path}`, 'MUTATION_REPORT_INVALID');
    if (file.language !== 'javascript' && file.language !== 'typescript') {
      fail('MUTATION_REPORT_INVALID', `${label}.files.${path}.language is invalid`);
    }
    if (!Array.isArray(file.mutants)) fail('MUTATION_REPORT_INVALID', `${label} mutants must be an array`);
    for (const mutant of file.mutants) {
      exact(
        mutant,
        ['id', 'mutatorName', 'replacementDigest', 'location', 'status'],
        `${label} mutant`,
        'MUTATION_REPORT_INVALID',
      );
      string(mutant.id, `${label} mutant.id`, MUTANT_ID, 'MUTATION_REPORT_INVALID');
      const identity = `${path}\0${mutant.id}`;
      if (mutantIds.has(identity)) fail('MUTATION_REPORT_INVALID', `${label} mutant IDs are duplicated`);
      mutantIds.add(identity);
      string(
        mutant.mutatorName,
        `${label} mutant.mutatorName`,
        MUTATOR_NAME,
        'MUTATION_REPORT_INVALID',
      );
      string(
        mutant.replacementDigest,
        `${label} mutant.replacementDigest`,
        SHA256,
        'MUTATION_REPORT_INVALID',
      );
      exact(mutant.location, ['start', 'end'], `${label} mutant.location`, 'MUTATION_REPORT_INVALID');
      for (const position of ['start', 'end']) {
        const point = mutant.location[position];
        exact(point, ['line', 'column'], `${label} mutant.location.${position}`, 'MUTATION_REPORT_INVALID');
        if (!Number.isSafeInteger(point.line) || point.line < 1) {
          fail('MUTATION_REPORT_INVALID', `${label} mutant line is invalid`);
        }
        if (!Number.isSafeInteger(point.column) || point.column < 0) {
          fail('MUTATION_REPORT_INVALID', `${label} mutant column is invalid`);
        }
      }
      if (!STATUSES.includes(mutant.status)) fail('MUTATION_REPORT_INVALID', `${label} mutant status is invalid`);
      totals[mutant.status] = checkedAdd(totals[mutant.status], 1, `${label}.${mutant.status}`);
    }
  }
  const targetFileCount = Object.keys(report.files).length;
  const totalMutants = STATUSES.reduce(
    (total, status) => checkedAdd(total, totals[status], `${label}.totalMutants`),
    0,
  );
  const detected = checkedAdd(totals.Killed, totals.Timeout, `${label}.detected`);
  const scored = checkedAdd(
    checkedAdd(detected, totals.Survived, `${label}.scored`),
    totals.NoCoverage,
    `${label}.scored`,
  );
  const score = scored === 0 ? 100 : (detected / scored) * 100;
  return { totals, detected, scored, score, targetCensus: { targetFileCount, totalMutants } };
}

function validateProcess(process, label) {
  exact(process, ['errorAbsent', 'signal', 'status'], label, 'MUTATION_REPORT_INVALID');
  boolean(process.errorAbsent, `${label}.errorAbsent`, 'MUTATION_REPORT_INVALID');
  if (process.signal !== null) string(process.signal, `${label}.signal`, SIGNAL, 'MUTATION_REPORT_INVALID');
  if (process.status !== null && (!Number.isSafeInteger(process.status) || process.status < 0 || process.status > 255)) {
    fail('MUTATION_REPORT_INVALID', `${label}.status is invalid`);
  }
}

function validateToolVersions(versions, label) {
  object(versions, label, 'MUTATION_REPORT_INVALID');
  for (const [name, version] of Object.entries(versions)) {
    string(name, `${label} name`, TOOL_VERSION, 'MUTATION_REPORT_INVALID');
    string(version, `${label}.${name}`, TOOL_VERSION, 'MUTATION_REPORT_INVALID');
  }
}

function validateReuseOrigin(origin, label) {
  exact(origin, ['candidate', 'semanticReceiptDigest', 'evidenceSetDigest'], label, 'MUTATION_ORIGIN_MISMATCH');
  validateCandidate(origin.candidate, `${label}.candidate`);
  string(origin.semanticReceiptDigest, `${label}.semanticReceiptDigest`, SHA256, 'MUTATION_ORIGIN_MISMATCH');
  string(origin.evidenceSetDigest, `${label}.evidenceSetDigest`, SHA256, 'MUTATION_ORIGIN_MISMATCH');
}

function artifactPaths(inputDigest, reportDigest, resultDigest) {
  const root = `.devai/state/mutation/v2/store/inputs/${inputDigest}/objects`;
  return {
    reportPath: `${root}/${reportDigest}.report.json`,
    resultPath: `${root}/${resultDigest}.result.json`,
  };
}

function validateRequiredMaterial(contractEntry, material, disposition, origin, enforcePassing) {
  const label = `mutation result ${contractEntry.packageName}`;
  const result = material.result;
  const report = material.report;
  if (
    result?.kind === 'mutation-package-result-v1' ||
    result?.schemaVersion === '1.0.0'
  ) {
    if (disposition === 'reused') fail('MUTATION_REUSE_DENIED', `${label} is legacy evidence`);
    fail('MUTATION_VERSION_UNSUPPORTED', `${label} is legacy evidence`);
  }
  exact(
    result,
    [
      'schemaVersion',
      'kind',
      'packageName',
      'workspace',
      'inputProjection',
      'inputDigest',
      'reportDigest',
      'toolVersions',
      'process',
      'thresholds',
      'statusTotals',
      'targetCensus',
      'score',
      'complete',
      'passed',
    ],
    label,
    'MUTATION_REPORT_INVALID',
  );
  if (result.schemaVersion !== MUTATION_V21_SCHEMA || result.kind !== 'mutation-package-result-v2') {
    fail('MUTATION_VERSION_UNSUPPORTED', `${label} declares an unsupported version`);
  }
  if (result.packageName !== contractEntry.packageName || result.workspace !== contractEntry.workspace) {
    fail('MUTATION_ROSTER_MISMATCH', `${label} package identity differs`);
  }
  validateInputProjection(
    result.inputProjection,
    contractEntry.packageName,
    contractEntry.workspace,
    `${label}.inputProjection`,
  );
  const recomputedInputDigest = framedDigest(DOMAINS.input, contractEntry.inputProjection);
  if (
    contractEntry.inputDigest !== recomputedInputDigest ||
    result.inputDigest !== recomputedInputDigest ||
    canonicalize(result.inputProjection) !== canonicalize(contractEntry.inputProjection)
  ) {
    fail('MUTATION_INPUT_DIGEST_MISMATCH', `${label} input identity differs`);
  }
  validateToolVersions(result.toolVersions, `${label}.toolVersions`);
  validateProcess(result.process, `${label}.process`);
  validateThresholds(result.thresholds, `${label}.thresholds`);
  validateStatusTotals(result.statusTotals, `${label}.statusTotals`);
  exact(result.targetCensus, ['targetFileCount', 'totalMutants'], `${label}.targetCensus`, 'MUTATION_REPORT_INVALID');
  safeCount(result.targetCensus.targetFileCount, `${label}.targetCensus.targetFileCount`);
  safeCount(result.targetCensus.totalMutants, `${label}.targetCensus.totalMutants`);
  finite(result.score, `${label}.score`);
  boolean(result.complete, `${label}.complete`, 'MUTATION_REPORT_INVALID');
  boolean(result.passed, `${label}.passed`, 'MUTATION_REPORT_INVALID');
  string(result.reportDigest, `${label}.reportDigest`, SHA256, 'MUTATION_REPORT_INVALID');

  const metrics = reportMetrics(report, `mutation report ${contractEntry.packageName}`);
  const reportDigest = sha256Hex(canonicalBytes(report));
  const resultDigest = sha256Hex(canonicalBytes(result));
  if (result.reportDigest !== reportDigest) {
    fail('ARTIFACT_DIGEST_MISMATCH', `${label} report digest differs`);
  }
  const paths = artifactPaths(recomputedInputDigest, reportDigest, resultDigest);
  if (contractEntry.reportPath !== paths.reportPath || contractEntry.resultPath !== paths.resultPath) {
    fail('MUTATION_INPUT_DIGEST_MISMATCH', `${label} store address differs from its input identity`);
  }
  if (
    canonicalize(result.thresholds) !== canonicalize(contractEntry.thresholds) ||
    canonicalize(report.thresholds) !==
      canonicalize({
        break: contractEntry.thresholds.break,
        high: contractEntry.thresholds.high,
        low: contractEntry.thresholds.low,
      })
  ) {
    fail('MUTATION_THRESHOLD_MISMATCH', `${label} thresholds differ`);
  }
  if (
    canonicalize(result.statusTotals) !== canonicalize(metrics.totals) ||
    canonicalize(result.targetCensus) !== canonicalize(metrics.targetCensus) ||
    !sameNumber(result.score, metrics.score)
  ) {
    fail('MUTATION_METRIC_MISMATCH', `${label} metrics differ from the normalized report`);
  }

  const processSuccessful =
    result.process.errorAbsent === true && result.process.signal === null && result.process.status === 0;
  const complete =
    processSuccessful &&
    metrics.totals.Pending === 0 &&
    metrics.targetCensus.totalMutants > 0 &&
    metrics.scored > 0;
  const passed =
    complete &&
    metrics.totals.RuntimeError === 0 &&
    metrics.score >= Math.max(contractEntry.thresholds.break, contractEntry.thresholds.scoreMin) &&
    metrics.totals.Survived <= contractEntry.thresholds.survivedMax;
  if (result.complete !== complete || result.passed !== passed) {
    fail('MUTATION_METRIC_MISMATCH', `${label} semantic verdict differs`);
  }

  // Fixed verification error precedence: process, runtime, incomplete, threshold.
  if (enforcePassing) {
    if (!processSuccessful) {
      fail('MUTATION_INFRASTRUCTURE_FAILURE', `${label} process did not complete successfully`);
    }
    if (metrics.totals.RuntimeError !== 0) {
      fail('MUTATION_RUNTIME_FAILURE', `${label} contains runtime errors`);
    }
    if (!complete) fail('MUTATION_INCOMPLETE', `${label} is incomplete`);
    if (!passed) fail('MUTATION_THRESHOLD_FAILED', `${label} does not satisfy mutation thresholds`);
  }

  if (disposition !== 'executed' && disposition !== 'reused') {
    fail('MUTATION_SUMMARY_MISMATCH', `${label} disposition is invalid`);
  }
  if (disposition === 'executed' && origin !== null) {
    fail('MUTATION_ORIGIN_MISMATCH', `${label} executed origin must be null`);
  }
  if (disposition === 'reused') validateReuseOrigin(origin, `${label}.origin`);
  return { reportDigest, resultDigest, paths, metrics, complete, passed };
}

function validateRequiredContract(entry, label) {
  for (const key of ['inputProjection', 'inputDigest']) {
    if (!Object.hasOwn(entry, key)) {
      fail('MUTATION_INPUT_IDENTITY_MISSING', `${label}.${key} is missing`);
    }
  }
  exact(
    entry,
    [
      'packageName',
      'workspace',
      'requirement',
      'reportPath',
      'resultPath',
      'inputProjection',
      'inputDigest',
      'thresholds',
    ],
    label,
  );
  string(entry.packageName, `${label}.packageName`, PACKAGE_NAME);
  validatePortable(entry.workspace, `${label}.workspace`);
  validatePortable(entry.reportPath, `${label}.reportPath`);
  validatePortable(entry.resultPath, `${label}.resultPath`);
  if (entry.requirement !== 'required') fail('SCHEMA_INVALID', `${label}.requirement is invalid`);
  validateInputProjection(entry.inputProjection, entry.packageName, entry.workspace, `${label}.inputProjection`);
  string(entry.inputDigest, `${label}.inputDigest`, SHA256, 'MUTATION_INPUT_DIGEST_MISMATCH');
  if (entry.inputDigest !== framedDigest(DOMAINS.input, entry.inputProjection)) {
    fail('MUTATION_INPUT_DIGEST_MISMATCH', `${label}.inputDigest differs from its projection`);
  }
  validateThresholds(entry.thresholds, `${label}.thresholds`);
}

function validateNotRequiredContract(entry, label) {
  exact(entry, ['packageName', 'workspace', 'requirement', 'reasonCode'], label);
  string(entry.packageName, `${label}.packageName`, PACKAGE_NAME);
  validatePortable(entry.workspace, `${label}.workspace`);
  if (entry.requirement !== 'not-required' || !REASONS.includes(entry.reasonCode)) {
    fail('SCHEMA_INVALID', `${label} not-required decision is invalid`);
  }
}

export function validateMutationContractV21(contract, label = 'mutation output contract') {
  exact(
    contract,
    [
      'schemaVersion',
      'kind',
      'expectedPackageCount',
      'summaryPath',
      'semanticReceiptPath',
      'releasePlanReceiptDigest',
      'releaseProfileDigest',
      'policyDigest',
      'packages',
      'paths',
    ],
    label,
  );
  if (contract.kind !== MUTATION_V21_CONTRACT || contract.schemaVersion !== MUTATION_V21_SCHEMA) {
    fail('MUTATION_VERSION_UNSUPPORTED', `${label} version is unsupported`);
  }
  safeCount(contract.expectedPackageCount, `${label}.expectedPackageCount`, 'SCHEMA_INVALID');
  if (contract.expectedPackageCount === 0 || !Array.isArray(contract.packages)) {
    fail('SCHEMA_INVALID', `${label}.packages must be nonempty`);
  }
  if (contract.packages.length !== contract.expectedPackageCount) {
    fail('MUTATION_ROSTER_MISMATCH', `${label} package count differs`);
  }
  validatePortable(contract.summaryPath, `${label}.summaryPath`);
  validatePortable(contract.semanticReceiptPath, `${label}.semanticReceiptPath`);
  for (const key of ['releasePlanReceiptDigest', 'releaseProfileDigest', 'policyDigest']) {
    string(contract[key], `${label}.${key}`, SHA256);
  }
  const names = new Set();
  const workspaces = new Set();
  const expectedPaths = [contract.summaryPath, contract.semanticReceiptPath];
  for (const [index, entry] of contract.packages.entries()) {
    const entryLabel = `${label}.packages[${index}]`;
    if (entry?.requirement === 'required') {
      validateRequiredContract(entry, entryLabel);
      expectedPaths.push(entry.reportPath, entry.resultPath);
    } else {
      validateNotRequiredContract(entry, entryLabel);
    }
    if (names.has(entry.packageName) || workspaces.has(entry.workspace)) {
      fail('MUTATION_ROSTER_MISMATCH', `${label} package identities are duplicated`);
    }
    names.add(entry.packageName);
    workspaces.add(entry.workspace);
  }
  if (!Array.isArray(contract.paths)) fail('SCHEMA_INVALID', `${label}.paths must be an array`);
  for (const [index, path] of contract.paths.entries()) validatePortable(path, `${label}.paths[${index}]`);
  if (new Set(contract.paths).size !== contract.paths.length) {
    fail('MUTATION_ROSTER_MISMATCH', `${label}.paths contains duplicates`);
  }
  const actual = [...contract.paths].sort();
  const expected = [...expectedPaths].sort();
  if (actual.length !== expected.length || actual.some((path, index) => path !== expected[index])) {
    fail('MUTATION_ROSTER_MISMATCH', `${label}.paths differs from its artifact roster`);
  }
}

function evidenceEntry(contractEntry, material, enforcePassing) {
  const { disposition, origin } = material;
  const checked = validateRequiredMaterial(
    contractEntry,
    material,
    disposition,
    origin,
    enforcePassing,
  );
  const evidenceRef = {
    kind: 'mutation-package-evidence-ref-v2',
    packageName: contractEntry.packageName,
    workspace: contractEntry.workspace,
    reportPath: checked.paths.reportPath,
    resultPath: checked.paths.resultPath,
    reportDigest: checked.reportDigest,
    resultDigest: checked.resultDigest,
    inputDigest: contractEntry.inputDigest,
    provenance: disposition === 'executed' ? 'fresh' : 'reused',
    origin,
  };
  return {
    packageName: contractEntry.packageName,
    workspace: contractEntry.workspace,
    requirement: 'required',
    disposition,
    verdict: checked.complete ? (checked.passed ? 'pass' : 'fail') : 'unknown',
    passed: checked.passed,
    complete: checked.complete,
    reportPath: checked.paths.reportPath,
    resultPath: checked.paths.resultPath,
    reportDigest: checked.reportDigest,
    resultDigest: checked.resultDigest,
    inputDigest: contractEntry.inputDigest,
    evidenceRef,
    evidenceRefDigest: framedDigest(DOMAINS.evidenceRef, evidenceRef),
    thresholds: contractEntry.thresholds,
    statusTotals: checked.metrics.totals,
    targetCensus: checked.metrics.targetCensus,
    score: checked.metrics.score,
    origin,
  };
}

function notRequiredEntry(contractEntry, material) {
  if (material.disposition !== 'not-required' || material.reasonCode !== contractEntry.reasonCode) {
    fail('MUTATION_NOT_REQUIRED_MISMATCH', `${contractEntry.packageName} not-required decision differs`);
  }
  return {
    packageName: contractEntry.packageName,
    workspace: contractEntry.workspace,
    requirement: 'not-required',
    disposition: 'not-required',
    verdict: 'not-applicable',
    passed: false,
    reasonCode: contractEntry.reasonCode,
  };
}

function finalizeMutationReportSet(input, enforcePassing) {
  exact(input, ['contract', 'candidate', 'packages'], 'mutation refinalization input');
  validateMutationContractV21(input.contract);
  validateCandidate(input.candidate, 'mutation candidate');
  if (!Array.isArray(input.packages) || input.packages.length !== input.contract.packages.length) {
    fail('MUTATION_ROSTER_MISMATCH', 'mutation refinalization package roster differs');
  }

  const packages = input.contract.packages.map((contractEntry, index) => {
    const material = input.packages[index];
    object(material, `mutation refinalization packages[${index}]`);
    exact(
      material,
      contractEntry.requirement === 'required'
        ? ['disposition', 'report', 'result', 'origin']
        : ['disposition', 'reasonCode'],
      `mutation refinalization packages[${index}]`,
    );
    return contractEntry.requirement === 'required'
      ? evidenceEntry(contractEntry, material, enforcePassing)
      : notRequiredEntry(contractEntry, material);
  });
  const statusTotals = emptyTotals();
  for (const entry of packages) {
    if (entry.requirement !== 'required') continue;
    for (const status of STATUSES) {
      statusTotals[status] = checkedAdd(
        statusTotals[status],
        entry.statusTotals[status],
        `mutation aggregate.${status}`,
      );
    }
  }
  const required = packages.filter((entry) => entry.requirement === 'required');
  const detected = checkedAdd(statusTotals.Killed, statusTotals.Timeout, 'mutation aggregate detected');
  const scored = checkedAdd(
    checkedAdd(detected, statusTotals.Survived, 'mutation aggregate scored'),
    statusTotals.NoCoverage,
    'mutation aggregate scored',
  );
  const complete = required.every((entry) => entry.complete);
  const passed = required.length > 0 && complete && required.every((entry) => entry.passed);
  const verdict = required.length === 0 ? 'not-applicable' : !complete ? 'unknown' : passed ? 'pass' : 'fail';
  const score = required.length === 0 || scored === 0 ? null : (detected / scored) * 100;
  const evidenceSetDigest = framedDigest(DOMAINS.composition, packages);
  return {
    schemaVersion: MUTATION_V21_SCHEMA,
    kind: 'mutation-composed-report-set-v2',
    candidate: input.candidate,
    complete,
    verdict,
    passed,
    packages,
    aggregate: {
      packageCount: packages.length,
      executedPackageCount: packages.filter((entry) => entry.disposition === 'executed').length,
      reusedPackageCount: packages.filter((entry) => entry.disposition === 'reused').length,
      notRequiredPackageCount: packages.filter((entry) => entry.disposition === 'not-required').length,
      score,
      statusTotals,
      verdict,
      passed,
      evidenceSetDigest,
    },
  };
}

export function finalizeMutationReportSetV21(input) {
  return finalizeMutationReportSet(input, false);
}

function validateSummaryEntryIdentity(contractEntry, entry, result) {
  if (contractEntry.requirement === 'not-required') {
    if (entry?.reasonCode !== contractEntry.reasonCode) {
      fail('MUTATION_NOT_REQUIRED_MISMATCH', `${contractEntry.packageName} not-required decision differs`);
    }
    return;
  }
  const expectedInput = contractEntry.inputDigest;
  const addressPrefix = `.devai/state/mutation/v2/store/inputs/${expectedInput}/objects/`;
  if (
    result?.inputDigest !== expectedInput ||
    entry?.inputDigest !== expectedInput ||
    entry?.evidenceRef?.inputDigest !== expectedInput ||
    !contractEntry.reportPath.startsWith(addressPrefix) ||
    !contractEntry.resultPath.startsWith(addressPrefix)
  ) {
    fail('MUTATION_INPUT_DIGEST_MISMATCH', `${contractEntry.packageName} input identities differ`);
  }
}

function validateProvenance(value) {
  exact(value, ['source', 'vendor', 'byteEquality'], 'mutation verifier provenance', 'MUTATION_VENDOR_PROVENANCE_MISMATCH');
  exact(
    value.source,
    ['repository', 'commit', 'tree', 'byteSetDigest'],
    'mutation verifier source',
    'MUTATION_VENDOR_PROVENANCE_MISMATCH',
  );
  exact(
    value.vendor,
    ['root', 'manifestPath', 'manifestDigest', 'sourceCommit', 'sourceTree', 'byteSetDigest'],
    'mutation verifier vendor',
    'MUTATION_VENDOR_PROVENANCE_MISMATCH',
  );
  if (value.source.repository !== 'devai-verifier' || value.byteEquality !== true) {
    fail('MUTATION_VENDOR_PROVENANCE_MISMATCH', 'mutation verifier provenance is invalid');
  }
  for (const key of ['commit', 'tree']) string(value.source[key], `source.${key}`, GIT_OBJECT, 'MUTATION_VENDOR_PROVENANCE_MISMATCH');
  string(value.source.byteSetDigest, 'source.byteSetDigest', SHA256, 'MUTATION_VENDOR_PROVENANCE_MISMATCH');
  validatePortable(value.vendor.root, 'vendor.root', 'MUTATION_VENDOR_PROVENANCE_MISMATCH');
  validatePortable(value.vendor.manifestPath, 'vendor.manifestPath', 'MUTATION_VENDOR_PROVENANCE_MISMATCH');
  string(value.vendor.manifestDigest, 'vendor.manifestDigest', SHA256, 'MUTATION_VENDOR_PROVENANCE_MISMATCH');
  string(value.vendor.sourceCommit, 'vendor.sourceCommit', GIT_OBJECT, 'MUTATION_VENDOR_PROVENANCE_MISMATCH');
  string(value.vendor.sourceTree, 'vendor.sourceTree', GIT_OBJECT, 'MUTATION_VENDOR_PROVENANCE_MISMATCH');
  string(value.vendor.byteSetDigest, 'vendor.byteSetDigest', SHA256, 'MUTATION_VENDOR_PROVENANCE_MISMATCH');
  if (
    value.source.commit !== value.vendor.sourceCommit ||
    value.source.tree !== value.vendor.sourceTree ||
    value.source.byteSetDigest !== value.vendor.byteSetDigest ||
    !value.vendor.manifestPath.startsWith(`${value.vendor.root}/`)
  ) {
    fail('MUTATION_VENDOR_PROVENANCE_MISMATCH', 'mutation verifier source and vendor differ');
  }
}

function validateSemanticReceipt(receipt, contract, summary, options) {
  exact(
    receipt,
    [
      'schemaVersion',
      'kind',
      'receiptId',
      'candidate',
      'outputContractDigest',
      'releasePlanReceiptDigest',
      'releaseProfileDigest',
      'policyDigest',
      'verifierProvenance',
      'packages',
      'packageResultSetDigest',
      'evidenceSetDigest',
      'verdict',
      'semanticVerificationPerformed',
      'receiptDigest',
    ],
    'mutation semantic receipt',
    'MUTATION_SEMANTIC_RECEIPT_MISMATCH',
  );
  if (
    receipt.schemaVersion !== MUTATION_V21_SCHEMA ||
    receipt.kind !== 'mutation-semantic-verification-receipt-v2'
  ) {
    fail('MUTATION_VERSION_UNSUPPORTED', 'mutation semantic receipt version is unsupported');
  }
  string(receipt.receiptId, 'mutation semantic receipt.receiptId', RECEIPT_ID, 'MUTATION_SEMANTIC_RECEIPT_MISMATCH');
  validateCandidate(receipt.candidate, 'mutation semantic receipt.candidate');
  const expectedCandidate = {
    releaseUnit: options.releaseUnit,
    commit: options.candidateCommit,
    tree: options.candidateTree,
  };
  if (
    canonicalize(receipt.candidate) !== canonicalize(expectedCandidate) ||
    canonicalize(summary.candidate) !== canonicalize(expectedCandidate)
  ) {
    fail('MUTATION_SEMANTIC_RECEIPT_MISMATCH', 'mutation candidate identity differs');
  }
  for (const key of [
    'outputContractDigest',
    'releasePlanReceiptDigest',
    'releaseProfileDigest',
    'policyDigest',
    'packageResultSetDigest',
    'evidenceSetDigest',
    'receiptDigest',
  ]) {
    string(receipt[key], `mutation semantic receipt.${key}`, SHA256, 'MUTATION_SEMANTIC_RECEIPT_MISMATCH');
  }
  if (
    receipt.outputContractDigest !== framedDigest(DOMAINS.outputContract, contract) ||
    receipt.releasePlanReceiptDigest !== contract.releasePlanReceiptDigest ||
    receipt.releaseProfileDigest !== contract.releaseProfileDigest ||
    receipt.policyDigest !== contract.policyDigest ||
    receipt.evidenceSetDigest !== summary.aggregate.evidenceSetDigest ||
    receipt.verdict !== summary.verdict ||
    receipt.semanticVerificationPerformed !== true
  ) {
    fail('MUTATION_SEMANTIC_RECEIPT_MISMATCH', 'mutation semantic receipt bindings differ');
  }
  validateProvenance(receipt.verifierProvenance);
  if (!Array.isArray(receipt.packages) || receipt.packages.length !== contract.packages.length) {
    fail('MUTATION_SEMANTIC_RECEIPT_MISMATCH', 'mutation semantic receipt roster differs');
  }
  for (const [index, contractEntry] of contract.packages.entries()) {
    const receiptEntry = receipt.packages[index];
    const summaryEntry = summary.packages[index];
    const required = contractEntry.requirement === 'required';
    exact(
      receiptEntry,
      required
        ? ['packageName', 'disposition', 'inputDigest', 'reportDigest', 'resultDigest', 'compositionEntryDigest']
        : ['packageName', 'disposition', 'compositionEntryDigest'],
      `mutation semantic receipt.packages[${index}]`,
      'MUTATION_SEMANTIC_RECEIPT_MISMATCH',
    );
    if (
      receiptEntry.packageName !== contractEntry.packageName ||
      receiptEntry.disposition !== summaryEntry.disposition ||
      receiptEntry.compositionEntryDigest !== framedDigest(DOMAINS.compositionEntry, summaryEntry)
    ) {
      fail('MUTATION_SEMANTIC_RECEIPT_MISMATCH', 'mutation semantic receipt package differs');
    }
    if (required) {
      if (receiptEntry.inputDigest !== contractEntry.inputDigest) {
        fail('MUTATION_INPUT_DIGEST_MISMATCH', `${contractEntry.packageName} semantic receipt input differs`);
      }
      if (
        receiptEntry.reportDigest !== summaryEntry.reportDigest ||
        receiptEntry.resultDigest !== summaryEntry.resultDigest
      ) {
        fail('MUTATION_SEMANTIC_RECEIPT_MISMATCH', 'mutation semantic receipt artifact differs');
      }
    }
  }
  const resultSetPayload = contract.packages
    .map((entry, index) => ({ entry, summary: summary.packages[index] }))
    .filter(({ entry }) => entry.requirement === 'required')
    .map(({ entry, summary: summaryEntry }) => ({
      packageName: entry.packageName,
      resultDigest: summaryEntry.resultDigest,
    }));
  if (receipt.packageResultSetDigest !== framedDigest(DOMAINS.packageResultSet, resultSetPayload)) {
    fail('MUTATION_SEMANTIC_RECEIPT_MISMATCH', 'mutation package result set digest differs');
  }
  const { receiptDigest, ...withoutDigest } = receipt;
  if (receiptDigest !== framedDigest(DOMAINS.semanticReceipt, withoutDigest)) {
    fail('MUTATION_SEMANTIC_RECEIPT_MISMATCH', 'mutation semantic receipt digest differs');
  }
}

export function verifyMutationReportSetV21(contract, readArtifact, options = {}) {
  validateMutationContractV21(contract);
  for (const key of ['candidateCommit', 'candidateTree', 'releaseUnit']) {
    if (typeof options[key] !== 'string' || options[key].length === 0) {
      fail('MUTATION_SEMANTIC_RECEIPT_MISMATCH', `mutation ${key} expectation is missing`);
    }
  }
  const summaryFile = readArtifact(contract.summaryPath, 'mutation summary');
  const receiptFile = readArtifact(contract.semanticReceiptPath, 'mutation semantic receipt');
  const summary = summaryFile.value;
  object(summary, 'mutation summary', 'MUTATION_SUMMARY_MISMATCH');
  if (!Array.isArray(summary.packages) || summary.packages.length !== contract.packages.length) {
    fail('MUTATION_ROSTER_MISMATCH', 'mutation summary package roster differs');
  }

  const materials = [];
  for (const [index, contractEntry] of contract.packages.entries()) {
    const summaryEntry = summary.packages[index];
    if (summaryEntry?.packageName !== contractEntry.packageName || summaryEntry?.workspace !== contractEntry.workspace) {
      fail('MUTATION_ROSTER_MISMATCH', `mutation package ${index} identity differs`);
    }
    if (contractEntry.requirement === 'not-required') {
      validateSummaryEntryIdentity(contractEntry, summaryEntry);
      materials.push({ disposition: 'not-required', reasonCode: summaryEntry.reasonCode });
      continue;
    }
    const reportFile = readArtifact(contractEntry.reportPath, `mutation report ${contractEntry.packageName}`);
    const resultFile = readArtifact(contractEntry.resultPath, `mutation result ${contractEntry.packageName}`);
    validateSummaryEntryIdentity(contractEntry, summaryEntry, resultFile.value);
    materials.push({
      disposition: summaryEntry.disposition,
      origin: summaryEntry.origin,
      report: reportFile.value,
      result: resultFile.value,
    });
  }

  const expectedSummary = finalizeMutationReportSet({
    contract,
    candidate: {
      releaseUnit: options.releaseUnit,
      commit: options.candidateCommit,
      tree: options.candidateTree,
    },
    packages: materials,
  }, true);
  if (canonicalize(summary) !== canonicalize(expectedSummary)) {
    fail('MUTATION_SUMMARY_MISMATCH', 'mutation summary does not match immutable package evidence');
  }
  validateSemanticReceipt(receiptFile.value, contract, summary, options);
  return {
    packageCount: summary.aggregate.packageCount,
    executedPackageCount: summary.aggregate.executedPackageCount,
    reusedPackageCount: summary.aggregate.reusedPackageCount,
    notRequiredPackageCount: summary.aggregate.notRequiredPackageCount,
    complete: summary.complete,
    verdict: summary.verdict,
    passed: summary.passed,
    score: summary.aggregate.score,
    statusTotals: summary.aggregate.statusTotals,
    evidenceSetDigest: summary.aggregate.evidenceSetDigest,
    semanticReceiptDigest: receiptFile.value.receiptDigest,
    resultDigests: summary.packages
      .filter((entry) => entry.requirement === 'required')
      .map((entry) => entry.resultDigest),
    reportDigests: summary.packages
      .filter((entry) => entry.requirement === 'required')
      .map((entry) => entry.reportDigest),
  };
}

export { DOMAINS as MUTATION_V21_DIGEST_DOMAINS, INPUT_BINDINGS, STATUSES as MUTATION_V21_STATUSES };

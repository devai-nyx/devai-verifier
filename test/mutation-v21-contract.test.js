import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { canonicalBytes, canonicalize, sha256Hex } from '../src/canonical.js';
import { exportCandidateEvidence } from '../src/export.js';
import { validateMutationContract, verifyMutationReportSet } from '../src/mutation.js';
import { buildExpectedTaskPolicy } from '../src/policy-builder.js';
import { verifyPreparedBundle } from '../src/publish.js';
import { PAYLOAD_TYPE } from '../src/verify.js';

const temporaryDirectories = [];
const V21_SCHEMA = '2.1.0';
const INPUT_DOMAIN = 'devai:mutation-input:v2.1';
const COMPOSITION_DOMAIN = 'devai:mutation-composition:v2.1';
const SEMANTIC_RECEIPT_DOMAIN = 'devai:mutation-semantic-receipt:v2.1';
const EVIDENCE_REF_DOMAIN = 'devai:mutation-evidence-ref:v2.1';
const COMPOSITION_ENTRY_DOMAIN = 'devai:mutation-composition-entry:v2.1';
const PACKAGE_RESULT_SET_DOMAIN = 'devai:mutation-package-result-set:v2.1';
const OUTPUT_CONTRACT_DOMAIN = 'devai:mutation-output-contract:v2.1';
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
const SIGNER_ID = 'fixture-inspector';
const TRUST_ROOT_ID = 'fixture-trust-root';
const KEY_ID = 'fixture-ed25519-key';

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function temporaryDirectory(prefix) {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return directory;
}

function put(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, typeof value === 'string' ? value : `${canonicalize(value)}\n`);
}

function framedDigest(domain, value) {
  assert.equal(typeof domain, 'string');
  assert.equal(domain.includes('\0'), false);
  const bytes = canonicalBytes(value);
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  return createHash('sha256')
    .update(Buffer.from(domain, 'utf8'))
    .update(Buffer.from([0]))
    .update(length)
    .update(bytes)
    .digest('hex');
}

function zeroTotals(overrides = {}) {
  return {
    CompileError: overrides.CompileError ?? 0,
    Ignored: overrides.Ignored ?? 0,
    Killed: overrides.Killed ?? 0,
    NoCoverage: overrides.NoCoverage ?? 0,
    Pending: overrides.Pending ?? 0,
    RuntimeError: overrides.RuntimeError ?? 0,
    Survived: overrides.Survived ?? 0,
    Timeout: overrides.Timeout ?? 0,
  };
}

function aggregateMetrics(totals) {
  const detected = totals.Killed + totals.Timeout;
  const scored = detected + totals.Survived + totals.NoCoverage;
  return { score: scored === 0 ? 100 : (detected / scored) * 100 };
}

function populationBinding(seed, memberCount = 1) {
  return {
    canonicalization: 'rfc8785-jcs-utf8',
    memberCount,
    populationDigest: sha256Hex(Buffer.from(`population:${seed}`)),
    selectionRuleDigest: sha256Hex(Buffer.from(`selection:${seed}`)),
  };
}

function inputProjection(packageName, workspace, suffix = 'current') {
  return {
    schemaVersion: V21_SCHEMA,
    kind: 'mutation-input-projection-v2',
    packageName,
    workspace,
    bindings: Object.fromEntries(
      INPUT_BINDINGS.map((name) => [
        name,
        populationBinding(`${packageName}:${name}:${suffix}`),
      ]),
    ),
  };
}

function artifactPaths(inputDigest, reportDigest, resultDigest) {
  const root = `.devai/state/mutation/v2/store/inputs/${inputDigest}/objects`;
  return {
    reportPath: `${root}/${reportDigest}.report.json`,
    resultPath: `${root}/${resultDigest}.result.json`,
  };
}

function reportFor(packageName, thresholds, statuses = ['Killed']) {
  const stem = packageName.slice(packageName.indexOf('/') + 1);
  return {
    schemaVersion: V21_SCHEMA,
    kind: 'mutation-normalized-stryker-report-v2',
    strykerSchemaVersion: '1',
    projectRoot: '.',
    thresholds: { break: thresholds.break, high: thresholds.high, low: thresholds.low },
    files: {
      [`src/${stem}.ts`]: {
        language: 'typescript',
        mutants: statuses.map((status, index) => ({
          id: String(index),
          mutatorName: 'ConditionalExpression',
          replacementDigest: sha256Hex(Buffer.from(`replacement:${index}`)),
          location: {
            start: { line: index + 1, column: 1 },
            end: { line: index + 1, column: 2 },
          },
          status,
        })),
      },
    },
    testFiles: {},
    config: {},
    framework: { name: 'StrykerJS' },
  };
}

function evidencePackage({
  packageName,
  workspace,
  disposition,
  candidate,
  statuses = ['Killed'],
}) {
  const thresholds = { break: 90, high: 100, low: 90, scoreMin: 90, survivedMax: 0 };
  const projection = inputProjection(packageName, workspace);
  const inputDigest = framedDigest(INPUT_DOMAIN, projection);
  const report = reportFor(packageName, thresholds, statuses);
  const statusTotals = zeroTotals(
    Object.fromEntries(statuses.map((status) => [status, statuses.filter((item) => item === status).length])),
  );
  const score = aggregateMetrics(statusTotals).score;
  const complete = statusTotals.Pending === 0;
  const passed =
    complete &&
    statusTotals.RuntimeError === 0 &&
    score >= Math.max(thresholds.break, thresholds.scoreMin) &&
    statusTotals.Survived <= thresholds.survivedMax;
  const process = { errorAbsent: true, signal: null, status: 0 };
  const reportDigest = sha256Hex(canonicalBytes(report));
  const result = {
    schemaVersion: V21_SCHEMA,
    kind: 'mutation-package-result-v2',
    packageName,
    workspace,
    inputProjection: projection,
    inputDigest,
    reportDigest,
    toolVersions: { stryker: '9.6.1', sanitizer: '2.1.0' },
    process,
    thresholds,
    statusTotals,
    targetCensus: { targetFileCount: 1, totalMutants: statuses.length },
    score,
    complete,
    passed,
  };
  const resultDigest = sha256Hex(canonicalBytes(result));
  const paths = artifactPaths(inputDigest, reportDigest, resultDigest);
  const origin =
    disposition === 'executed'
      ? null
      : {
          candidate: {
            releaseUnit: candidate.releaseUnit,
            commit: '9'.repeat(40),
            tree: '8'.repeat(40),
          },
          semanticReceiptDigest: '7'.repeat(64),
          evidenceSetDigest: '6'.repeat(64),
        };
  const evidenceRef = {
    kind: 'mutation-package-evidence-ref-v2',
    packageName,
    workspace,
    reportPath: paths.reportPath,
    resultPath: paths.resultPath,
    reportDigest,
    resultDigest,
    inputDigest,
    provenance: disposition === 'executed' ? 'fresh' : 'reused',
    origin,
  };
  const evidenceRefDigest = framedDigest(EVIDENCE_REF_DOMAIN, evidenceRef);
  const entry = {
    packageName,
    workspace,
    requirement: 'required',
    disposition,
    verdict: passed ? 'pass' : complete ? 'fail' : 'unknown',
    passed,
    complete,
    reportPath: paths.reportPath,
    resultPath: paths.resultPath,
    reportDigest,
    resultDigest,
    inputDigest,
    evidenceRef,
    evidenceRefDigest,
    thresholds,
    statusTotals,
    targetCensus: result.targetCensus,
    score,
    origin,
  };
  const contract = {
    packageName,
    workspace,
    requirement: 'required',
    inputProjection: projection,
    inputDigest,
    reportPath: paths.reportPath,
    resultPath: paths.resultPath,
    thresholds,
  };
  return { contract, entry, report, result, candidate };
}

function notRequiredPackage(packageName, workspace, reasonCode = 'no-mutatable-production-surface') {
  return {
    contract: { packageName, workspace, requirement: 'not-required', reasonCode },
    entry: {
      packageName,
      workspace,
      requirement: 'not-required',
      disposition: 'not-required',
      verdict: 'not-applicable',
      passed: false,
      reasonCode,
    },
  };
}

function mutationV21Fixture({ dispositions = ['executed', 'reused', 'not-required'] } = {}) {
  const artifactsDir = temporaryDirectory('devai-mutation-v21-');
  const candidate = {
    releaseUnit: 'fixture/repository',
    commit: 'a'.repeat(40),
    tree: 'b'.repeat(40),
  };
  const packages = dispositions.map((disposition, index) => {
    const packageName = `@fixture/package-${index}`;
    const workspace = `packages/package-${index}`;
    return disposition === 'not-required'
      ? notRequiredPackage(packageName, workspace)
      : evidencePackage({ packageName, workspace, disposition, candidate });
  });
  const contract = {
    schemaVersion: V21_SCHEMA,
    kind: 'mutation-report-set-v2',
    expectedPackageCount: packages.length,
    summaryPath: 'mutation/summary.json',
    semanticReceiptPath: 'mutation/semantic-receipt.json',
    releasePlanReceiptDigest: 'c'.repeat(64),
    releaseProfileDigest: 'd'.repeat(64),
    policyDigest: 'e'.repeat(64),
    packages: packages.map((entry) => entry.contract),
    paths: [
      'mutation/summary.json',
      'mutation/semantic-receipt.json',
      ...packages.flatMap((entry) =>
        entry.contract.requirement === 'required'
          ? [entry.contract.reportPath, entry.contract.resultPath]
          : [],
      ),
    ],
  };

  const state = { artifactsDir, candidate, contract, packages };
  state.reseal = ({ retargetPaths = true } = {}) => {
    for (const item of state.packages) {
      if (item.contract.requirement !== 'required') continue;
      item.entry.reportDigest = sha256Hex(canonicalBytes(item.report));
      item.result.reportDigest = item.entry.reportDigest;
      item.entry.resultDigest = sha256Hex(canonicalBytes(item.result));
      if (retargetPaths) {
        const paths = artifactPaths(
          item.contract.inputDigest,
          item.entry.reportDigest,
          item.entry.resultDigest,
        );
        Object.assign(item.contract, paths);
        Object.assign(item.entry, paths);
        Object.assign(item.entry.evidenceRef, paths);
      }
      Object.assign(item.entry.evidenceRef, {
        reportPath: item.entry.reportPath,
        resultPath: item.entry.resultPath,
        reportDigest: item.entry.reportDigest,
        resultDigest: item.entry.resultDigest,
      });
      item.entry.evidenceRefDigest = framedDigest(EVIDENCE_REF_DOMAIN, item.entry.evidenceRef);
    }
    const evidenceEntries = state.packages.filter(
      (entry) => entry.contract.requirement === 'required',
    );
    const aggregateTotals = zeroTotals();
    for (const item of evidenceEntries) {
      for (const status of Object.keys(aggregateTotals)) {
        aggregateTotals[status] += item.entry.statusTotals[status];
      }
    }
    const executed = state.packages.filter((item) => item.entry.disposition === 'executed');
    const reused = state.packages.filter((item) => item.entry.disposition === 'reused');
    const notRequired = state.packages.filter(
      (item) => item.entry.disposition === 'not-required',
    );
    const requiredPassed = evidenceEntries.every((item) => item.entry.passed);
    const allNotRequired = evidenceEntries.length === 0;
    const complete = evidenceEntries.every((item) => item.entry.complete);
    const passed = !allNotRequired && complete && requiredPassed;
    const verdict = allNotRequired
      ? 'not-applicable'
      : passed
        ? 'pass'
        : complete
          ? 'fail'
          : 'unknown';
    state.summary = {
      schemaVersion: V21_SCHEMA,
      kind: 'mutation-composed-report-set-v2',
      candidate: state.candidate,
      complete,
      verdict,
      passed,
      packages: state.packages.map((item) => item.entry),
      aggregate: {
        packageCount: state.packages.length,
        executedPackageCount: executed.length,
        reusedPackageCount: reused.length,
        notRequiredPackageCount: notRequired.length,
        score: allNotRequired ? null : aggregateMetrics(aggregateTotals).score,
        statusTotals: aggregateTotals,
        verdict,
        passed,
        evidenceSetDigest: framedDigest(
          COMPOSITION_DOMAIN,
          state.packages.map((item) => item.entry),
        ),
      },
    };
    state.contract.paths = [
      state.contract.summaryPath,
      state.contract.semanticReceiptPath,
      ...state.packages.flatMap((entry) =>
        entry.contract.requirement === 'required'
          ? [entry.contract.reportPath, entry.contract.resultPath]
          : [],
      ),
    ];
    const receiptWithoutDigest = {
      schemaVersion: V21_SCHEMA,
      kind: 'mutation-semantic-verification-receipt-v2',
      receiptId: `MSV2-${'1'.repeat(16)}`,
      candidate: state.candidate,
      outputContractDigest: framedDigest(OUTPUT_CONTRACT_DOMAIN, state.contract),
      releasePlanReceiptDigest: state.contract.releasePlanReceiptDigest,
      releaseProfileDigest: state.contract.releaseProfileDigest,
      policyDigest: state.contract.policyDigest,
      verifierProvenance: {
        source: {
          repository: 'devai-verifier',
          commit: 'fcefd0ad9b1210f5d460509f801a16fc3c4dcbd1',
          tree: 'ad06a07074428af47e2fd33ad1115efc7b1feb1e',
          byteSetDigest: '5'.repeat(64),
        },
        vendor: {
          root: 'vendor/devai-verifier',
          manifestPath: 'vendor/devai-verifier/provenance.json',
          manifestDigest: '4'.repeat(64),
          sourceCommit: 'fcefd0ad9b1210f5d460509f801a16fc3c4dcbd1',
          sourceTree: 'ad06a07074428af47e2fd33ad1115efc7b1feb1e',
          byteSetDigest: '5'.repeat(64),
        },
        byteEquality: true,
      },
      packages: state.packages.map((item) => ({
        packageName: item.entry.packageName,
        disposition: item.entry.disposition,
        ...(item.contract.requirement === 'required' && { inputDigest: item.entry.inputDigest }),
        ...(item.contract.requirement === 'required' && {
          reportDigest: item.entry.reportDigest,
          resultDigest: item.entry.resultDigest,
        }),
        compositionEntryDigest: framedDigest(COMPOSITION_ENTRY_DOMAIN, item.entry),
      })),
      packageResultSetDigest: framedDigest(
        PACKAGE_RESULT_SET_DOMAIN,
        state.packages
          .filter((item) => item.contract.requirement === 'required')
          .map((item) => ({
            packageName: item.entry.packageName,
            resultDigest: item.entry.resultDigest,
          })),
      ),
      evidenceSetDigest: state.summary.aggregate.evidenceSetDigest,
      verdict,
      semanticVerificationPerformed: true,
    };
    state.semanticReceipt = {
      ...receiptWithoutDigest,
      receiptDigest: framedDigest(SEMANTIC_RECEIPT_DOMAIN, receiptWithoutDigest),
    };
  };
  state.write = () => {
    rmSync(state.artifactsDir, { recursive: true, force: true });
    mkdirSync(state.artifactsDir, { recursive: true });
    for (const item of state.packages) {
      if (item.contract.requirement !== 'required') continue;
      put(join(state.artifactsDir, item.entry.reportPath), item.report);
      put(join(state.artifactsDir, item.entry.resultPath), item.result);
    }
    put(join(state.artifactsDir, state.contract.summaryPath), state.summary);
    put(join(state.artifactsDir, state.contract.semanticReceiptPath), state.semanticReceipt);
  };
  state.reseal();
  state.write();
  return state;
}

function verifyV21(state, options = {}) {
  return verifyMutationReportSet(state.contract, state.artifactsDir, {
    candidateCommit: state.candidate.commit,
    candidateTree: state.candidate.tree,
    releaseUnit: state.candidate.releaseUnit,
    mutationVerificationMode: 'offline',
    ...options,
  });
}

function trustedReuseResolution(item) {
  const packages = [structuredClone(item.entry)];
  const origin = item.entry.origin;
  const evidenceSetDigest = framedDigest(COMPOSITION_DOMAIN, packages);
  const composition = {
    schemaVersion: V21_SCHEMA,
    kind: 'mutation-composed-report-set-v2',
    candidate: origin.candidate,
    complete: true,
    verdict: 'pass',
    passed: true,
    packages,
    aggregate: {
      packageCount: 1,
      executedPackageCount: 0,
      reusedPackageCount: 1,
      notRequiredPackageCount: 0,
      score: item.entry.score,
      statusTotals: item.entry.statusTotals,
      verdict: 'pass',
      passed: true,
      evidenceSetDigest,
    },
  };
  const receiptWithoutDigest = {
    schemaVersion: V21_SCHEMA,
    kind: 'mutation-semantic-verification-receipt-v2',
    receiptId: `MSV2-${'2'.repeat(16)}`,
    candidate: origin.candidate,
    outputContractDigest: 'a'.repeat(64),
    releasePlanReceiptDigest: 'b'.repeat(64),
    releaseProfileDigest: 'c'.repeat(64),
    policyDigest: 'd'.repeat(64),
    verifierProvenance: {
      source: {
        repository: 'devai-verifier',
        commit: 'fcefd0ad9b1210f5d460509f801a16fc3c4dcbd1',
        tree: 'ad06a07074428af47e2fd33ad1115efc7b1feb1e',
        byteSetDigest: 'e'.repeat(64),
      },
      vendor: {
        root: 'vendor/devai-verifier',
        manifestPath: 'vendor/devai-verifier/provenance.json',
        manifestDigest: 'f'.repeat(64),
        sourceCommit: 'fcefd0ad9b1210f5d460509f801a16fc3c4dcbd1',
        sourceTree: 'ad06a07074428af47e2fd33ad1115efc7b1feb1e',
        byteSetDigest: 'e'.repeat(64),
      },
      byteEquality: true,
    },
    packages: [
      {
        packageName: item.entry.packageName,
        disposition: 'reused',
        inputDigest: item.entry.inputDigest,
        reportDigest: item.entry.reportDigest,
        resultDigest: item.entry.resultDigest,
        compositionEntryDigest: framedDigest(COMPOSITION_ENTRY_DOMAIN, packages[0]),
      },
    ],
    packageResultSetDigest: framedDigest(PACKAGE_RESULT_SET_DOMAIN, [
      { packageName: item.entry.packageName, resultDigest: item.entry.resultDigest },
    ]),
    evidenceSetDigest,
    verdict: 'pass',
    semanticVerificationPerformed: true,
  };
  const semanticReceipt = {
    ...receiptWithoutDigest,
    receiptDigest: framedDigest(SEMANTIC_RECEIPT_DOMAIN, receiptWithoutDigest),
  };
  origin.evidenceSetDigest = evidenceSetDigest;
  origin.semanticReceiptDigest = semanticReceipt.receiptDigest;
  return { composition, semanticReceipt };
}

function retargetInputIdentity(state, item, projection) {
  const inputDigest = framedDigest(INPUT_DOMAIN, projection);
  Object.assign(item.contract, {
    inputProjection: projection,
    inputDigest,
  });
  Object.assign(item.result, { inputProjection: projection, inputDigest });
  Object.assign(item.entry, { inputDigest });
  Object.assign(item.entry.evidenceRef, { inputDigest });
  state.reseal();
  state.write();
}

function expectCode(code, action) {
  try {
    action();
    assert.fail(`expected ${code}`);
  } catch (error) {
    assert.equal(error?.code, code, `expected ${code}, got ${String(error?.code)}`);
  }
}

function expectedVerification(state) {
  return {
    packageCount: state.summary.aggregate.packageCount,
    executedPackageCount: state.summary.aggregate.executedPackageCount,
    reusedPackageCount: state.summary.aggregate.reusedPackageCount,
    notRequiredPackageCount: state.summary.aggregate.notRequiredPackageCount,
    complete: state.summary.complete,
    verdict: state.summary.verdict,
    passed: state.summary.passed,
    score: state.summary.aggregate.score,
    statusTotals: state.summary.aggregate.statusTotals,
    evidenceSetDigest: state.summary.aggregate.evidenceSetDigest,
  };
}

function assertVerification(actual, state) {
  const expected = expectedVerification(state);
  assert.deepEqual(
    Object.fromEntries(Object.keys(expected).map((key) => [key, actual[key]])),
    expected,
  );
}

describe('mutation report-set v2.1 immutable contract', () => {
  it('preserves executed, reused, and not-required as three explicit dispositions', () => {
    const state = mutationV21Fixture();
    assertVerification(verifyV21(state), state);
  });

  it('denies reused evidence during certify unless a protected resolver supplies its origin', () => {
    const state = mutationV21Fixture({ dispositions: ['reused'] });
    expectCode('MUTATION_REUSE_DENIED', () =>
      verifyV21(state, { mutationVerificationMode: 'certify' }),
    );
    expectCode('MUTATION_REUSE_DENIED', () =>
      verifyV21(state, {
        mutationVerificationMode: 'certify',
        resolveReuseOrigin: () => ({}),
      }),
    );

    const resolved = mutationV21Fixture({ dispositions: ['reused'] });
    const resolution = trustedReuseResolution(resolved.packages[0]);
    resolved.reseal();
    resolved.write();
    assertVerification(
      verifyV21(resolved, {
        mutationVerificationMode: 'certify',
        resolveReuseOrigin: () => resolution,
      }),
      resolved,
    );
    resolution.composition.packages[0].resultDigest = '0'.repeat(64);
    expectCode('MUTATION_REUSE_DENIED', () =>
      verifyV21(resolved, {
        mutationVerificationMode: 'certify',
        resolveReuseOrigin: () => resolution,
      }),
    );
  });

  it('keeps an all-not-required composition distinct from pass', () => {
    const state = mutationV21Fixture({ dispositions: ['not-required', 'not-required'] });
    assert.equal(state.summary.passed, false);
    assert.equal(state.summary.aggregate.score, null);
    assertVerification(verifyV21(state), state);
  });

  it('does not accept a self-asserted not-required reason that differs from the output contract', () => {
    const state = mutationV21Fixture({ dispositions: ['not-required'] });
    state.contract.packages[0].reasonCode = 'package-excluded-by-approved-release-profile';
    state.reseal();
    state.write();
    expectCode('MUTATION_NOT_REQUIRED_MISMATCH', () => verifyV21(state));
  });

  it('refuses Pending as incomplete even when its arithmetic score would be 100', () => {
    const state = mutationV21Fixture({ dispositions: ['executed'] });
    const item = state.packages[0];
    item.report = reportFor(item.contract.packageName, item.contract.thresholds, ['Pending']);
    item.result.statusTotals = zeroTotals({ Pending: 1 });
    item.result.targetCensus.totalMutants = 1;
    item.result.score = 100;
    item.result.complete = false;
    item.result.passed = false;
    Object.assign(item.entry, {
      statusTotals: item.result.statusTotals,
      targetCensus: item.result.targetCensus,
      score: 100,
      complete: false,
      passed: false,
      verdict: 'unknown',
    });
    state.reseal();
    state.write();
    expectCode('MUTATION_INCOMPLETE', () => verifyV21(state));
  });

  it('refuses RuntimeError while preserving CompileError and Ignored as non-scored', () => {
    const accepted = mutationV21Fixture({ dispositions: ['executed'] });
    const acceptedItem = accepted.packages[0];
    acceptedItem.report = reportFor(acceptedItem.contract.packageName, acceptedItem.contract.thresholds, [
      'Killed',
      'CompileError',
      'Ignored',
    ]);
    acceptedItem.result.statusTotals = zeroTotals({ Killed: 1, CompileError: 1, Ignored: 1 });
    acceptedItem.result.targetCensus.totalMutants = 3;
    acceptedItem.entry.statusTotals = acceptedItem.result.statusTotals;
    acceptedItem.entry.targetCensus = acceptedItem.result.targetCensus;
    accepted.reseal();
    accepted.write();
    assertVerification(verifyV21(accepted), accepted);

    const rejected = mutationV21Fixture({ dispositions: ['executed'] });
    const rejectedItem = rejected.packages[0];
    rejectedItem.report = reportFor(rejectedItem.contract.packageName, rejectedItem.contract.thresholds, [
      'Killed',
      'RuntimeError',
    ]);
    rejectedItem.result.statusTotals = zeroTotals({ Killed: 1, RuntimeError: 1 });
    rejectedItem.result.targetCensus.totalMutants = 2;
    rejectedItem.result.score = 100;
    rejectedItem.result.passed = false;
    Object.assign(rejectedItem.entry, {
      statusTotals: rejectedItem.result.statusTotals,
      targetCensus: rejectedItem.result.targetCensus,
      score: 100,
      passed: false,
      verdict: 'fail',
    });
    rejected.reseal();
    rejected.write();
    expectCode('MUTATION_RUNTIME_FAILURE', () => verifyV21(rejected));
  });

  it('requires at least one recorded tool version in immutable package evidence', () => {
    const state = mutationV21Fixture({ dispositions: ['executed'] });
    state.packages[0].result.toolVersions = {};
    state.reseal();
    state.write();
    expectCode('MUTATION_REPORT_INVALID', () => verifyV21(state));
  });

  it('recomputes the framed input digest instead of accepting a consistent self-assertion', () => {
    const state = mutationV21Fixture({ dispositions: ['reused'] });
    const item = state.packages[0];
    const falseDigest = 'e'.repeat(64);
    item.contract.inputDigest = falseDigest;
    item.result.inputDigest = falseDigest;
    item.entry.inputDigest = falseDigest;
    item.entry.evidenceRef.inputDigest = falseDigest;
    state.reseal();
    state.write();
    expectCode('MUTATION_INPUT_DIGEST_MISMATCH', () => verifyV21(state));
  });

  it('requires every canonical input population in the recomputed digest projection', () => {
    for (const omitted of INPUT_BINDINGS) {
      const state = mutationV21Fixture({ dispositions: ['reused'] });
      const item = state.packages[0];
      const projection = structuredClone(item.contract.inputProjection);
      delete projection.bindings[omitted];
      retargetInputIdentity(state, item, projection);
      expectCode('MUTATION_INPUT_IDENTITY_MISSING', () => verifyV21(state));
    }
  });

  it('requires contract, result, address, reference, entry, and semantic receipt input identity equality', () => {
    const attacks = [
      { mutate: (item) => (item.result.inputDigest = '1'.repeat(64)) },
      {
        mutate: (item) => {
          const paths = artifactPaths(
            '2'.repeat(64),
            item.entry.reportDigest,
            item.entry.resultDigest,
          );
          Object.assign(item.contract, paths);
          Object.assign(item.entry, paths);
          Object.assign(item.entry.evidenceRef, paths);
        },
        retargetPaths: false,
      },
      { mutate: (item) => (item.entry.evidenceRef.inputDigest = '3'.repeat(64)) },
      { mutate: (item) => (item.entry.inputDigest = '4'.repeat(64)) },
    ];
    for (const attack of attacks) {
      const state = mutationV21Fixture({ dispositions: ['reused'] });
      attack.mutate(state.packages[0]);
      state.reseal({ retargetPaths: attack.retargetPaths ?? true });
      state.write();
      expectCode('MUTATION_INPUT_DIGEST_MISMATCH', () => verifyV21(state));
    }

    const receiptAttack = mutationV21Fixture({ dispositions: ['reused'] });
    receiptAttack.semanticReceipt.packages[0].inputDigest = '5'.repeat(64);
    const { receiptDigest: _, ...receiptWithoutDigest } = receiptAttack.semanticReceipt;
    receiptAttack.semanticReceipt.receiptDigest = framedDigest(
      SEMANTIC_RECEIPT_DOMAIN,
      receiptWithoutDigest,
    );
    receiptAttack.write();
    expectCode('MUTATION_INPUT_DIGEST_MISMATCH', () => verifyV21(receiptAttack));
  });

  it('denies v1 package evidence as a v2.1 reuse source', () => {
    const state = mutationV21Fixture({ dispositions: ['reused'] });
    const item = state.packages[0];
    item.result.schemaVersion = '1.0.0';
    item.result.kind = 'mutation-package-result-v1';
    state.reseal();
    state.write();
    expectCode('MUTATION_REUSE_DENIED', () => verifyV21(state));
  });

  it('reserves every mutation-* spelling instead of falling through to a generic contract', () => {
    for (const kind of [
      'mutation-report-set-next',
      'mutation-report-set-v3',
      'mutation-composed-report-set-vnext',
      'mutation-opaque-artifact',
    ]) {
      const state = mutationV21Fixture({ dispositions: ['executed'] });
      state.contract.kind = kind;
      expectCode('MUTATION_VERSION_UNSUPPORTED', () =>
        validateMutationContract(state.contract, 'mutation output contract'),
      );
    }
  });
});

function git(repo, args) {
  return execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim();
}

function v1ExportFixture() {
  const root = temporaryDirectory('devai-mutation-v1-export-');
  const repo = join(root, 'candidate');
  mkdirSync(repo);
  git(repo, ['init', '--quiet', '-b', 'main']);
  git(repo, ['config', 'user.name', 'Verifier Contract Test']);
  git(repo, ['config', 'user.email', 'verifier@example.invalid']);
  const thresholds = { break: 50, high: 90, low: 80 };
  const packageName = '@fixture/core';
  const workspace = 'packages/core';
  const summaryPath = 'mutation/summary.json';
  const reportPath = 'mutation/core.stryker.json';
  const resultPath = 'mutation/core.result.json';
  const contract = {
    kind: 'mutation-report-set-v1',
    expectedPackageCount: 1,
    summaryPath,
    packages: [{ packageName, workspace, reportPath, resultPath, thresholds }],
    paths: [summaryPath, reportPath, resultPath],
  };
  const descriptor = {
    schemaVersion: '1.0.0',
    descriptorVersion: 'fixture-v1-export',
    repositoryId: 'fixture/repository',
    fallbackNodeId: null,
    dynamicFallbackSelectors: [],
    tasks: [
      {
        nodeId: 'test:mutation',
        dependencies: [],
        argv: ['node', '--test'],
        cwd: '.',
        runner: 'node-test-v1',
        inputSelectors: [{ kind: 'exact', pattern: 'input.txt' }],
        toolchainKeys: ['node'],
        allowlistedEnv: [],
        outputContract: contract,
      },
    ],
    profiles: [{ profileId: 'rc', mode: 'fixed', requiredNodes: ['test:mutation'] }],
  };
  put(join(repo, 'input.txt'), 'input\n');
  put(join(repo, '.gitignore'), 'mutation/\n');
  put(join(repo, 'test-tasks.json'), `${JSON.stringify(descriptor, null, 2)}\n`);
  git(repo, ['add', '-A']);
  git(repo, ['commit', '--quiet', '-m', 'candidate']);
  const commit = git(repo, ['rev-parse', 'HEAD']);
  const tree = git(repo, ['rev-parse', 'HEAD^{tree}']);
  const report = reportFor(packageName, thresholds, ['Killed']);
  const reportDigest = sha256Hex(canonicalBytes(report));
  const packageResult = {
    schemaVersion: '1.0.0',
    kind: 'mutation-package-result-v1',
    packageName,
    workspace,
    passed: true,
    durationMs: 1,
    toolVersions: { stryker: '9.6.1' },
    thresholds,
    score: 100,
    statusTotals: zeroTotals({ Killed: 1 }),
    reportDigest,
  };
  const resultDigest = sha256Hex(canonicalBytes(packageResult));
  const summary = {
    schemaVersion: '1.0.0',
    kind: 'mutation-report-set-v1',
    complete: true,
    passed: true,
    packages: [
      {
        packageName,
        workspace,
        resultPath,
        reportPath,
        resultDigest,
        reportDigest,
        score: 100,
        passed: true,
      },
    ],
    aggregate: {
      packageCount: 1,
      durationMs: 1,
      score: 100,
      statusTotals: zeroTotals({ Killed: 1 }),
    },
  };
  for (const [path, value] of [
    [reportPath, report],
    [resultPath, packageResult],
    [summaryPath, summary],
  ]) {
    put(join(repo, path), value);
  }
  const toolchainPath = join(root, 'toolchain.json');
  const environmentPath = join(root, 'environment.json');
  put(toolchainPath, { node: 'v24.15.0' });
  put(environmentPath, {});
  const built = buildExpectedTaskPolicy({
    repo,
    descriptor,
    profileId: 'rc',
    candidateCommit: commit,
    expectedTree: tree,
    toolchain: { node: 'v24.15.0' },
    environment: {},
    policySchemaVersion: '1.1.0',
  });
  const taskResult = {
    schemaVersion: '1.0.0',
    nodeId: 'test:mutation',
    taskKey: built.taskPolicy.requiredNodes[0].taskKey,
    status: 'PASS',
    inputDigest: '6'.repeat(64),
    dependencyResultDigests: {},
    outputDigests: {
      stdout: '7'.repeat(64),
      stderr: '8'.repeat(64),
      ...Object.fromEntries(
        contract.paths.map((path) => [path, sha256Hex(readFileSync(join(repo, path)))]),
      ),
    },
    startedAt: '2026-09-03T00:00:00.000Z',
    finishedAt: '2026-09-03T00:00:01.000Z',
  };
  const taskResultDigest = sha256Hex(taskResult);
  const resultsDir = join(root, 'results');
  put(join(resultsDir, `${taskResultDigest}.json`), taskResult);
  const receiptPath = join(root, 'receipt.json');
  put(receiptPath, {
    schemaVersion: '1.1.0',
    repository: { id: 'fixture/repository', commit, tree },
    profile: 'rc',
    taskPolicyDigest: built.taskPolicyDigest,
    createdAt: '2026-09-03T00:00:02.000Z',
    tasks: [
      { nodeId: 'test:mutation', taskKey: taskResult.taskKey, resultDigest: taskResultDigest },
    ],
  });
  const keys = generateKeyPairSync('ed25519');
  const privateKeyPath = join(root, 'private.pem');
  const publicKeyPath = join(root, 'public.pem');
  put(
    privateKeyPath,
    keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  );
  put(
    publicKeyPath,
    keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  );
  return {
    repo,
    commit,
    tree,
    receiptPath,
    resultsDir,
    toolchainPath,
    environmentPath,
    privateKeyPath,
    publicKeyPath,
    outputDir: join(root, 'exported'),
  };
}

describe('mutation v1 write boundary', () => {
  it('keeps v1 readable but refuses to export it as new evidence', () => {
    const state = v1ExportFixture();
    expectCode('MUTATION_VERSION_UNSUPPORTED', () =>
      exportCandidateEvidence({
        repo: state.repo,
        receiptPath: state.receiptPath,
        resultsDir: state.resultsDir,
        profile: 'rc',
        commit: state.commit,
        tree: state.tree,
        toolchainPath: state.toolchainPath,
        environmentPath: state.environmentPath,
        privateKeyPath: state.privateKeyPath,
        publicKeyPath: state.publicKeyPath,
        signerId: SIGNER_ID,
        outputDir: state.outputDir,
      }),
    );
  });
});

function preparedV21Bundle() {
  const root = temporaryDirectory('devai-mutation-v21-bundle-');
  const bundleDir = join(root, 'bundle');
  const state = mutationV21Fixture({ dispositions: ['executed', 'reused', 'not-required'] });
  const keys = generateKeyPairSync('ed25519');
  const trustStore = {
    schemaVersion: '1.1.0',
    trustRootId: TRUST_ROOT_ID,
    trustedSigners: [
      {
        signerId: SIGNER_ID,
        keyId: KEY_ID,
        publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      },
    ],
    revokedSignerIds: [],
    revokedKeyIds: [],
  };
  const trustStorePath = join(root, 'trust.json');
  put(trustStorePath, trustStore);
  const taskKey = sha256Hex(Buffer.from('task:mutation-v21'));
  const taskPolicy = {
    schemaVersion: '1.1.0',
    repositoryId: state.candidate.releaseUnit,
    requiredNodes: [
      {
        nodeId: 'test:mutation',
        taskKey,
        dependencies: [],
        outputContract: state.contract,
      },
    ],
  };
  const taskPolicyDigest = sha256Hex(taskPolicy);
  const outputDigests = {
    stdout: sha256Hex(Buffer.from('')),
    stderr: sha256Hex(Buffer.from('')),
  };
  const artifacts = [];
  for (const path of state.contract.paths) {
    const source = join(state.artifactsDir, path);
    const bytes = readFileSync(source);
    put(join(bundleDir, 'artifacts', path), bytes.toString('utf8'));
    outputDigests[path] = sha256Hex(bytes);
    artifacts.push({ path, mediaType: 'application/json', sha256: sha256Hex(bytes) });
  }
  const taskResult = {
    schemaVersion: '1.0.0',
    nodeId: 'test:mutation',
    taskKey,
    status: 'PASS',
    inputDigest: sha256Hex(Buffer.from('task-input')),
    dependencyResultDigests: {},
    outputDigests,
    startedAt: '2026-09-03T00:00:00.000Z',
    finishedAt: '2026-09-03T00:00:01.000Z',
  };
  const resultDigest = sha256Hex(taskResult);
  put(join(bundleDir, 'results', `${resultDigest}.json`), taskResult);
  const receipt = {
    schemaVersion: '1.1.0',
    repository: {
      id: state.candidate.releaseUnit,
      commit: state.candidate.commit,
      tree: state.candidate.tree,
    },
    profile: 'rc',
    taskPolicyDigest,
    createdAt: '2026-09-03T00:00:02.000Z',
    tasks: [{ nodeId: 'test:mutation', taskKey, resultDigest }],
  };
  const payload = canonicalBytes(receipt);
  const envelope = {
    schemaVersion: '1.0.0',
    payloadType: PAYLOAD_TYPE,
    payload: payload.toString('base64'),
    signatures: [
      {
        signerId: SIGNER_ID,
        signature: sign(null, payload, keys.privateKey).toString('base64'),
      },
    ],
  };
  put(join(bundleDir, 'envelope.json'), envelope);
  put(join(bundleDir, 'task-policy.json'), taskPolicy);
  put(join(bundleDir, 'manifest.json'), {
    schemaVersion: '1.1.0',
    repositoryId: state.candidate.releaseUnit,
    commit: state.candidate.commit,
    tree: state.candidate.tree,
    profile: 'rc',
    signerId: SIGNER_ID,
    taskPolicyDigest,
    envelopeDigest: sha256Hex(envelope),
    resultDigests: [resultDigest],
    artifacts,
  });
  const expected = {
    expectedRepository: state.candidate.releaseUnit,
    expectedCommit: state.candidate.commit,
    expectedTree: state.candidate.tree,
    expectedPolicyDigest: taskPolicyDigest,
    expectedSignerId: SIGNER_ID,
    expectedTrustRootId: TRUST_ROOT_ID,
    expectedTrustStoreDigest: sha256Hex(trustStore),
    expectedKeyId: KEY_ID,
  };
  return { root, bundleDir, trustStorePath, trustStore, state, expected, resultDigest };
}

describe('mutation v2.1 offline closure', () => {
  it('verifies from only the closed bundle, external trust store, and exact expected identities', () => {
    const fixture = preparedV21Bundle();
    const result = verifyPreparedBundle({
      bundleDir: fixture.bundleDir,
      trustStorePath: fixture.trustStorePath,
      ...fixture.expected,
    });
    assert.equal(result.verified.verifiedMutation[0].nodeId, 'test:mutation');
    assertVerification(result.verified.verifiedMutation[0], fixture.state);
  });

  it('refuses every missing external identity before trusting bundle-provided defaults', () => {
    const keys = [
      'expectedRepository',
      'expectedCommit',
      'expectedTree',
      'expectedPolicyDigest',
      'expectedSignerId',
      'expectedTrustRootId',
      'expectedTrustStoreDigest',
      'expectedKeyId',
    ];
    for (const key of keys) {
      const fixture = preparedV21Bundle();
      const expected = { ...fixture.expected };
      delete expected[key];
      expectCode('MUTATION_OFFLINE_EXPECTATION_MISSING', () =>
        verifyPreparedBundle({
          bundleDir: fixture.bundleDir,
          trustStorePath: fixture.trustStorePath,
          ...expected,
        }),
      );
    }
  });

  it(
    'refuses a symlinked bundle root rather than canonicalizing it before verification',
    { skip: process.platform === 'win32' },
    () => {
      const fixture = preparedV21Bundle();
      const linkedBundle = join(temporaryDirectory('devai-mutation-v21-bundle-link-'), 'bundle');
      symlinkSync(fixture.bundleDir, linkedBundle, 'dir');
      expectCode('ARTIFACT_SYMLINK_ESCAPE', () =>
        verifyPreparedBundle({
          bundleDir: linkedBundle,
          trustStorePath: fixture.trustStorePath,
          ...fixture.expected,
        }),
      );
    },
  );

  it('requires signed receipt, manifest, and supplied task-result populations to be identical', () => {
    const fixture = preparedV21Bundle();
    const extraResult = {
      schemaVersion: '1.0.0',
      nodeId: 'test:extra',
      taskKey: '1'.repeat(64),
      status: 'PASS',
      inputDigest: '2'.repeat(64),
      dependencyResultDigests: {},
      outputDigests: { stdout: '3'.repeat(64), stderr: '4'.repeat(64) },
      startedAt: '2026-09-03T00:00:00.000Z',
      finishedAt: '2026-09-03T00:00:01.000Z',
    };
    const extraDigest = sha256Hex(extraResult);
    put(join(fixture.bundleDir, 'results', `${extraDigest}.json`), extraResult);
    const manifestPath = join(fixture.bundleDir, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.resultDigests.push(extraDigest);
    manifest.resultDigests.sort();
    put(manifestPath, manifest);
    expectCode('RESULT_SET_MISMATCH', () =>
      verifyPreparedBundle({
        bundleDir: fixture.bundleDir,
        trustStorePath: fixture.trustStorePath,
        ...fixture.expected,
      }),
    );
  });

  it(
    'refuses a symlink in an artifact ancestor rather than following it',
    { skip: process.platform === 'win32' },
    () => {
      const state = mutationV21Fixture({ dispositions: ['executed'] });
      const linkedRoot = temporaryDirectory('devai-mutation-v21-link-');
      const mutationTarget = join(state.artifactsDir, 'mutation');
      symlinkSync(mutationTarget, join(linkedRoot, 'mutation'), 'dir');
      expectCode('ARTIFACT_SYMLINK_ESCAPE', () =>
        verifyMutationReportSet(state.contract, linkedRoot, {
          candidateCommit: state.candidate.commit,
          candidateTree: state.candidate.tree,
          releaseUnit: state.candidate.releaseUnit,
        }),
      );
    },
  );
});

describe('pure mutation v2.1 refinalization', () => {
  it('reuses immutable package artifacts deterministically with every spawn API disabled', () => {
    const state = mutationV21Fixture();
    const inputPath = join(state.artifactsDir, 'refinalization-input.json');
    put(inputPath, {
      contract: state.contract,
      candidate: state.candidate,
      packages: state.packages.map((item) =>
        item.contract.requirement === 'required'
          ? {
              disposition: item.entry.disposition,
              report: item.report,
              result: item.result,
              origin: item.entry.origin,
            }
          : { disposition: 'not-required', reasonCode: item.entry.reasonCode },
      ),
    });
    const tripwire = join(state.artifactsDir, 'spawn-tripwire.cjs');
    put(
      tripwire,
      [
        "const childProcess = require('node:child_process');",
        "const { syncBuiltinESMExports } = require('node:module');",
        "for (const name of ['exec', 'execFile', 'execFileSync', 'spawn', 'spawnSync']) {",
        "  childProcess[name] = () => { throw new Error(`FORBIDDEN_PROCESS:${name}`); };",
        '}',
        'syncBuiltinESMExports();',
        '',
      ].join('\n'),
    );
    const driver = join(state.artifactsDir, 'refinalize.mjs');
    const mutationModule = resolve(import.meta.dirname, '../src/mutation.js');
    put(
      driver,
      [
        "import assert from 'node:assert/strict';",
        "import { readFileSync } from 'node:fs';",
        `const mutation = await import(${JSON.stringify(mutationModule)});`,
        "assert.equal(typeof mutation.finalizeMutationReportSetV21, 'function');",
        "const input = JSON.parse(readFileSync(process.argv[2], 'utf8'));",
        'const first = mutation.finalizeMutationReportSetV21(input);',
        'const second = mutation.finalizeMutationReportSetV21(structuredClone(input));',
        'assert.deepEqual(second, first);',
        'process.stdout.write(JSON.stringify(first));',
        '',
      ].join('\n'),
    );
    const execution = spawnSync(process.execPath, ['--require', tripwire, driver, inputPath], {
      encoding: 'utf8',
    });
    assert.equal(execution.status, 0, execution.stderr);
    assert.deepEqual(JSON.parse(execution.stdout), state.summary);
  });
});

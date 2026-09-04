import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { VerificationError, canonicalBytes, framedDigest, sha256Hex } from '../src/canonical.js';
import {
  MUTATION_V22_DIGEST_DOMAINS,
  buildMutationPackageExecutionReceiptV1,
  buildMutationSemanticReceiptV22,
  finalizeMutationReportSetV22,
  rebuildMutationPackageExecutionReceiptV1,
  validateMutationPackageExecutionOriginV1,
  validateMutationContractV22,
  verifyMutationPackageExecutionOriginV1,
  verifyMutationReportSetV22,
} from '../src/mutation-v22.js';
import { MUTATION_V21_DIGEST_DOMAINS, finalizeMutationReportSetV21 } from '../src/mutation-v21.js';

const DIGEST = (character) => character.repeat(64);
const COMMIT = 'a'.repeat(40);
const TREE = 'b'.repeat(40);
const PROVENANCE = {
  source: {
    repository: 'devai-verifier',
    commit: 'c'.repeat(40),
    tree: 'd'.repeat(40),
    byteSetDigest: DIGEST('e'),
  },
  vendor: {
    root: 'vendor/devai-verifier',
    manifestPath: 'vendor/devai-verifier/manifest.json',
    manifestDigest: DIGEST('f'),
    sourceCommit: 'c'.repeat(40),
    sourceTree: 'd'.repeat(40),
    byteSetDigest: DIGEST('e'),
  },
  byteEquality: true,
};

function payload() {
  return {
    schemaVersion: '1.0.0',
    kind: 'mutation-package-execution-receipt-v1',
    repositoryId: 'fixture/repository',
    candidate: { releaseUnit: 'fixture/repository', commit: COMMIT, tree: TREE },
    releasePlanReceiptDigest: DIGEST('1'),
    releaseProfileDigest: DIGEST('2'),
    policyDigest: DIGEST('3'),
    template: { id: 'mutation-template', version: '1.3.0' },
    task: { nodeId: 'test:mutation', policyDigest: DIGEST('4') },
    package: {
      packageName: '@fixture/package',
      workspace: 'packages/package',
      inputDigest: DIGEST('5'),
    },
    report: { path: 'mutation/package.report.json', sha256: DIGEST('6'), sizeBytes: 11 },
    result: { path: 'mutation/package.result.json', sha256: DIGEST('7'), sizeBytes: 12 },
    verifierProvenance: PROVENANCE,
  };
}

function expectations(receipt) {
  return {
    repositoryId: receipt.repositoryId,
    candidate: receipt.candidate,
    releasePlanReceiptDigest: receipt.releasePlanReceiptDigest,
    releaseProfileDigest: receipt.releaseProfileDigest,
    policyDigest: receipt.policyDigest,
    packageName: receipt.package.packageName,
    workspace: receipt.package.workspace,
    inputDigest: receipt.package.inputDigest,
    executionBinding: {
      templateId: receipt.template.id,
      templateVersion: receipt.template.version,
      taskNode: receipt.task.nodeId,
      taskPolicyDigest: receipt.task.policyDigest,
    },
    reportPath: receipt.report.path,
    reportDigest: receipt.report.sha256,
    reportSizeBytes: receipt.report.sizeBytes,
    resultPath: receipt.result.path,
    resultDigest: receipt.result.sha256,
    resultSizeBytes: receipt.result.sizeBytes,
    summaryPath: 'mutation/summary.json',
    semanticReceiptPath: 'mutation/semantic-receipt.json',
    members: new Map([
      [receipt.report.path, { sha256: receipt.report.sha256, sizeBytes: receipt.report.sizeBytes }],
      [receipt.result.path, { sha256: receipt.result.sha256, sizeBytes: receipt.result.sizeBytes }],
    ]),
    verifierProvenance: receipt.verifierProvenance,
    taskPolicyDigests: [receipt.task.policyDigest],
    expectedOutputContract: {
      path: 'mutation/output-contract.json',
      sha256: DIGEST('a'),
      sizeBytes: 1,
    },
  };
}

function code(expected, operation) {
  assert.throws(
    operation,
    (error) => error instanceof VerificationError && error.code === expected,
  );
}

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

function totals(overrides = {}) {
  return Object.fromEntries(STATUSES.map((status) => [status, overrides[status] ?? 0]));
}

function projection(packageName, workspace) {
  return {
    schemaVersion: '2.1.0',
    kind: 'mutation-input-projection-v2',
    packageName,
    workspace,
    bindings: Object.fromEntries(
      INPUT_BINDINGS.map((name) => [
        name,
        {
          canonicalization: 'rfc8785-jcs-utf8',
          memberCount: 1,
          populationDigest: sha256Hex(Buffer.from(`${packageName}:${name}:population`, 'utf8')),
          selectionRuleDigest: sha256Hex(Buffer.from(`${packageName}:${name}:selection`, 'utf8')),
        },
      ]),
    ),
  };
}

function packageMaterial(index, disposition = 'executed', status = 'Killed') {
  const packageName = `@fixture/package-${index}`;
  const workspace = `packages/package-${index}`;
  const thresholds = { break: 90, high: 100, low: 90, scoreMin: 90, survivedMax: 0 };
  const inputProjection = projection(packageName, workspace);
  const inputDigest = framedDigest('devai:mutation-input:v2.1', inputProjection);
  const report = {
    schemaVersion: '2.1.0',
    kind: 'mutation-normalized-stryker-report-v2',
    strykerSchemaVersion: '1',
    projectRoot: '.',
    thresholds: { break: 90, high: 100, low: 90 },
    files: {
      [`src/package-${index}.ts`]: {
        language: 'typescript',
        mutants: [
          {
            id: 'm1',
            mutatorName: 'ConditionalExpression',
            replacementDigest: sha256Hex(Buffer.from(`replacement:${index}`, 'utf8')),
            location: { start: { line: 1, column: 1 }, end: { line: 1, column: 2 } },
            status,
          },
        ],
      },
    },
    testFiles: {},
    config: {},
    framework: { name: 'StrykerJS' },
  };
  const reportDigest = sha256Hex(canonicalBytes(report));
  const statusTotals = totals({ [status]: 1 });
  const score = status === 'Killed' ? 100 : 0;
  const passed = status === 'Killed';
  const result = {
    schemaVersion: '2.1.0',
    kind: 'mutation-package-result-v2',
    packageName,
    workspace,
    inputProjection,
    inputDigest,
    reportDigest,
    toolVersions: { stryker: '9.6.1', sanitizer: '2.1.0' },
    process: { errorAbsent: true, signal: null, status: 0 },
    thresholds,
    statusTotals,
    targetCensus: { targetFileCount: 1, totalMutants: 1 },
    score,
    complete: true,
    passed,
  };
  const resultDigest = sha256Hex(canonicalBytes(result));
  const root = `.devai/state/mutation/v2/store/inputs/${inputDigest}/objects`;
  const contract = {
    packageName,
    workspace,
    requirement: 'required',
    reportPath: `${root}/${reportDigest}.report.json`,
    resultPath: `${root}/${resultDigest}.result.json`,
    inputProjection,
    inputDigest,
    thresholds,
    executionBinding: {
      templateId: 'mutation-template',
      templateVersion: '1.3.0',
      taskNode: `test:mutation-${index}`,
      taskPolicyDigest: sha256Hex(Buffer.from(`task-policy:${index}`, 'utf8')),
    },
  };
  return { contract, report, result, disposition };
}

function nonRequired(index) {
  return {
    packageName: `@fixture/not-required-${index}`,
    workspace: `packages/not-required-${index}`,
    requirement: 'not-required',
    reasonCode: 'no-mutatable-production-surface',
  };
}

function corpus({
  dispositions = ['executed', 'reused', 'not-required'],
  candidate = undefined,
  statuses = [],
} = {}) {
  const selectedCandidate = candidate ?? {
    releaseUnit: 'fixture/repository',
    commit: COMMIT,
    tree: TREE,
  };
  const contractEntries = dispositions.map((disposition, index) =>
    disposition === 'not-required'
      ? nonRequired(index)
      : packageMaterial(index, disposition, statuses[index] ?? 'Killed'),
  );
  const required = contractEntries.filter((entry) => entry.contract !== undefined);
  const contract = {
    schemaVersion: '2.2.0',
    kind: 'mutation-report-set-v2',
    expectedPackageCount: contractEntries.length,
    summaryPath: 'mutation/summary.json',
    semanticReceiptPath: 'mutation/semantic-receipt.json',
    releasePlanReceiptDigest: DIGEST('1'),
    releaseProfileDigest: DIGEST('2'),
    policyDigest: DIGEST('3'),
    packages: contractEntries.map((entry) => entry.contract ?? entry),
    paths: [],
  };
  contract.paths = [
    contract.summaryPath,
    contract.semanticReceiptPath,
    ...required.flatMap(({ contract: entry }) => [entry.reportPath, entry.resultPath]),
  ];
  validateMutationContractV22(contract);

  const material = contractEntries.map((entry) => {
    if (entry.contract === undefined) {
      return { disposition: 'not-required', reasonCode: entry.reasonCode };
    }
    if (entry.disposition === 'executed') {
      return { disposition: 'executed', report: entry.report, result: entry.result, origin: null };
    }
    const receipt = buildMutationPackageExecutionReceiptV1({
      schemaVersion: '1.0.0',
      kind: 'mutation-package-execution-receipt-v1',
      repositoryId: 'fixture/repository',
      candidate: selectedCandidate,
      releasePlanReceiptDigest: contract.releasePlanReceiptDigest,
      releaseProfileDigest: contract.releaseProfileDigest,
      policyDigest: contract.policyDigest,
      template: {
        id: entry.contract.executionBinding.templateId,
        version: entry.contract.executionBinding.templateVersion,
      },
      task: {
        nodeId: entry.contract.executionBinding.taskNode,
        policyDigest: entry.contract.executionBinding.taskPolicyDigest,
      },
      package: {
        packageName: entry.contract.packageName,
        workspace: entry.contract.workspace,
        inputDigest: entry.contract.inputDigest,
      },
      report: {
        path: entry.contract.reportPath,
        sha256: sha256Hex(canonicalBytes(entry.report)),
        sizeBytes: canonicalBytes(entry.report).length,
      },
      result: {
        path: entry.contract.resultPath,
        sha256: sha256Hex(canonicalBytes(entry.result)),
        sizeBytes: canonicalBytes(entry.result).length,
      },
      verifierProvenance: PROVENANCE,
    });
    return {
      disposition: 'reused',
      report: entry.report,
      result: entry.result,
      origin: { kind: 'mutation-package-execution-origin-v1', receipt },
    };
  });
  const documents = new Map();
  for (const [index, entry] of contractEntries.entries()) {
    if (entry.contract === undefined) continue;
    documents.set(contract.packages[index].reportPath, canonicalBytes(entry.report));
    documents.set(contract.packages[index].resultPath, canonicalBytes(entry.result));
  }
  const expectedOutputContract = {
    path: 'mutation/output-contract.json',
    sha256: sha256Hex(canonicalBytes(contract)),
    sizeBytes: canonicalBytes(contract).length,
  };
  const options = {
    releaseUnit: selectedCandidate.releaseUnit,
    candidateCommit: selectedCandidate.commit,
    candidateTree: selectedCandidate.tree,
    expectedRepositoryId: 'fixture/repository',
    expectedReleasePlanReceiptDigest: contract.releasePlanReceiptDigest,
    expectedReleaseProfileDigest: contract.releaseProfileDigest,
    expectedPolicyDigest: contract.policyDigest,
    expectedSemanticReceiptProvenance: PROVENANCE,
    expectedExecutionBindings: required.map(({ contract: entry }) => ({
      packageName: entry.packageName,
      ...entry.executionBinding,
    })),
    finalUnitReferent: undefined,
    expectedOutputContract,
  };
  const state = { candidate: selectedCandidate, contract, documents, material, options };
  state.reseal = () => {
    state.summary = finalizeMutationReportSetV22({
      contract,
      candidate: selectedCandidate,
      packages: material,
    });
    state.semanticReceipt = buildMutationSemanticReceiptV22({
      contract,
      summary: state.summary,
      receiptId: 'MSV2-1111111111111111',
      verifierProvenance: PROVENANCE,
    });
    documents.set(contract.summaryPath, canonicalBytes(state.summary));
    documents.set(contract.semanticReceiptPath, canonicalBytes(state.semanticReceipt));
    state.finalUnitReferent = {
      repositoryId: 'fixture/repository',
      candidate: selectedCandidate,
      releasePlanReceiptDigest: contract.releasePlanReceiptDigest,
      releaseProfileDigest: contract.releaseProfileDigest,
      policyDigest: contract.policyDigest,
      taskPolicyDigests:
        required.length === 0
          ? [sha256Hex(Buffer.from('not-required-task-policy', 'utf8'))]
          : required.map(({ contract: entry }) => entry.executionBinding.taskPolicyDigest).sort(),
      members: [...documents.entries()]
        .map(([path, bytes]) => ({ path, sha256: sha256Hex(bytes), sizeBytes: bytes.length }))
        .sort((left, right) => left.path.localeCompare(right.path)),
    };
    options.finalUnitReferent = state.finalUnitReferent;
  };
  const readArtifact = (path) => {
    const bytes = documents.get(path);
    assert.ok(bytes, `missing fixture artifact ${path}`);
    return { value: JSON.parse(bytes.toString('utf8')), bytes: Buffer.from(bytes) };
  };
  state.readArtifact = readArtifact;
  state.reseal();
  return state;
}

function v21Producer(state) {
  const contract = {
    ...structuredClone(state.contract),
    schemaVersion: '2.1.0',
    packages: state.contract.packages.map((entry) => {
      if (entry.requirement !== 'required') return structuredClone(entry);
      const { executionBinding: _binding, ...v21Entry } = entry;
      return v21Entry;
    }),
  };
  const summary = finalizeMutationReportSetV21({
    contract,
    candidate: state.candidate,
    packages: state.material.map((entry) => ({ ...entry, origin: null, disposition: 'executed' })),
  });
  const packages = contract.packages.map((entry, index) => {
    const summaryEntry = summary.packages[index];
    const compositionEntryDigest = framedDigest(
      MUTATION_V21_DIGEST_DOMAINS.compositionEntry,
      summaryEntry,
    );
    return entry.requirement === 'required'
      ? {
          packageName: entry.packageName,
          disposition: summaryEntry.disposition,
          inputDigest: entry.inputDigest,
          reportDigest: summaryEntry.reportDigest,
          resultDigest: summaryEntry.resultDigest,
          compositionEntryDigest,
        }
      : {
          packageName: entry.packageName,
          disposition: summaryEntry.disposition,
          compositionEntryDigest,
        };
  });
  const packageResultSet = summary.packages
    .filter((entry) => entry.requirement === 'required')
    .map((entry) => ({ packageName: entry.packageName, resultDigest: entry.resultDigest }));
  const payload = {
    schemaVersion: '2.1.0',
    kind: 'mutation-semantic-verification-receipt-v2',
    receiptId: 'MSV2-2222222222222222',
    candidate: state.candidate,
    outputContractDigest: framedDigest(MUTATION_V21_DIGEST_DOMAINS.outputContract, contract),
    releasePlanReceiptDigest: contract.releasePlanReceiptDigest,
    releaseProfileDigest: contract.releaseProfileDigest,
    policyDigest: contract.policyDigest,
    verifierProvenance: PROVENANCE,
    packages,
    packageResultSetDigest: framedDigest(
      MUTATION_V21_DIGEST_DOMAINS.packageResultSet,
      packageResultSet,
    ),
    evidenceSetDigest: summary.aggregate.evidenceSetDigest,
    verdict: summary.verdict,
    semanticVerificationPerformed: true,
  };
  return {
    composition: summary,
    semanticReceipt: {
      ...payload,
      receiptDigest: framedDigest(MUTATION_V21_DIGEST_DOMAINS.semanticReceipt, payload),
    },
  };
}

describe('mutation v2.2 package execution origin (ADR-MUT-0009)', () => {
  it('frames a closed MPE1 independently and rebuilds its exact self-reference', () => {
    const receipt = buildMutationPackageExecutionReceiptV1(payload());
    assert.match(receipt.receiptId, /^MPE1-[0-9a-f]{16}$/u);
    assert.equal(
      rebuildMutationPackageExecutionReceiptV1(structuredClone(receipt)).receiptDigest,
      receipt.receiptDigest,
    );
    assert.equal(
      MUTATION_V22_DIGEST_DOMAINS.executionReceipt,
      'devai:mutation-package-execution-receipt:v1',
    );
    const { receiptId: _id, receiptDigest: _digest, ...withoutSelfReference } = receipt;
    assert.equal(
      receipt.receiptDigest,
      sha256Hex(
        Buffer.concat([
          Buffer.from('devai:mutation-package-execution-receipt:v1\0', 'utf8'),
          (() => {
            const bytes = canonicalBytes(withoutSelfReference);
            const length = Buffer.alloc(8);
            length.writeBigUInt64BE(BigInt(bytes.length));
            return Buffer.concat([length, bytes]);
          })(),
        ]),
      ),
    );
  });

  it('refuses MPE1 self-reference, closed-key, path, provenance and identity drift', () => {
    const receipt = buildMutationPackageExecutionReceiptV1(payload());
    for (const mutate of [
      (value) => (value.receiptDigest = DIGEST('0')),
      (value) => Object.assign(value, { unexpected: true }),
      (value) => (value.report.path = '../escape.json'),
      (value) => (value.report.path = 'mutation/e\u0301.json'),
      (value) => (value.candidate.commit = '9'.repeat(40)),
    ]) {
      const changed = structuredClone(receipt);
      mutate(changed);
      code('MUTATION_REUSE_DENIED', () => rebuildMutationPackageExecutionReceiptV1(changed));
    }
    const provenance = structuredClone(receipt);
    provenance.verifierProvenance.vendor.sourceTree = '0'.repeat(40);
    code('MUTATION_VENDOR_PROVENANCE_MISMATCH', () =>
      rebuildMutationPackageExecutionReceiptV1(provenance),
    );
  });

  it('accepts only the full embedded same-campaign origin and compares every portable binding', () => {
    const receipt = buildMutationPackageExecutionReceiptV1(payload());
    const origin = { kind: 'mutation-package-execution-origin-v1', receipt };
    assert.equal(
      validateMutationPackageExecutionOriginV1(structuredClone(origin)).receiptDigest,
      receipt.receiptDigest,
    );
    assert.deepEqual(verifyMutationPackageExecutionOriginV1(origin, expectations(receipt)), {
      receiptId: receipt.receiptId,
      receiptDigest: receipt.receiptDigest,
    });
    const withoutControl = expectations(receipt);
    delete withoutControl.expectedOutputContract;
    code('MUTATION_OFFLINE_EXPECTATION_MISSING', () =>
      verifyMutationPackageExecutionOriginV1(origin, withoutControl),
    );
    for (const mutate of [
      (value) => (value.candidate.tree = '8'.repeat(40)),
      (value) => (value.template.version = '1.2.0'),
      (value) => (value.task.nodeId = 'test:other'),
      (value) => (value.package.inputDigest = DIGEST('8')),
      (value) => (value.report.sizeBytes = 99),
      (value) => (value.result.sha256 = DIGEST('9')),
    ]) {
      const changed = structuredClone(receipt);
      mutate(changed);
      const changedOrigin = { kind: 'mutation-package-execution-origin-v1', receipt: changed };
      code('MUTATION_REUSE_DENIED', () =>
        verifyMutationPackageExecutionOriginV1(changedOrigin, expectations(receipt)),
      );
    }
    for (const invalid of [
      { kind: 'mutation-package-execution-origin-v1', receipt: receipt.receiptDigest },
      { kind: 'mutation-package-execution-origin-v1', receipt, callback: () => receipt },
    ]) {
      code('MUTATION_REUSE_DENIED', () => validateMutationPackageExecutionOriginV1(invalid));
    }
    code('MUTATION_VERSION_UNSUPPORTED', () =>
      validateMutationPackageExecutionOriginV1({
        kind: 'mutation-package-execution-origin-v2',
        receipt,
      }),
    );
  });
});

describe('mutation v2.2 composed verification (ADR-MUT-0009)', () => {
  it('preserves v2.1 report/result bytes in a mixed executed, MPE-reused and not-required closure offline and on certify', () => {
    const state = corpus();
    const expected = {
      schemaVersion: '2.2.0',
      packageCount: 3,
      executedPackageCount: 1,
      reusedPackageCount: 1,
      notRequiredPackageCount: 1,
      complete: true,
      verdict: 'pass',
      passed: true,
      memberCount: 6,
    };
    for (const mutationVerificationMode of ['offline', 'certify']) {
      const actual = verifyMutationReportSetV22(state.contract, state.readArtifact, {
        ...state.options,
        mutationVerificationMode,
      });
      assert.deepEqual(
        Object.fromEntries(Object.keys(expected).map((key) => [key, actual[key]])),
        expected,
      );
      assert.equal(actual.executionOrigins.length, 1);
    }
    for (const path of state.contract.packages
      .filter((entry) => entry.requirement === 'required')
      .flatMap((entry) => [entry.reportPath, entry.resultPath])) {
      const bytes = state.documents.get(path);
      assert.equal(
        sha256Hex(bytes),
        state.finalUnitReferent.members.find((member) => member.path === path).sha256,
      );
    }
  });

  it('requires an independent exact output-contract control and binds canonical callback bytes', () => {
    const state = corpus();
    const baseline = () =>
      verifyMutationReportSetV22(state.contract, state.readArtifact, state.options);
    assert.equal(baseline().passed, true);

    const withoutControl = { ...state.options };
    delete withoutControl.expectedOutputContract;
    code('MUTATION_OFFLINE_EXPECTATION_MISSING', () =>
      verifyMutationReportSetV22(state.contract, state.readArtifact, withoutControl),
    );
    code('ARTIFACT_DIGEST_MISMATCH', () =>
      verifyMutationReportSetV22(state.contract, state.readArtifact, {
        ...state.options,
        expectedOutputContract: { ...state.options.expectedOutputContract, sha256: DIGEST('0') },
      }),
    );
    code('MUTATION_ROSTER_MISMATCH', () =>
      verifyMutationReportSetV22(state.contract, state.readArtifact, {
        ...state.options,
        expectedOutputContract: {
          ...state.options.expectedOutputContract,
          path: state.contract.summaryPath,
        },
      }),
    );
    code('MUTATION_ROSTER_MISMATCH', () =>
      verifyMutationReportSetV22(state.contract, state.readArtifact, {
        ...state.options,
        expectedOutputContract: {
          ...state.options.expectedOutputContract,
          path: state.contract.packages[0].reportPath,
        },
      }),
    );

    const summaryBytes = state.documents.get(state.contract.summaryPath);
    code('ARTIFACT_DIGEST_MISMATCH', () =>
      verifyMutationReportSetV22(
        state.contract,
        (path) => {
          const snapshot = state.readArtifact(path);
          return path === state.contract.summaryPath
            ? { value: { ...snapshot.value, passed: false }, bytes: summaryBytes }
            : snapshot;
        },
        state.options,
      ),
    );
    const malformed = Buffer.from('{"bad":"\xff"}', 'binary');
    code('NON_CANONICAL_JSON', () =>
      verifyMutationReportSetV22(
        state.contract,
        (path) =>
          path === state.contract.summaryPath
            ? { value: { bad: '\ufffd' }, bytes: malformed }
            : state.readArtifact(path),
        state.options,
      ),
    );
  });

  it('does not infer repository, candidate, receipt, policy, or task identity from the submitted documents', () => {
    const state = corpus();
    const variants = [
      ['MUTATION_SEMANTIC_RECEIPT_MISMATCH', { expectedRepositoryId: 'other/repository' }],
      ['MUTATION_SEMANTIC_RECEIPT_MISMATCH', { candidateCommit: '9'.repeat(40) }],
      ['MUTATION_SEMANTIC_RECEIPT_MISMATCH', { expectedReleasePlanReceiptDigest: DIGEST('0') }],
      ['MUTATION_SEMANTIC_RECEIPT_MISMATCH', { expectedReleaseProfileDigest: DIGEST('0') }],
      ['MUTATION_SEMANTIC_RECEIPT_MISMATCH', { expectedPolicyDigest: DIGEST('0') }],
      [
        'MUTATION_REUSE_DENIED',
        {
          expectedExecutionBindings: state.options.expectedExecutionBindings.map((entry) =>
            entry.packageName === '@fixture/package-0'
              ? { ...entry, taskNode: 'test:substituted' }
              : entry,
          ),
        },
      ],
    ];
    for (const [expectedCode, patch] of variants) {
      code(expectedCode, () =>
        verifyMutationReportSetV22(state.contract, state.readArtifact, {
          ...state.options,
          ...patch,
        }),
      );
    }
  });

  it('accepts all-fresh and all-MPE-reused portable report pairs without a semantic-origin resolver', () => {
    for (const dispositions of [
      ['executed', 'executed'],
      ['reused', 'reused'],
    ]) {
      const state = corpus({ dispositions });
      let calls = 0;
      const result = verifyMutationReportSetV22(state.contract, state.readArtifact, {
        ...state.options,
        mutationVerificationMode: 'certify',
        resolveReuseOrigin: () => {
          calls += 1;
          throw new Error('MPE1 must not consult a semantic origin resolver');
        },
      });
      assert.equal(result.passed, true);
      assert.equal(calls, 0);
    }
  });

  it('keeps all-not-required and nonpassing required evidence distinct from a verified pass', () => {
    const notRequired = corpus({ dispositions: ['not-required', 'not-required'] });
    const none = verifyMutationReportSetV22(notRequired.contract, notRequired.readArtifact, {
      ...notRequired.options,
      mutationVerificationMode: 'offline',
    });
    assert.deepEqual(
      { complete: none.complete, verdict: none.verdict, passed: none.passed, score: none.score },
      { complete: true, verdict: 'not-applicable', passed: false, score: null },
    );
    const nonpassing = corpus({ dispositions: ['executed'], statuses: ['Survived'] });
    assert.equal(nonpassing.summary.verdict, 'fail');
    code('MUTATION_THRESHOLD_FAILED', () =>
      verifyMutationReportSetV22(nonpassing.contract, nonpassing.readArtifact, {
        ...nonpassing.options,
        mutationVerificationMode: 'offline',
      }),
    );
  });

  it('never lets a correctly framed MPE1 widen to a different candidate', () => {
    const state = corpus({ dispositions: ['reused'] });
    const entry = state.contract.packages[0];
    state.material[0].origin = {
      kind: 'mutation-package-execution-origin-v1',
      receipt: buildMutationPackageExecutionReceiptV1({
        schemaVersion: '1.0.0',
        kind: 'mutation-package-execution-receipt-v1',
        repositoryId: 'fixture/repository',
        candidate: {
          releaseUnit: 'fixture/repository',
          commit: '9'.repeat(40),
          tree: '8'.repeat(40),
        },
        releasePlanReceiptDigest: state.contract.releasePlanReceiptDigest,
        releaseProfileDigest: state.contract.releaseProfileDigest,
        policyDigest: state.contract.policyDigest,
        template: {
          id: entry.executionBinding.templateId,
          version: entry.executionBinding.templateVersion,
        },
        task: {
          nodeId: entry.executionBinding.taskNode,
          policyDigest: entry.executionBinding.taskPolicyDigest,
        },
        package: {
          packageName: entry.packageName,
          workspace: entry.workspace,
          inputDigest: entry.inputDigest,
        },
        report: {
          path: entry.reportPath,
          sha256: sha256Hex(state.documents.get(entry.reportPath)),
          sizeBytes: state.documents.get(entry.reportPath).length,
        },
        result: {
          path: entry.resultPath,
          sha256: sha256Hex(state.documents.get(entry.resultPath)),
          sizeBytes: state.documents.get(entry.resultPath).length,
        },
        verifierProvenance: PROVENANCE,
      }),
    };
    state.reseal();
    code('MUTATION_REUSE_DENIED', () =>
      verifyMutationReportSetV22(state.contract, state.readArtifact, {
        ...state.options,
        mutationVerificationMode: 'offline',
      }),
    );
  });

  it('accepts a complete v2.2 producing origin exactly once on certify and never calls it offline', () => {
    const producer = corpus({
      dispositions: ['executed'],
      candidate: {
        releaseUnit: 'fixture/repository',
        commit: '9'.repeat(40),
        tree: '8'.repeat(40),
      },
    });
    const consumer = corpus({ dispositions: ['reused'] });
    consumer.material[0].origin = {
      candidate: producer.candidate,
      semanticReceiptDigest: producer.semanticReceipt.receiptDigest,
      evidenceSetDigest: producer.summary.aggregate.evidenceSetDigest,
    };
    consumer.reseal();
    const reportPath = consumer.contract.packages[0].reportPath;
    const originalReportBytes = Buffer.from(consumer.documents.get(reportPath));
    let certifyCalls = 0;
    assert.equal(
      verifyMutationReportSetV22(consumer.contract, consumer.readArtifact, {
        ...consumer.options,
        mutationVerificationMode: 'certify',
        resolveReuseOrigin: (origin) => {
          certifyCalls += 1;
          assert.deepEqual(origin, consumer.material[0].origin);
          // Later mutation cannot alter the private artifacts/expectations already captured.
          consumer.documents.get(reportPath)[0] ^= 0xff;
          return { composition: producer.summary, semanticReceipt: producer.semanticReceipt };
        },
      }).passed,
      true,
    );
    assert.equal(certifyCalls, 1);
    consumer.documents.set(reportPath, originalReportBytes);

    let offlineCalls = 0;
    assert.equal(
      verifyMutationReportSetV22(consumer.contract, consumer.readArtifact, {
        ...consumer.options,
        mutationVerificationMode: 'offline',
        resolveReuseOrigin: () => {
          offlineCalls += 1;
          throw new Error('offline verification does not use an origin callback');
        },
      }).passed,
      true,
    );
    assert.equal(offlineCalls, 0);
  });

  it('supports v2.1 producing evidence only through its matching validator and refuses mixed or unknown producing versions', () => {
    const producer = corpus({
      dispositions: ['executed'],
      candidate: {
        releaseUnit: 'fixture/repository',
        commit: '9'.repeat(40),
        tree: '8'.repeat(40),
      },
    });
    const consumer = corpus({ dispositions: ['reused'] });
    const v21 = v21Producer(producer);
    consumer.material[0].origin = {
      candidate: producer.candidate,
      semanticReceiptDigest: v21.semanticReceipt.receiptDigest,
      evidenceSetDigest: v21.composition.aggregate.evidenceSetDigest,
    };
    consumer.reseal();
    let calls = 0;
    assert.equal(
      verifyMutationReportSetV22(consumer.contract, consumer.readArtifact, {
        ...consumer.options,
        mutationVerificationMode: 'certify',
        resolveReuseOrigin: () => {
          calls += 1;
          return v21;
        },
      }).passed,
      true,
    );
    assert.equal(calls, 1);

    for (const [expectedCode, resolved] of [
      [
        'MUTATION_REUSE_DENIED',
        {
          composition: { ...v21.composition, schemaVersion: '2.2.0' },
          semanticReceipt: v21.semanticReceipt,
        },
      ],
      [
        'MUTATION_VERSION_UNSUPPORTED',
        {
          composition: { ...v21.composition, schemaVersion: '2.3.0' },
          semanticReceipt: { ...v21.semanticReceipt, schemaVersion: '2.3.0' },
        },
      ],
    ]) {
      code(expectedCode, () =>
        verifyMutationReportSetV22(consumer.contract, consumer.readArtifact, {
          ...consumer.options,
          mutationVerificationMode: 'certify',
          resolveReuseOrigin: () => resolved,
        }),
      );
    }
  });
});

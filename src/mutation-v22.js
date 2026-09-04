import {
  VerificationError,
  canonicalBytes,
  canonicalize,
  framedDigest,
  sha256Hex,
} from './canonical-json.js';
import {
  MUTATION_V21_DIGEST_DOMAINS,
  MUTATION_V21_PATTERNS,
  MUTATION_V21_REASONS,
  MUTATION_V21_SCHEMA,
  MUTATION_V21_SHAPE,
  MUTATION_V21_STATUSES,
  checkedStatusAdd,
  emptyStatusTotals,
  validateCandidateIdentity,
  validateInputProjectionIdentity,
  validateMutationPackagePair,
  validateMutationThresholds,
  validatePortablePath,
  validateSemanticReuseOriginShape,
  validateTrustedSemanticReuseOrigin,
  validateVerifierProvenance,
} from './mutation-v21.js';

/**
 * Strict mutation report-set contract `2.2.0`.
 *
 * The branch reuses the v2.1 semantic kernels verbatim: the normalized report,
 * package result and input projection stay byte-identical v2.1 documents with the
 * v2.1 input digest domain and the v2.1 content-addressed store layout. Only the
 * output contract, composition summary and semantic receipt are v2.2 documents,
 * and they carry their own digest domains so a v2.1 reader refuses them and a
 * cross-version producing composition never resolves as an origin.
 */
export const MUTATION_V22_SCHEMA = '2.2.0';
export const MUTATION_V22_CONTRACT = 'mutation-report-set-v2';
export const MUTATION_V22_SUMMARY_KIND = 'mutation-composed-report-set-v2';
export const MUTATION_V22_SEMANTIC_RECEIPT_KIND = 'mutation-semantic-verification-receipt-v2';
export const MUTATION_V22_EVIDENCE_REF_KIND = 'mutation-package-evidence-ref-v2';
export const MPE1_SCHEMA = '1.0.0';
export const MPE1_KIND = 'mutation-package-execution-receipt-v1';
export const MPE1_ORIGIN_KIND = 'mutation-package-execution-origin-v1';

const { exact, fail, object, safeCount, string } = MUTATION_V21_SHAPE;
const { PACKAGE_NAME, RECEIPT_ID, SHA256 } = MUTATION_V21_PATTERNS;
const STATUSES = MUTATION_V21_STATUSES;

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const TEMPLATE_VERSION = /^\d+\.\d+\.\d+$/u;
const MPE1_RECEIPT_ID = /^MPE1-[0-9a-f]{16}$/u;
const PORTABLE_PATH_MAX = 512;
// The portable path shape is conjuncted with NFC equality (already enforced by the
// shared v2.1 grammar) and rejection of every Unicode Cc or Cs character, which
// also excludes the C1 controls and lone surrogates that ASCII checks miss.
const NON_PORTABLE_UNICODE = /[\p{Cc}\p{Cs}]/u;

const DOMAINS = Object.freeze({
  outputContract: 'devai:mutation-output-contract:v2.2',
  packageResultSet: 'devai:mutation-package-result-set:v2.2',
  compositionEntry: 'devai:mutation-composition-entry:v2.2',
  evidenceRef: 'devai:mutation-evidence-ref:v2.2',
  composition: 'devai:mutation-composition:v2.2',
  semanticReceipt: 'devai:mutation-semantic-receipt:v2.2',
  // Unchanged on purpose: the package pair keeps its exact v2.1 bytes, so its
  // input identity must keep the exact v2.1 domain.
  input: 'devai:mutation-input:v2.1',
  executionReceipt: 'devai:mutation-package-execution-receipt:v1',
});
const BRANCH = Object.freeze({ schemaVersion: MUTATION_V22_SCHEMA, domains: DOMAINS });

/**
 * The producing contract branches this reader explicitly supports for a complete
 * semantic-receipt origin. A producing document is always verified under its own
 * declared branch: v2.1 keeps unchanged v2.1 semantics and domains, v2.2 uses the
 * v2.2 domains, and neither is ever reinterpreted as the other.
 */
const PRODUCING_BRANCHES = Object.freeze({
  __proto__: null,
  [MUTATION_V21_SCHEMA]: Object.freeze({
    schemaVersion: MUTATION_V21_SCHEMA,
    domains: MUTATION_V21_DIGEST_DOMAINS,
  }),
  [MUTATION_V22_SCHEMA]: BRANCH,
});

const EXECUTION_BINDING_KEYS = ['templateId', 'templateVersion', 'taskNode', 'taskPolicyDigest'];
const REQUIRED_CONTRACT_KEYS = [
  'packageName',
  'workspace',
  'requirement',
  'reportPath',
  'resultPath',
  'inputProjection',
  'inputDigest',
  'thresholds',
  'executionBinding',
];
const MPE1_PAYLOAD_KEYS = [
  'schemaVersion',
  'kind',
  'repositoryId',
  'candidate',
  'releasePlanReceiptDigest',
  'releaseProfileDigest',
  'policyDigest',
  'template',
  'task',
  'package',
  'report',
  'result',
  'verifierProvenance',
];
const MPE1_KEYS = [...MPE1_PAYLOAD_KEYS, 'receiptId', 'receiptDigest'];
const SEMANTIC_RECEIPT_KEYS = [
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
];
const REFERENT_KEYS = [
  'repositoryId',
  'candidate',
  'releasePlanReceiptDigest',
  'releaseProfileDigest',
  'policyDigest',
  'taskPolicyDigests',
  'members',
];

function denyReuse(message) {
  fail('MUTATION_REUSE_DENIED', message);
}

/**
 * Chooses the producing branch from the single resolved pair. The composition and
 * the semantic receipt must declare the same supported version: a mixed or unknown
 * pair refuses rather than being credited under either branch.
 */
function selectProducingBranch(resolved, entry) {
  const composition = resolved?.composition?.schemaVersion;
  const receipt = resolved?.semanticReceipt?.schemaVersion;
  if (typeof composition !== 'string' || typeof receipt !== 'string') {
    denyReuse(`${entry.packageName} reused origin does not declare a producing contract version`);
  }
  if (composition !== receipt) {
    denyReuse(
      `${entry.packageName} reused origin composition and semantic receipt declare different contract versions`,
    );
  }
  if (!Object.hasOwn(PRODUCING_BRANCHES, composition)) {
    fail(
      'MUTATION_VERSION_UNSUPPORTED',
      `${entry.packageName} reused origin declares an unsupported producing contract version`,
    );
  }
  return PRODUCING_BRANCHES[composition];
}

/**
 * Captures a caller-owned protected input before any candidate-supplied callback
 * runs, so a later read or resolver call cannot rebind an already validated
 * expectation.
 */
function captureDocument(value, label, code = 'SCHEMA_INVALID') {
  try {
    return structuredClone(value);
  } catch {
    return fail(code, `${label} is not a plain JSON document`);
  }
}

/**
 * Reads one declared artifact and binds its document to its exact bytes.
 *
 * The returned document is reparsed from a private copy of the returned bytes, so
 * the semantics this verification checks and the bytes the final closure binds can
 * never diverge, and a later callback cannot mutate an object or buffer an earlier
 * call already returned.
 *
 * Both canonical comparisons are exact byte comparisons. Decoding to a string first
 * would replace invalid UTF-8 with U+FFFD, so noncanonical raw bytes could round
 * trip through an equal text comparison while hashing differently in the closure.
 */
function captureArtifact(readArtifact, path, label) {
  const snapshot = readArtifact(path, label);
  object(snapshot, `${label} snapshot`, 'MUTATION_REPORT_INVALID');
  if (!Buffer.isBuffer(snapshot.bytes)) {
    fail('MUTATION_REPORT_INVALID', `${label} was not returned as exact bytes`);
  }
  const bytes = Buffer.from(snapshot.bytes);
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail('MUTATION_REPORT_INVALID', `${label} is not valid JSON`);
  }
  if (!bytes.equals(canonicalBytes(value))) {
    fail('NON_CANONICAL_JSON', `${label} is not canonical JSON`);
  }
  if (!bytes.equals(canonicalBytes(snapshot.value))) {
    fail(
      'ARTIFACT_DIGEST_MISMATCH',
      `${label} document does not match the bytes bound into the final unit closure`,
    );
  }
  return { value, bytes, sha256: sha256Hex(bytes), sizeBytes: bytes.length };
}

function validateOutputContractControlShape(control, label = 'mutation expectedOutputContract') {
  exact(control, ['path', 'sha256', 'sizeBytes'], label, 'MUTATION_OFFLINE_EXPECTATION_MISSING');
  validateV22Path(control.path, `${label}.path`, 'MUTATION_OFFLINE_EXPECTATION_MISSING');
  string(control.sha256, `${label}.sha256`, SHA256, 'MUTATION_OFFLINE_EXPECTATION_MISSING');
  safeCount(control.sizeBytes, `${label}.sizeBytes`, 'MUTATION_OFFLINE_EXPECTATION_MISSING');
  if (control.sizeBytes === 0) missingExpectation(`${label}.sizeBytes`);
}

function missingExpectation(name) {
  fail(
    'MUTATION_OFFLINE_EXPECTATION_MISSING',
    `mutation v2.2 ${name} is required as an independent protected expectation`,
  );
}

function validateV22Path(path, label, code = 'SCHEMA_INVALID') {
  validatePortablePath(path, label, code);
  if (path.length > PORTABLE_PATH_MAX || NON_PORTABLE_UNICODE.test(path)) {
    fail(code, `${label} is not a canonical portable path`);
  }
}

function validateExecutionBinding(binding, label, code = 'SCHEMA_INVALID') {
  exact(binding, EXECUTION_BINDING_KEYS, label, code);
  string(binding.templateId, `${label}.templateId`, IDENTIFIER, code);
  string(binding.templateVersion, `${label}.templateVersion`, TEMPLATE_VERSION, code);
  string(binding.taskNode, `${label}.taskNode`, IDENTIFIER, code);
  string(binding.taskPolicyDigest, `${label}.taskPolicyDigest`, SHA256, code);
}

function validateRequiredContract(entry, label) {
  for (const key of ['inputProjection', 'inputDigest']) {
    if (!Object.hasOwn(entry, key)) {
      fail('MUTATION_INPUT_IDENTITY_MISSING', `${label}.${key} is missing`);
    }
  }
  exact(entry, REQUIRED_CONTRACT_KEYS, label);
  string(entry.packageName, `${label}.packageName`, PACKAGE_NAME);
  validateV22Path(entry.workspace, `${label}.workspace`);
  validateV22Path(entry.reportPath, `${label}.reportPath`);
  validateV22Path(entry.resultPath, `${label}.resultPath`);
  if (entry.requirement !== 'required') fail('SCHEMA_INVALID', `${label}.requirement is invalid`);
  validateInputProjectionIdentity(
    entry.inputProjection,
    entry.packageName,
    entry.workspace,
    `${label}.inputProjection`,
  );
  string(entry.inputDigest, `${label}.inputDigest`, SHA256, 'MUTATION_INPUT_DIGEST_MISMATCH');
  if (entry.inputDigest !== framedDigest(DOMAINS.input, entry.inputProjection)) {
    fail('MUTATION_INPUT_DIGEST_MISMATCH', `${label}.inputDigest differs from its projection`);
  }
  validateMutationThresholds(entry.thresholds, `${label}.thresholds`);
  validateExecutionBinding(entry.executionBinding, `${label}.executionBinding`);
}

function validateNotRequiredContract(entry, label) {
  exact(entry, ['packageName', 'workspace', 'requirement', 'reasonCode'], label);
  string(entry.packageName, `${label}.packageName`, PACKAGE_NAME);
  validateV22Path(entry.workspace, `${label}.workspace`);
  if (entry.requirement !== 'not-required' || !MUTATION_V21_REASONS.includes(entry.reasonCode)) {
    fail('SCHEMA_INVALID', `${label} not-required decision is invalid`);
  }
}

/**
 * Validates the strict `2.2.0` output contract. The required row is the v2.1 row
 * plus exactly one `executionBinding`; no other document in the branch repeats
 * that binding.
 */
export function validateMutationContractV22(contract, label = 'mutation output contract') {
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
  if (contract.kind !== MUTATION_V22_CONTRACT || contract.schemaVersion !== MUTATION_V22_SCHEMA) {
    fail('MUTATION_VERSION_UNSUPPORTED', `${label} version is unsupported`);
  }
  safeCount(contract.expectedPackageCount, `${label}.expectedPackageCount`, 'SCHEMA_INVALID');
  if (contract.expectedPackageCount === 0 || !Array.isArray(contract.packages)) {
    fail('SCHEMA_INVALID', `${label}.packages must be nonempty`);
  }
  if (contract.packages.length !== contract.expectedPackageCount) {
    fail('MUTATION_ROSTER_MISMATCH', `${label} package count differs`);
  }
  validateV22Path(contract.summaryPath, `${label}.summaryPath`);
  validateV22Path(contract.semanticReceiptPath, `${label}.semanticReceiptPath`);
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
  for (const [index, path] of contract.paths.entries())
    validateV22Path(path, `${label}.paths[${index}]`);
  if (new Set(contract.paths).size !== contract.paths.length) {
    fail('MUTATION_ROSTER_MISMATCH', `${label}.paths contains duplicates`);
  }
  const actual = [...contract.paths].sort();
  const expected = [...expectedPaths].sort();
  if (actual.length !== expected.length || actual.some((path, index) => path !== expected[index])) {
    fail('MUTATION_ROSTER_MISMATCH', `${label}.paths differs from its artifact roster`);
  }
}

/**
 * The v2.2 package-pair verifier. It is the shared v2.1 kernel: byte-identical
 * pairs are never reinterpreted here, only re-measured.
 */
export function validateMutationPackagePairV22(contractEntry, material, options = {}) {
  return validateMutationPackagePair(contractEntry, material, options);
}

function validateArtifactBinding(value, label) {
  exact(value, ['path', 'sha256', 'sizeBytes'], label, 'MUTATION_REUSE_DENIED');
  validateV22Path(value.path, `${label}.path`, 'MUTATION_REUSE_DENIED');
  string(value.sha256, `${label}.sha256`, SHA256, 'MUTATION_REUSE_DENIED');
  safeCount(value.sizeBytes, `${label}.sizeBytes`, 'MUTATION_REUSE_DENIED');
  if (value.sizeBytes === 0) denyReuse(`${label}.sizeBytes must be positive`);
}

function asReuseDenied(label, run) {
  try {
    return run();
  } catch (error) {
    if (
      error instanceof VerificationError &&
      (error.code === 'MUTATION_REUSE_DENIED' ||
        error.code === 'MUTATION_VERSION_UNSUPPORTED' ||
        error.code === 'MUTATION_VENDOR_PROVENANCE_MISMATCH')
    ) {
      throw error;
    }
    denyReuse(`${label} is invalid`);
  }
}

function validateExecutionReceiptPayload(payload, label) {
  exact(payload, MPE1_PAYLOAD_KEYS, label, 'MUTATION_REUSE_DENIED');
  if (payload.schemaVersion !== MPE1_SCHEMA || payload.kind !== MPE1_KIND) {
    fail(
      'MUTATION_VERSION_UNSUPPORTED',
      `${label} declares an unsupported execution receipt version`,
    );
  }
  string(payload.repositoryId, `${label}.repositoryId`, IDENTIFIER, 'MUTATION_REUSE_DENIED');
  asReuseDenied(`${label}.candidate`, () =>
    validateCandidateIdentity(payload.candidate, `${label}.candidate`),
  );
  for (const key of ['releasePlanReceiptDigest', 'releaseProfileDigest', 'policyDigest']) {
    string(payload[key], `${label}.${key}`, SHA256, 'MUTATION_REUSE_DENIED');
  }
  exact(payload.template, ['id', 'version'], `${label}.template`, 'MUTATION_REUSE_DENIED');
  string(payload.template.id, `${label}.template.id`, IDENTIFIER, 'MUTATION_REUSE_DENIED');
  string(
    payload.template.version,
    `${label}.template.version`,
    TEMPLATE_VERSION,
    'MUTATION_REUSE_DENIED',
  );
  exact(payload.task, ['nodeId', 'policyDigest'], `${label}.task`, 'MUTATION_REUSE_DENIED');
  string(payload.task.nodeId, `${label}.task.nodeId`, IDENTIFIER, 'MUTATION_REUSE_DENIED');
  string(payload.task.policyDigest, `${label}.task.policyDigest`, SHA256, 'MUTATION_REUSE_DENIED');
  exact(
    payload.package,
    ['packageName', 'workspace', 'inputDigest'],
    `${label}.package`,
    'MUTATION_REUSE_DENIED',
  );
  string(
    payload.package.packageName,
    `${label}.package.packageName`,
    PACKAGE_NAME,
    'MUTATION_REUSE_DENIED',
  );
  validateV22Path(payload.package.workspace, `${label}.package.workspace`, 'MUTATION_REUSE_DENIED');
  string(
    payload.package.inputDigest,
    `${label}.package.inputDigest`,
    SHA256,
    'MUTATION_REUSE_DENIED',
  );
  validateArtifactBinding(payload.report, `${label}.report`);
  validateArtifactBinding(payload.result, `${label}.result`);
  if (payload.report.path === payload.result.path) {
    denyReuse(`${label} report and result name the same member`);
  }
  asReuseDenied(`${label}.verifierProvenance`, () =>
    validateVerifierProvenance(payload.verifierProvenance),
  );
}

/**
 * Builds the closed `mutation-package-execution-receipt-v1` object from its exact
 * payload. The digest covers the payload with `receiptId` and `receiptDigest`
 * omitted, so no sink handle, object identity, timestamp, process identifier,
 * host path or raw output can enter it.
 */
export function buildMutationPackageExecutionReceiptV1(
  payload,
  label = 'mutation package execution receipt',
) {
  validateExecutionReceiptPayload(payload, label);
  const copy = structuredClone(payload);
  const receiptDigest = framedDigest(DOMAINS.executionReceipt, copy);
  return { ...copy, receiptId: `MPE1-${receiptDigest.slice(0, 16)}`, receiptDigest };
}

/**
 * Rebuilds a complete MPE1 from its own bytes and requires the supplied identifier
 * and digest to be exactly the recomputed ones. A self-referential or edited
 * receipt refuses.
 */
export function rebuildMutationPackageExecutionReceiptV1(
  receipt,
  label = 'mutation package execution receipt',
) {
  exact(receipt, MPE1_KEYS, label, 'MUTATION_REUSE_DENIED');
  string(receipt.receiptId, `${label}.receiptId`, MPE1_RECEIPT_ID, 'MUTATION_REUSE_DENIED');
  string(receipt.receiptDigest, `${label}.receiptDigest`, SHA256, 'MUTATION_REUSE_DENIED');
  const { receiptId, receiptDigest, ...payload } = receipt;
  const rebuilt = buildMutationPackageExecutionReceiptV1(payload, label);
  if (rebuilt.receiptDigest !== receiptDigest || rebuilt.receiptId !== receiptId) {
    denyReuse(`${label} digest or identifier does not bind its own payload`);
  }
  return rebuilt;
}

/**
 * Validates the embedded same-campaign origin envelope and returns the rebuilt
 * receipt. Digest-only, handle-only, partial and callback-resolved MPE forms have
 * no representation here and refuse.
 */
export function validateMutationPackageExecutionOriginV1(
  origin,
  label = 'mutation package execution origin',
) {
  object(origin, label, 'MUTATION_REUSE_DENIED');
  if (
    typeof origin.kind === 'string' &&
    origin.kind !== MPE1_ORIGIN_KIND &&
    origin.kind.startsWith('mutation-package-execution-origin-')
  ) {
    fail('MUTATION_VERSION_UNSUPPORTED', `${label} declares an unsupported origin version`);
  }
  exact(origin, ['kind', 'receipt'], label, 'MUTATION_REUSE_DENIED');
  if (origin.kind !== MPE1_ORIGIN_KIND) denyReuse(`${label} kind is invalid`);
  return rebuildMutationPackageExecutionReceiptV1(origin.receipt, `${label}.receipt`);
}

/**
 * Selects the closed origin alternative a reused package declares. The union is
 * exactly two members: the embedded MPE1 envelope, discriminated by its `kind`,
 * and the existing complete semantic-receipt origin. Anything else refuses in the
 * validator for the route it selected.
 */
function reuseOriginRoute(origin) {
  return origin !== null &&
    typeof origin === 'object' &&
    !Array.isArray(origin) &&
    Object.hasOwn(origin, 'kind')
    ? 'execution-receipt'
    : 'semantic-receipt';
}

function validateReuseOriginUnion(origin, label) {
  if (reuseOriginRoute(origin) === 'execution-receipt') {
    validateMutationPackageExecutionOriginV1(origin, label);
    return 'execution-receipt';
  }
  validateSemanticReuseOriginShape(origin, label);
  return 'semantic-receipt';
}

/**
 * Verifies an embedded MPE1 against already verified portable values only.
 *
 * Every expectation is supplied by the caller: the external protected identities,
 * the required output-contract row, the recomputed immutable artifacts, the final
 * unit-receipt referent and the protected `expectedOutputContract` control. No host
 * brand, checkout, sink reader, candidate callback or live policy resolver
 * participates, so offline verification runs this check exactly as certification
 * does.
 */
export function verifyMutationPackageExecutionOriginV1(origin, expectations) {
  const label = `mutation package ${expectations.packageName} execution origin`;
  const control = expectations.expectedOutputContract;
  if (control === null || typeof control !== 'object' || Array.isArray(control)) {
    missingExpectation('expectedOutputContract');
  }
  validateOutputContractControlShape(control);
  const receipt = validateMutationPackageExecutionOriginV1(origin, label);
  const deny = (message) => denyReuse(`${label} ${message}`);
  if (receipt.repositoryId !== expectations.repositoryId) {
    deny('repository differs from the protected expectation');
  }
  if (canonicalize(receipt.candidate) !== canonicalize(expectations.candidate)) {
    deny('candidate identity differs; MPE1 never widens cross-candidate reuse');
  }
  if (
    receipt.releasePlanReceiptDigest !== expectations.releasePlanReceiptDigest ||
    receipt.releaseProfileDigest !== expectations.releaseProfileDigest ||
    receipt.policyDigest !== expectations.policyDigest
  ) {
    deny('plan, profile or policy identity differs from the protected expectation');
  }
  if (
    receipt.package.packageName !== expectations.packageName ||
    receipt.package.workspace !== expectations.workspace ||
    receipt.package.inputDigest !== expectations.inputDigest
  ) {
    deny('package input identity differs from the required output-contract row');
  }
  const binding = expectations.executionBinding;
  if (
    receipt.template.id !== binding.templateId ||
    receipt.template.version !== binding.templateVersion ||
    receipt.task.nodeId !== binding.taskNode ||
    receipt.task.policyDigest !== binding.taskPolicyDigest
  ) {
    deny('execution binding differs from the required output-contract row');
  }
  if (!expectations.taskPolicyDigests.includes(receipt.task.policyDigest)) {
    deny('task policy digest is absent from the final unit receipt referent');
  }
  if (canonicalize(receipt.verifierProvenance) !== canonicalize(expectations.verifierProvenance)) {
    deny('verifier provenance differs from the pinned canonical provenance');
  }
  for (const [kind, artifact, path, digest, sizeBytes] of [
    [
      'report',
      receipt.report,
      expectations.reportPath,
      expectations.reportDigest,
      expectations.reportSizeBytes,
    ],
    [
      'result',
      receipt.result,
      expectations.resultPath,
      expectations.resultDigest,
      expectations.resultSizeBytes,
    ],
  ]) {
    if (
      artifact.path === expectations.summaryPath ||
      artifact.path === expectations.semanticReceiptPath
    ) {
      deny(`${kind} path names the summary or semantic receipt`);
    }
    if (artifact.path === control.path) {
      deny(`${kind} path collides with the protected output-contract control`);
    }
    if (artifact.path !== path) deny(`${kind} path differs from the required output-contract row`);
    if (artifact.sha256 !== digest || artifact.sizeBytes !== sizeBytes) {
      deny(`${kind} digest or size differs from the immutable artifact`);
    }
    const member = expectations.members.get(artifact.path);
    if (member === undefined) deny(`${kind} path is not a final unit closure member`);
    if (member.sha256 !== artifact.sha256 || member.sizeBytes !== artifact.sizeBytes) {
      deny(`${kind} member digest or size differs from the final unit closure`);
    }
  }
  return { receiptId: receipt.receiptId, receiptDigest: receipt.receiptDigest };
}

function evidenceEntry(contractEntry, material, enforcePassing) {
  const { disposition, origin } = material;
  const label = `mutation result ${contractEntry.packageName}`;
  const checked = validateMutationPackagePair(contractEntry, material, {
    enforcePassing,
    reused: disposition === 'reused',
  });
  if (disposition !== 'executed' && disposition !== 'reused') {
    fail('MUTATION_SUMMARY_MISMATCH', `${label} disposition is invalid`);
  }
  if (disposition === 'executed' && origin !== null) {
    fail('MUTATION_ORIGIN_MISMATCH', `${label} executed origin must be null`);
  }
  if (disposition === 'reused') validateReuseOriginUnion(origin, `${label}.origin`);
  const evidenceRef = {
    kind: MUTATION_V22_EVIDENCE_REF_KIND,
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
    fail(
      'MUTATION_NOT_REQUIRED_MISMATCH',
      `${contractEntry.packageName} not-required decision differs`,
    );
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
  validateMutationContractV22(input.contract);
  validateCandidateIdentity(input.candidate, 'mutation candidate');
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
  const statusTotals = emptyStatusTotals();
  for (const entry of packages) {
    if (entry.requirement !== 'required') continue;
    for (const status of STATUSES) {
      statusTotals[status] = checkedStatusAdd(
        statusTotals[status],
        entry.statusTotals[status],
        `mutation aggregate.${status}`,
      );
    }
  }
  const required = packages.filter((entry) => entry.requirement === 'required');
  const detected = checkedStatusAdd(
    statusTotals.Killed,
    statusTotals.Timeout,
    'mutation aggregate detected',
  );
  const scored = checkedStatusAdd(
    checkedStatusAdd(detected, statusTotals.Survived, 'mutation aggregate scored'),
    statusTotals.NoCoverage,
    'mutation aggregate scored',
  );
  const complete = required.every((entry) => entry.complete);
  const passed = required.length > 0 && complete && required.every((entry) => entry.passed);
  const verdict =
    required.length === 0 ? 'not-applicable' : !complete ? 'unknown' : passed ? 'pass' : 'fail';
  const score = required.length === 0 || scored === 0 ? null : (detected / scored) * 100;
  return {
    schemaVersion: MUTATION_V22_SCHEMA,
    kind: MUTATION_V22_SUMMARY_KIND,
    candidate: input.candidate,
    complete,
    verdict,
    passed,
    packages,
    aggregate: {
      packageCount: packages.length,
      executedPackageCount: packages.filter((entry) => entry.disposition === 'executed').length,
      reusedPackageCount: packages.filter((entry) => entry.disposition === 'reused').length,
      notRequiredPackageCount: packages.filter((entry) => entry.disposition === 'not-required')
        .length,
      score,
      statusTotals,
      verdict,
      passed,
      evidenceSetDigest: framedDigest(DOMAINS.composition, packages),
    },
  };
}

/**
 * Pure v2.2 finalizer. It reads only the supplied immutable documents, opens no
 * process and resolves no origin: a reused origin is checked for exact closed
 * shape and, for MPE1, digest self-consistency only. External binding is the
 * verifier's job.
 */
export function finalizeMutationReportSetV22(input) {
  return finalizeMutationReportSet(input, false);
}

/**
 * Rebuilds the v2.2 semantic receipt from the verified contract and summary. The
 * receipt identifier is opaque and inside the digest payload, exactly as in v2.1,
 * so it is supplied rather than derived.
 */
export function buildMutationSemanticReceiptV22({
  contract,
  summary,
  receiptId,
  verifierProvenance,
}) {
  string(receiptId, 'mutation semantic receipt.receiptId', RECEIPT_ID, 'MUTATION_SEMANTIC_RECEIPT_MISMATCH');
  validateVerifierProvenance(verifierProvenance);
  const packages = contract.packages.map((contractEntry, index) => {
    const summaryEntry = summary.packages[index];
    const compositionEntryDigest = framedDigest(DOMAINS.compositionEntry, summaryEntry);
    return contractEntry.requirement === 'required'
      ? {
          packageName: contractEntry.packageName,
          disposition: summaryEntry.disposition,
          inputDigest: contractEntry.inputDigest,
          reportDigest: summaryEntry.reportDigest,
          resultDigest: summaryEntry.resultDigest,
          compositionEntryDigest,
        }
      : {
          packageName: contractEntry.packageName,
          disposition: summaryEntry.disposition,
          compositionEntryDigest,
        };
  });
  const resultSet = contract.packages
    .map((entry, index) => ({ entry, summary: summary.packages[index] }))
    .filter(({ entry }) => entry.requirement === 'required')
    .map(({ entry, summary: summaryEntry }) => ({
      packageName: entry.packageName,
      resultDigest: summaryEntry.resultDigest,
    }));
  const payload = {
    schemaVersion: MUTATION_V22_SCHEMA,
    kind: MUTATION_V22_SEMANTIC_RECEIPT_KIND,
    receiptId,
    candidate: summary.candidate,
    outputContractDigest: framedDigest(DOMAINS.outputContract, contract),
    releasePlanReceiptDigest: contract.releasePlanReceiptDigest,
    releaseProfileDigest: contract.releaseProfileDigest,
    policyDigest: contract.policyDigest,
    verifierProvenance,
    packages,
    packageResultSetDigest: framedDigest(DOMAINS.packageResultSet, resultSet),
    evidenceSetDigest: summary.aggregate.evidenceSetDigest,
    verdict: summary.verdict,
    semanticVerificationPerformed: true,
  };
  return { ...payload, receiptDigest: framedDigest(DOMAINS.semanticReceipt, payload) };
}

function validateSemanticReceipt(receipt, contract, summary, expectedProvenance) {
  exact(receipt, SEMANTIC_RECEIPT_KEYS, 'mutation semantic receipt', 'MUTATION_SEMANTIC_RECEIPT_MISMATCH');
  if (
    receipt.schemaVersion !== MUTATION_V22_SCHEMA ||
    receipt.kind !== MUTATION_V22_SEMANTIC_RECEIPT_KIND
  ) {
    fail('MUTATION_VERSION_UNSUPPORTED', 'mutation semantic receipt version is unsupported');
  }
  string(
    receipt.receiptId,
    'mutation semantic receipt.receiptId',
    RECEIPT_ID,
    'MUTATION_SEMANTIC_RECEIPT_MISMATCH',
  );
  validateVerifierProvenance(receipt.verifierProvenance);
  if (canonicalize(receipt.verifierProvenance) !== canonicalize(expectedProvenance)) {
    fail(
      'MUTATION_VENDOR_PROVENANCE_MISMATCH',
      'mutation semantic receipt provenance differs from the pinned canonical provenance',
    );
  }
  const expected = buildMutationSemanticReceiptV22({
    contract,
    summary,
    receiptId: receipt.receiptId,
    verifierProvenance: receipt.verifierProvenance,
  });
  if (canonicalize(receipt) !== canonicalize(expected)) {
    fail(
      'MUTATION_SEMANTIC_RECEIPT_MISMATCH',
      'mutation semantic receipt does not match its recomputed bindings',
    );
  }
}

function validateSummaryEntryIdentity(contractEntry, entry, result) {
  if (contractEntry.requirement === 'not-required') {
    if (entry?.reasonCode !== contractEntry.reasonCode) {
      fail(
        'MUTATION_NOT_REQUIRED_MISMATCH',
        `${contractEntry.packageName} not-required decision differs`,
      );
    }
    return;
  }
  const refKind = entry?.evidenceRef?.kind;
  if (
    typeof refKind === 'string' &&
    refKind !== MUTATION_V22_EVIDENCE_REF_KIND &&
    refKind.startsWith('mutation-package-evidence-ref-')
  ) {
    fail(
      'MUTATION_VERSION_UNSUPPORTED',
      `${contractEntry.packageName} evidence reference declares an unsupported version`,
    );
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

/**
 * Explicit version rejection: a mutation report-set summary from any branch this
 * kernel does not implement fails closed instead of falling through to a generic
 * summary comparison.
 */
function validateSummaryVersion(summary) {
  const kind = summary?.kind;
  if (typeof kind !== 'string' || !/^mutation-(?:composed-)?report-set-v\d+$/u.test(kind)) return;
  if (kind !== MUTATION_V22_SUMMARY_KIND || summary.schemaVersion !== MUTATION_V22_SCHEMA) {
    fail(
      'MUTATION_VERSION_UNSUPPORTED',
      'mutation summary declares an unsupported mutation report-set version',
    );
  }
}

function validateReferentTaskPolicyDigests(referent) {
  if (!Array.isArray(referent.taskPolicyDigests) || referent.taskPolicyDigests.length === 0) {
    missingExpectation('finalUnitReferent.taskPolicyDigests');
  }
  let previous;
  for (const [index, digest] of referent.taskPolicyDigests.entries()) {
    string(
      digest,
      `mutation final unit receipt referent taskPolicyDigests[${index}]`,
      SHA256,
      'MUTATION_OFFLINE_EXPECTATION_MISSING',
    );
    if (previous !== undefined && digest <= previous) {
      fail(
        'MUTATION_ROSTER_MISMATCH',
        'mutation final unit receipt referent task policy digests must be unique and sorted',
      );
    }
    previous = digest;
  }
}

function validateReferentMembers(contract, referent) {
  const requiredCount = contract.packages.filter(
    (entry) => entry.requirement === 'required',
  ).length;
  if (!Array.isArray(referent.members)) missingExpectation('finalUnitReferent.members');
  if (referent.members.length !== requiredCount * 2 + 2) {
    fail(
      'MUTATION_ROSTER_MISMATCH',
      'mutation final unit closure must contain exactly 2N + 2 members',
    );
  }
  const members = new Map();
  for (const [index, member] of referent.members.entries()) {
    const label = `mutation final unit closure member[${index}]`;
    exact(member, ['path', 'sha256', 'sizeBytes'], label, 'MUTATION_ROSTER_MISMATCH');
    validateV22Path(member.path, `${label}.path`, 'MUTATION_ROSTER_MISMATCH');
    string(member.sha256, `${label}.sha256`, SHA256, 'ARTIFACT_DIGEST_MISMATCH');
    safeCount(member.sizeBytes, `${label}.sizeBytes`, 'ARTIFACT_DIGEST_MISMATCH');
    if (members.has(member.path)) {
      fail('MUTATION_ROSTER_MISMATCH', 'mutation final unit closure members are duplicated');
    }
    members.set(member.path, member);
  }
  const actual = [...members.keys()].sort();
  const expected = [...contract.paths].sort();
  if (actual.length !== expected.length || actual.some((path, index) => path !== expected[index])) {
    fail(
      'MUTATION_ROSTER_MISMATCH',
      'mutation final unit closure members differ from the output-contract artifact roster',
    );
  }
  return members;
}

function validateExpectedExecutionBindings(contract, referent, supplied) {
  const bindings = new Map();
  for (const [index, entry] of supplied.entries()) {
    const label = `mutation expectedExecutionBindings[${index}]`;
    exact(
      entry,
      ['packageName', ...EXECUTION_BINDING_KEYS],
      label,
      'MUTATION_OFFLINE_EXPECTATION_MISSING',
    );
    const { packageName, ...binding } = entry;
    string(packageName, `${label}.packageName`, PACKAGE_NAME, 'MUTATION_OFFLINE_EXPECTATION_MISSING');
    validateExecutionBinding(binding, label, 'MUTATION_OFFLINE_EXPECTATION_MISSING');
    if (bindings.has(packageName)) {
      fail('MUTATION_ROSTER_MISMATCH', 'mutation expected execution bindings are duplicated');
    }
    bindings.set(packageName, binding);
  }
  const required = contract.packages.filter((entry) => entry.requirement === 'required');
  if (bindings.size !== required.length) {
    fail(
      'MUTATION_ROSTER_MISMATCH',
      'mutation expected execution bindings differ from the required package roster',
    );
  }
  for (const entry of required) {
    const expected = bindings.get(entry.packageName);
    if (expected === undefined) {
      missingExpectation(`${entry.packageName} expectedExecutionBinding`);
    }
    if (canonicalize(expected) !== canonicalize(entry.executionBinding)) {
      denyReuse(
        `${entry.packageName} execution binding differs from the protected expected binding`,
      );
    }
    if (!referent.taskPolicyDigests.includes(entry.executionBinding.taskPolicyDigest)) {
      denyReuse(
        `${entry.packageName} task policy digest is absent from the final unit receipt referent`,
      );
    }
  }
}

/**
 * Binds the protected output-contract control to the exact canonical contract
 * bytes. The control is independent host state: it is never a wire field, never a
 * final-closure member, and its path may not collide with any declared artifact.
 */
function validateOutputContractControl(control, contract, members) {
  validateOutputContractControlShape(control);
  const bytes = canonicalBytes(contract);
  if (control.sha256 !== sha256Hex(bytes) || control.sizeBytes !== bytes.length) {
    fail(
      'ARTIFACT_DIGEST_MISMATCH',
      'mutation expectedOutputContract does not bind the canonical output contract bytes',
    );
  }
  if (
    contract.paths.includes(control.path) ||
    control.path === contract.summaryPath ||
    control.path === contract.semanticReceiptPath ||
    members.has(control.path)
  ) {
    fail(
      'MUTATION_ROSTER_MISMATCH',
      'mutation expectedOutputContract path collides with a declared artifact or closure member',
    );
  }
}

/**
 * Collects the independent protected expectations. None of them may be inferred
 * from the summary, the semantic receipt or an origin: this routine only compares
 * the candidate-supplied output contract against externally supplied values. Every
 * expectation is captured here, before any external read or resolver callback runs.
 */
function validateProtectedExpectations(contract, options) {
  for (const name of [
    'releaseUnit',
    'candidateCommit',
    'candidateTree',
    'expectedRepositoryId',
    'expectedReleasePlanReceiptDigest',
    'expectedReleaseProfileDigest',
    'expectedPolicyDigest',
  ]) {
    if (typeof options[name] !== 'string' || options[name].length === 0) missingExpectation(name);
  }
  for (const name of [
    'expectedSemanticReceiptProvenance',
    'finalUnitReferent',
    'expectedOutputContract',
  ]) {
    const value = options[name];
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      missingExpectation(name);
    }
  }
  if (!Array.isArray(options.expectedExecutionBindings)) {
    missingExpectation('expectedExecutionBindings');
  }

  const repositoryId = options.expectedRepositoryId;
  const releasePlanReceiptDigest = options.expectedReleasePlanReceiptDigest;
  const releaseProfileDigest = options.expectedReleaseProfileDigest;
  const policyDigest = options.expectedPolicyDigest;
  const provenance = captureDocument(
    options.expectedSemanticReceiptProvenance,
    'mutation expectedSemanticReceiptProvenance',
    'MUTATION_OFFLINE_EXPECTATION_MISSING',
  );
  const referent = captureDocument(
    options.finalUnitReferent,
    'mutation finalUnitReferent',
    'MUTATION_OFFLINE_EXPECTATION_MISSING',
  );
  const control = captureDocument(
    options.expectedOutputContract,
    'mutation expectedOutputContract',
    'MUTATION_OFFLINE_EXPECTATION_MISSING',
  );
  const suppliedBindings = captureDocument(
    options.expectedExecutionBindings,
    'mutation expectedExecutionBindings',
    'MUTATION_OFFLINE_EXPECTATION_MISSING',
  );
  const candidate = {
    releaseUnit: options.releaseUnit,
    commit: options.candidateCommit,
    tree: options.candidateTree,
  };
  validateCandidateIdentity(candidate, 'mutation candidate expectation');
  string(repositoryId, 'mutation expectedRepositoryId', IDENTIFIER);
  for (const [name, value] of [
    ['expectedReleasePlanReceiptDigest', releasePlanReceiptDigest],
    ['expectedReleaseProfileDigest', releaseProfileDigest],
    ['expectedPolicyDigest', policyDigest],
  ]) {
    string(value, `mutation ${name}`, SHA256);
  }
  validateVerifierProvenance(provenance);
  if (
    contract.releasePlanReceiptDigest !== releasePlanReceiptDigest ||
    contract.releaseProfileDigest !== releaseProfileDigest ||
    contract.policyDigest !== policyDigest
  ) {
    fail(
      'MUTATION_SEMANTIC_RECEIPT_MISMATCH',
      'mutation output contract plan, profile or policy identity differs from the protected expectation',
    );
  }

  exact(
    referent,
    REFERENT_KEYS,
    'mutation final unit receipt referent',
    'MUTATION_OFFLINE_EXPECTATION_MISSING',
  );
  string(
    referent.repositoryId,
    'mutation final unit receipt referent.repositoryId',
    IDENTIFIER,
    'MUTATION_OFFLINE_EXPECTATION_MISSING',
  );
  validateCandidateIdentity(referent.candidate, 'mutation final unit receipt referent.candidate');
  if (
    referent.repositoryId !== repositoryId ||
    canonicalize(referent.candidate) !== canonicalize(candidate) ||
    referent.releasePlanReceiptDigest !== releasePlanReceiptDigest ||
    referent.releaseProfileDigest !== releaseProfileDigest ||
    referent.policyDigest !== policyDigest
  ) {
    fail(
      'MUTATION_SEMANTIC_RECEIPT_MISMATCH',
      'mutation final unit receipt referent differs from the protected expectation',
    );
  }
  validateReferentTaskPolicyDigests(referent);
  const members = validateReferentMembers(contract, referent);
  validateExpectedExecutionBindings(contract, referent, suppliedBindings);
  validateOutputContractControl(control, contract, members);
  return {
    candidate,
    control,
    members,
    policyDigest,
    provenance,
    referent,
    releasePlanReceiptDigest,
    releaseProfileDigest,
    repositoryId,
  };
}

/**
 * Verifies a complete `2.2.0` report set.
 *
 * `readArtifact(path, label)` returns the exact `{ value, bytes }` canonical
 * snapshot. Every snapshot is immediately recaptured: the document verified and the
 * bytes bound into the closure are the same private copy, so a later callback
 * cannot change the meaning of an earlier row. The output contract and every
 * protected expectation are captured before the first callback runs.
 *
 * This kernel opens no path, spawns no process, makes no network request and never
 * resolves an MPE1 origin through a callback. The complete semantic-receipt origin
 * keeps its existing route: it is resolved exactly once in `certify` mode through
 * the protected `resolveReuseOrigin`, under the producing document's own version
 * branch, and offline verification's boundary stays the signed current semantic
 * receipt and the portable closure.
 */
export function verifyMutationReportSetV22(suppliedContract, readArtifact, options = {}) {
  const contract = captureDocument(suppliedContract, 'mutation output contract');
  validateMutationContractV22(contract);
  if (
    options.mutationVerificationMode !== undefined &&
    options.mutationVerificationMode !== 'certify' &&
    options.mutationVerificationMode !== 'offline'
  ) {
    fail('SCHEMA_INVALID', 'mutation verification mode is invalid');
  }
  const verificationOptions = {
    mutationVerificationMode: options.mutationVerificationMode ?? 'certify',
    resolveReuseOrigin: options.resolveReuseOrigin,
  };
  const expectations = validateProtectedExpectations(contract, options);

  const summaryFile = captureArtifact(readArtifact, contract.summaryPath, 'mutation summary');
  const receiptFile = captureArtifact(
    readArtifact,
    contract.semanticReceiptPath,
    'mutation semantic receipt',
  );
  const summary = summaryFile.value;
  object(summary, 'mutation summary', 'MUTATION_SUMMARY_MISMATCH');
  validateSummaryVersion(summary);
  if (!Array.isArray(summary.packages) || summary.packages.length !== contract.packages.length) {
    fail('MUTATION_ROSTER_MISMATCH', 'mutation summary package roster differs');
  }

  const materials = [];
  const artifacts = new Map();
  for (const [index, contractEntry] of contract.packages.entries()) {
    const summaryEntry = summary.packages[index];
    if (
      summaryEntry?.packageName !== contractEntry.packageName ||
      summaryEntry?.workspace !== contractEntry.workspace
    ) {
      fail('MUTATION_ROSTER_MISMATCH', `mutation package ${index} identity differs`);
    }
    if (contractEntry.requirement === 'not-required') {
      validateSummaryEntryIdentity(contractEntry, summaryEntry);
      materials.push({ disposition: 'not-required', reasonCode: summaryEntry.reasonCode });
      continue;
    }
    const reportFile = captureArtifact(
      readArtifact,
      contractEntry.reportPath,
      `mutation report ${contractEntry.packageName}`,
    );
    const resultFile = captureArtifact(
      readArtifact,
      contractEntry.resultPath,
      `mutation result ${contractEntry.packageName}`,
    );
    validateSummaryEntryIdentity(contractEntry, summaryEntry, resultFile.value);
    artifacts.set(contractEntry.reportPath, {
      sha256: reportFile.sha256,
      sizeBytes: reportFile.sizeBytes,
    });
    artifacts.set(contractEntry.resultPath, {
      sha256: resultFile.sha256,
      sizeBytes: resultFile.sizeBytes,
    });
    materials.push({
      disposition: summaryEntry.disposition,
      origin: summaryEntry.origin,
      report: reportFile.value,
      result: resultFile.value,
    });
  }

  const expectedSummary = finalizeMutationReportSet(
    { contract, candidate: expectations.candidate, packages: materials },
    true,
  );

  const executionOrigins = [];
  for (const [index, entry] of expectedSummary.packages.entries()) {
    if (entry.requirement !== 'required' || entry.disposition !== 'reused') continue;
    const contractEntry = contract.packages[index];
    if (reuseOriginRoute(entry.origin) === 'semantic-receipt') {
      validateTrustedSemanticReuseOrigin(
        entry.origin,
        entry,
        verificationOptions,
        selectProducingBranch,
      );
      continue;
    }
    const identity = verifyMutationPackageExecutionOriginV1(entry.origin, {
      packageName: entry.packageName,
      workspace: entry.workspace,
      inputDigest: entry.inputDigest,
      reportPath: contractEntry.reportPath,
      resultPath: contractEntry.resultPath,
      reportDigest: entry.reportDigest,
      resultDigest: entry.resultDigest,
      reportSizeBytes: artifacts.get(contractEntry.reportPath).sizeBytes,
      resultSizeBytes: artifacts.get(contractEntry.resultPath).sizeBytes,
      executionBinding: contractEntry.executionBinding,
      repositoryId: expectations.repositoryId,
      candidate: expectations.candidate,
      releasePlanReceiptDigest: expectations.releasePlanReceiptDigest,
      releaseProfileDigest: expectations.releaseProfileDigest,
      policyDigest: expectations.policyDigest,
      verifierProvenance: expectations.provenance,
      taskPolicyDigests: expectations.referent.taskPolicyDigests,
      members: expectations.members,
      expectedOutputContract: expectations.control,
      summaryPath: contract.summaryPath,
      semanticReceiptPath: contract.semanticReceiptPath,
    });
    executionOrigins.push({ packageName: entry.packageName, ...identity });
  }

  if (canonicalize(summary) !== canonicalize(expectedSummary)) {
    fail('MUTATION_SUMMARY_MISMATCH', 'mutation summary does not match immutable package evidence');
  }
  validateSemanticReceipt(receiptFile.value, contract, summary, expectations.provenance);

  // Exact 2N + 2 conjunction: every member of the final unit closure is one of the
  // documents this verification just reread, at the exact path, digest and size.
  const snapshots = [
    {
      path: contract.summaryPath,
      sha256: summaryFile.sha256,
      sizeBytes: summaryFile.sizeBytes,
    },
    {
      path: contract.semanticReceiptPath,
      sha256: receiptFile.sha256,
      sizeBytes: receiptFile.sizeBytes,
    },
    ...[...artifacts.entries()].map(([path, snapshot]) => ({ path, ...snapshot })),
  ];
  if (snapshots.length !== expectations.members.size) {
    fail(
      'MUTATION_ROSTER_MISMATCH',
      'mutation final unit closure member population differs from the verified documents',
    );
  }
  for (const snapshot of snapshots) {
    const member = expectations.members.get(snapshot.path);
    if (member === undefined) {
      fail(
        'MUTATION_ROSTER_MISMATCH',
        `mutation final unit closure member ${snapshot.path} is absent`,
      );
    }
    if (member.sha256 !== snapshot.sha256 || member.sizeBytes !== snapshot.sizeBytes) {
      fail(
        'ARTIFACT_DIGEST_MISMATCH',
        `mutation final unit closure member ${snapshot.path} differs after reread`,
      );
    }
  }

  return {
    schemaVersion: MUTATION_V22_SCHEMA,
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
    memberCount: snapshots.length,
    executionOrigins,
    resultDigests: summary.packages
      .filter((entry) => entry.requirement === 'required')
      .map((entry) => entry.resultDigest),
    reportDigests: summary.packages
      .filter((entry) => entry.requirement === 'required')
      .map((entry) => entry.reportDigest),
  };
}

export { DOMAINS as MUTATION_V22_DIGEST_DOMAINS };

import { createPublicKey, verify as verifySignature } from 'node:crypto';
import { readdirSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { artifactMediaType, validateArtifactContent } from './artifact-safety.js';
import {
  VerificationError,
  assertExactKeys,
  assertObject,
  assertString,
  assertUniqueStrings,
  canonicalBytes,
  sha256Hex,
} from './canonical.js';
import {
  mutationContractVersion,
  validateMutationContract,
  verifyMutationReportSet,
} from './mutation.js';
import { readAbsoluteRegularFile, readRootRelativeRegularFile } from './safe-path.js';
import { resolveTrustedSigner } from './trust.js';

const SHA256 = /^[0-9a-f]{64}$/u;
const GIT_OBJECT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const PAYLOAD_TYPE = 'application/vnd.devai.candidate-receipt+json;version=1';
const PORTABLE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\\)(?!.*\0)[^/]+(?:\/[^/]+)*$/u;

function validateOutputContract(contract, label) {
  assertObject(contract, label);
  canonicalBytes(contract);
  if (contract.paths === undefined) {
    // A mutation report set declares its own artifact roster, so a pathless one is
    // never a legitimately artifact-free contract: validate it here rather than
    // letting the generic no-paths return skip every mutation check below.
    if (mutationContractVersion(contract.kind, label) !== undefined) {
      validateMutationContract(contract, label);
    }
    return;
  }
  assertUniqueStrings(contract.paths, `${label}.paths`);
  if (contract.paths.length === 0) {
    throw new VerificationError('SCHEMA_INVALID', `${label}.paths must be nonempty when present`);
  }
  for (const path of contract.paths) assertString(path, `${label} path`, PORTABLE_PATH);
  if (mutationContractVersion(contract.kind, label) !== undefined) {
    validateMutationContract(contract, label);
  }
}

export function validateTaskPolicy(policy) {
  assertExactKeys(policy, ['repositoryId', 'requiredNodes', 'schemaVersion'], 'task policy');
  if (policy.schemaVersion !== '1.0.0' && policy.schemaVersion !== '1.1.0') {
    throw new VerificationError('SCHEMA_INVALID', 'unsupported task-policy schemaVersion');
  }
  assertString(policy.repositoryId, 'task policy repositoryId', IDENTIFIER);
  if (!Array.isArray(policy.requiredNodes) || policy.requiredNodes.length === 0) {
    throw new VerificationError('SCHEMA_INVALID', 'task policy requiredNodes must be nonempty');
  }
  const nodeIds = [];
  for (const [index, node] of policy.requiredNodes.entries()) {
    const label = `task policy requiredNodes[${index}]`;
    const keys = ['dependencies', 'nodeId', 'taskKey'];
    if (policy.schemaVersion === '1.1.0') keys.push('outputContract');
    assertExactKeys(node, keys, label);
    assertString(node.nodeId, `${label}.nodeId`, IDENTIFIER);
    assertString(node.taskKey, `${label}.taskKey`, SHA256);
    assertUniqueStrings(node.dependencies, `${label}.dependencies`);
    if (policy.schemaVersion === '1.1.0') {
      validateOutputContract(node.outputContract, `${label}.outputContract`);
    }
    nodeIds.push(node.nodeId);
  }
  assertUniqueStrings(nodeIds, 'task policy node IDs');
  const known = new Set(nodeIds);
  for (const node of policy.requiredNodes) {
    for (const dependency of node.dependencies) {
      if (!known.has(dependency)) {
        throw new VerificationError(
          'SCHEMA_INVALID',
          `node ${node.nodeId} names unknown dependency ${dependency}`,
        );
      }
    }
  }
  const visiting = new Set();
  const visited = new Set();
  const byId = new Map(policy.requiredNodes.map((node) => [node.nodeId, node]));
  const visit = (nodeId) => {
    if (visiting.has(nodeId)) {
      throw new VerificationError('SCHEMA_INVALID', `task policy contains a cycle at ${nodeId}`);
    }
    if (visited.has(nodeId)) return;
    visiting.add(nodeId);
    for (const dependency of byId.get(nodeId).dependencies) visit(dependency);
    visiting.delete(nodeId);
    visited.add(nodeId);
  };
  for (const nodeId of nodeIds) visit(nodeId);
}

function validateEnvelope(envelope) {
  assertExactKeys(envelope, ['payload', 'payloadType', 'schemaVersion', 'signatures'], 'envelope');
  if (envelope.schemaVersion !== '1.0.0' || envelope.payloadType !== PAYLOAD_TYPE) {
    throw new VerificationError('SCHEMA_INVALID', 'unsupported signed envelope');
  }
  assertString(envelope.payload, 'envelope payload', /^[A-Za-z0-9+/]+={0,2}$/u);
  if (!Array.isArray(envelope.signatures) || envelope.signatures.length !== 1) {
    throw new VerificationError('SCHEMA_INVALID', 'envelope must have exactly one signature');
  }
  assertExactKeys(envelope.signatures[0], ['signature', 'signerId'], 'envelope signature');
  assertString(envelope.signatures[0].signerId, 'envelope signerId', IDENTIFIER);
  assertString(
    envelope.signatures[0].signature,
    'envelope signature bytes',
    /^[A-Za-z0-9+/]+={0,2}$/u,
  );
}

function validateReceipt(receipt) {
  assertExactKeys(
    receipt,
    ['createdAt', 'profile', 'repository', 'schemaVersion', 'taskPolicyDigest', 'tasks'],
    'candidate receipt',
  );
  if (receipt.schemaVersion !== '1.0.0' && receipt.schemaVersion !== '1.1.0') {
    throw new VerificationError('SCHEMA_INVALID', 'unsupported candidate-receipt schemaVersion');
  }
  assertExactKeys(receipt.repository, ['commit', 'id', 'tree'], 'candidate receipt repository');
  assertString(receipt.repository.id, 'candidate receipt repository ID', IDENTIFIER);
  assertString(receipt.repository.commit, 'candidate receipt commit', GIT_OBJECT);
  assertString(receipt.repository.tree, 'candidate receipt tree', GIT_OBJECT);
  assertString(receipt.taskPolicyDigest, 'candidate receipt taskPolicyDigest', SHA256);
  if (receipt.profile !== 'affected' && receipt.profile !== 'rc') {
    throw new VerificationError('SCHEMA_INVALID', 'candidate receipt profile is invalid');
  }
  assertString(receipt.createdAt, 'candidate receipt createdAt');
  if (!Array.isArray(receipt.tasks)) {
    throw new VerificationError('SCHEMA_INVALID', 'candidate receipt tasks must be an array');
  }
  const ids = [];
  for (const [index, task] of receipt.tasks.entries()) {
    const label = `candidate receipt tasks[${index}]`;
    assertExactKeys(task, ['nodeId', 'resultDigest', 'taskKey'], label);
    assertString(task.nodeId, `${label}.nodeId`, IDENTIFIER);
    assertString(task.taskKey, `${label}.taskKey`, SHA256);
    assertString(task.resultDigest, `${label}.resultDigest`, SHA256);
    ids.push(task.nodeId);
  }
  assertUniqueStrings(ids, 'candidate receipt node IDs');
}

function validateTaskResult(result, label) {
  assertExactKeys(
    result,
    [
      'dependencyResultDigests',
      'finishedAt',
      'inputDigest',
      'nodeId',
      'outputDigests',
      'schemaVersion',
      'startedAt',
      'status',
      'taskKey',
    ],
    label,
  );
  if (result.schemaVersion !== '1.0.0') {
    throw new VerificationError('SCHEMA_INVALID', `${label} schemaVersion is unsupported`);
  }
  assertString(result.nodeId, `${label}.nodeId`, IDENTIFIER);
  assertString(result.taskKey, `${label}.taskKey`, SHA256);
  assertString(result.inputDigest, `${label}.inputDigest`, SHA256);
  assertString(result.startedAt, `${label}.startedAt`);
  assertString(result.finishedAt, `${label}.finishedAt`);
  assertObject(result.dependencyResultDigests, `${label}.dependencyResultDigests`);
  assertObject(result.outputDigests, `${label}.outputDigests`);
  for (const [key, digest] of Object.entries(result.dependencyResultDigests)) {
    assertString(key, `${label} dependency ID`, IDENTIFIER);
    assertString(digest, `${label} dependency digest`, SHA256);
  }
  for (const [key, digest] of Object.entries(result.outputDigests)) {
    assertString(key, `${label} output name`, PORTABLE_PATH);
    assertString(digest, `${label} output digest`, SHA256);
  }
  if (result.status !== 'PASS') {
    const rendered = typeof result.status === 'string' ? result.status : '<malformed>';
    throw new VerificationError('TASK_STATUS_NOT_PASS', `${label} status is ${rendered}, not PASS`);
  }
}

/**
 * Reads one digest-named task-result file through the same fail-closed file contract the
 * export staging step applies. The exact path is inspected with lstat before any read, so
 * a symbolic link is refused here rather than followed into bytes outside the results
 * directory. Every failure reports a stable code and a message built only from the caller
 * label, so neither host paths nor file contents leak into verifier output.
 */
function readTaskResultFile(resultsDir, resultDigest, label) {
  let text;
  try {
    text = readRootRelativeRegularFile(resultsDir, `${resultDigest}.json`, label).toString('utf8');
  } catch (error) {
    if (error instanceof VerificationError && error.code === 'ARTIFACT_SYMLINK_ESCAPE') {
      throw new VerificationError('RESULT_INVALID', `${label} must be a regular non-symlink file`);
    }
    if (error instanceof VerificationError && error.code === 'ARTIFACTS_MISSING') {
      throw new VerificationError('INPUT_MISSING', `${label} is unavailable`);
    }
    if (error instanceof VerificationError) throw error;
    throw new VerificationError('INPUT_MISSING', `${label} is unreadable`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new VerificationError('MALFORMED_JSON', `${label} is not valid JSON`);
  }
}

function artifactPaths(policy) {
  const paths = new Set();
  for (const node of policy.requiredNodes) {
    if (policy.schemaVersion !== '1.1.0') continue;
    for (const path of node.outputContract.paths ?? []) paths.add(path);
  }
  return [...paths].sort();
}

function filesBelow(root, current = root) {
  const files = [];
  for (const entry of readdirSync(current, { withFileTypes: true })) {
    const absolute = join(current, entry.name);
    if (entry.isSymbolicLink()) {
      throw new VerificationError('ARTIFACT_SYMLINK', 'artifact bundle contains a symbolic link');
    }
    if (entry.isDirectory()) files.push(...filesBelow(root, absolute));
    else if (entry.isFile()) files.push(relative(root, absolute).split(sep).join('/'));
    else
      throw new VerificationError(
        'ARTIFACT_INVALID',
        'artifact bundle contains a non-regular file',
      );
  }
  return files;
}

function verifyArtifacts(
  policy,
  results,
  artifactsDir,
  candidate,
  allowAdditionalArtifactFiles = false,
  mutationVerification = {},
) {
  const expectedPaths = artifactPaths(policy);
  // Legacy results did not declare an exact stdout/stderr/artifact population.
  // A pathless v1.1 contract still declares exactly the two stream digests.
  if (policy.schemaVersion === '1.0.0') return { paths: [], mutation: [] };
  if (expectedPaths.length > 0 && typeof artifactsDir !== 'string') {
    throw new VerificationError(
      'ARTIFACTS_MISSING',
      'schema 1.1 output artifacts directory is required',
    );
  }
  if (!allowAdditionalArtifactFiles && typeof artifactsDir === 'string') {
    let actualPaths;
    try {
      actualPaths = filesBelow(resolve(artifactsDir)).sort();
    } catch (error) {
      if (error instanceof VerificationError) throw error;
      throw new VerificationError('ARTIFACTS_MISSING', 'artifact directory is unreadable');
    }
    if (
      actualPaths.length !== expectedPaths.length ||
      actualPaths.some((path, index) => path !== expectedPaths[index])
    ) {
      throw new VerificationError(
        'ARTIFACT_POPULATION_MISMATCH',
        'artifact population differs from policy',
      );
    }
  }
  const policyById = new Map(policy.requiredNodes.map((node) => [node.nodeId, node]));
  for (const [nodeId, result] of results) {
    const outputContract = policyById.get(nodeId).outputContract;
    const paths = outputContract.paths ?? [];
    const expectedOutputNames = ['stderr', 'stdout', ...paths].sort();
    const actualOutputNames = Object.keys(result.outputDigests).sort();
    if (
      actualOutputNames.length !== expectedOutputNames.length ||
      actualOutputNames.some((name, index) => name !== expectedOutputNames[index])
    ) {
      throw new VerificationError(
        'OUTPUT_POPULATION_MISMATCH',
        `node ${nodeId} output population differs`,
      );
    }
    for (const path of paths) {
      const bytes = readRootRelativeRegularFile(artifactsDir, path, `artifact ${path}`);
      validateArtifactContent({
        bytes,
        path,
        mediaType: artifactMediaType(path),
      });
      const actualDigest = sha256Hex(bytes);
      if (result.outputDigests[path] !== actualDigest) {
        throw new VerificationError(
          'ARTIFACT_DIGEST_MISMATCH',
          `artifact ${path} digest does not match`,
        );
      }
    }
  }
  const mutation = [];
  for (const node of policy.requiredNodes) {
    if (mutationContractVersion(node.outputContract.kind) === undefined) continue;
    mutation.push({
      nodeId: node.nodeId,
      ...verifyMutationReportSet(node.outputContract, artifactsDir, {
        ...candidate,
        releaseUnit: policy.repositoryId,
        ...mutationVerification,
      }),
    });
  }
  return { paths: expectedPaths, mutation };
}

function validateVerificationContext({
  resultsDir,
  taskPolicy,
  expectedRepository,
  expectedCommit,
  expectedTree,
  expectedPolicyDigest,
  bindingMode = 'exact-commit',
}) {
  validateTaskPolicy(taskPolicy);
  assertString(resultsDir, 'task results directory');
  assertString(expectedRepository, 'expected repository', IDENTIFIER);
  assertString(expectedCommit, 'expected commit', GIT_OBJECT);
  assertString(expectedTree, 'expected tree', GIT_OBJECT);
  assertString(expectedPolicyDigest, 'expected policy digest', SHA256);
  if (bindingMode !== 'exact-commit' && bindingMode !== 'exact-tree') {
    throw new VerificationError(
      'SCHEMA_INVALID',
      'binding mode must be exact-commit or exact-tree',
    );
  }

  const actualPolicyDigest = sha256Hex(taskPolicy);
  if (actualPolicyDigest !== expectedPolicyDigest) {
    throw new VerificationError(
      'POLICY_DIGEST_MISMATCH',
      'task-policy bytes do not match the pinned digest',
    );
  }
  if (taskPolicy.repositoryId !== expectedRepository) {
    throw new VerificationError('REPOSITORY_MISMATCH', 'task policy belongs to another repository');
  }
}

function verifyValidatedCandidateReceipt({
  receipt,
  resultsDir,
  taskPolicy,
  expectedRepository,
  expectedCommit,
  expectedTree,
  expectedPolicyDigest,
  bindingMode,
  artifactsDir,
  signerId,
  allowAdditionalArtifactFiles = false,
  expectedResultDigests,
  mutationVerification,
}) {
  validateReceipt(receipt);
  if (receipt.repository.id !== expectedRepository) {
    throw new VerificationError(
      'REPOSITORY_MISMATCH',
      'candidate receipt repository does not match',
    );
  }
  if (bindingMode === 'exact-commit' && receipt.repository.commit !== expectedCommit) {
    throw new VerificationError('COMMIT_MISMATCH', 'candidate receipt commit does not match');
  }
  if (receipt.repository.tree !== expectedTree) {
    throw new VerificationError('TREE_MISMATCH', 'candidate receipt tree does not match');
  }
  if (receipt.taskPolicyDigest !== expectedPolicyDigest) {
    throw new VerificationError(
      'POLICY_DIGEST_MISMATCH',
      'candidate receipt policy digest does not match',
    );
  }

  const expectedById = new Map(taskPolicy.requiredNodes.map((node) => [node.nodeId, node]));
  const receiptById = new Map(receipt.tasks.map((task) => [task.nodeId, task]));
  if (expectedResultDigests !== undefined) {
    const expectedResults = [...expectedResultDigests].sort();
    const receiptResults = receipt.tasks.map((task) => task.resultDigest).sort();
    if (
      expectedResults.length !== receiptResults.length ||
      expectedResults.some((digest, index) => digest !== receiptResults[index])
    ) {
      throw new VerificationError(
        'RESULT_SET_MISMATCH',
        'signed receipt and manifest task-result populations differ',
      );
    }
  }
  const expectedIds = [...expectedById.keys()].sort();
  const receiptIds = [...receiptById.keys()].sort();
  if (
    expectedIds.length !== receiptIds.length ||
    expectedIds.some((nodeId, index) => nodeId !== receiptIds[index])
  ) {
    throw new VerificationError(
      'NODE_POPULATION_MISMATCH',
      'candidate receipt does not contain exactly the required node population',
    );
  }

  const results = new Map();
  for (const nodeId of expectedIds) {
    const expected = expectedById.get(nodeId);
    const task = receiptById.get(nodeId);
    if (task.taskKey !== expected.taskKey) {
      throw new VerificationError('TASK_KEY_STALE', `node ${nodeId} has a stale task key`);
    }
    const result = readTaskResultFile(resultsDir, task.resultDigest, `task result ${nodeId}`);
    if (sha256Hex(result) !== task.resultDigest) {
      throw new VerificationError(
        'RESULT_DIGEST_MISMATCH',
        `task result ${nodeId} digest does not match`,
      );
    }
    validateTaskResult(result, `task result ${nodeId}`);
    if (result.nodeId !== nodeId || result.taskKey !== expected.taskKey) {
      throw new VerificationError('TASK_KEY_STALE', `task result ${nodeId} is not current`);
    }
    results.set(nodeId, result);
  }

  for (const nodeId of expectedIds) {
    const expected = expectedById.get(nodeId);
    const result = results.get(nodeId);
    const actualDependencies = Object.keys(result.dependencyResultDigests).sort();
    const expectedDependencies = [...expected.dependencies].sort();
    if (
      actualDependencies.length !== expectedDependencies.length ||
      actualDependencies.some((dependency, index) => dependency !== expectedDependencies[index])
    ) {
      throw new VerificationError(
        'DEPENDENCY_MISMATCH',
        `node ${nodeId} dependency population differs`,
      );
    }
    for (const dependency of expectedDependencies) {
      if (result.dependencyResultDigests[dependency] !== receiptById.get(dependency).resultDigest) {
        throw new VerificationError(
          'DEPENDENCY_MISMATCH',
          `node ${nodeId} has a stale dependency result`,
        );
      }
    }
  }

  const verifiedArtifactSet = verifyArtifacts(
    taskPolicy,
    results,
    artifactsDir,
    {
      candidateCommit: receipt.repository.commit,
      candidateTree: receipt.repository.tree,
    },
    allowAdditionalArtifactFiles,
    mutationVerification,
  );

  return {
    ok: true,
    repository: expectedRepository,
    commit: expectedCommit,
    evidenceCommit: receipt.repository.commit,
    tree: expectedTree,
    binding: bindingMode,
    profile: receipt.profile,
    ...(signerId !== undefined && { signerId }),
    policyDigest: expectedPolicyDigest,
    verifiedNodes: expectedIds,
    verifiedArtifacts: verifiedArtifactSet.paths,
    verifiedMutation: verifiedArtifactSet.mutation,
  };
}

/**
 * Verifies an already-decoded candidate receipt and all referenced result/artifact
 * semantics without performing envelope authentication or any signing operation.
 * Callers must keep this distinct from trusted signed-envelope verification.
 */
export function verifyCandidateReceiptEvidence({
  receipt,
  resultsDir,
  taskPolicy,
  expectedRepository,
  expectedCommit,
  expectedTree,
  expectedPolicyDigest,
  bindingMode = 'exact-commit',
  artifactsDir,
  allowAdditionalArtifactFiles = false,
  resolveReuseOrigin,
  mutationExpectations,
}) {
  const context = {
    resultsDir,
    taskPolicy,
    expectedRepository,
    expectedCommit,
    expectedTree,
    expectedPolicyDigest,
    bindingMode,
    artifactsDir,
    allowAdditionalArtifactFiles,
    mutationVerification: {
      // Independent protected expectations only. A forward mutation branch that
      // needs them refuses when the caller does not supply them; nothing here is
      // inferred from the candidate, its receipt or its summary.
      ...mutationExpectations,
      mutationVerificationMode: 'certify',
      resolveReuseOrigin,
    },
  };
  validateVerificationContext(context);
  return verifyValidatedCandidateReceipt({ ...context, receipt });
}

export function verifyCandidateEvidence({
  envelope,
  resultsDir,
  taskPolicy,
  trustStore,
  expectedRepository,
  expectedCommit,
  expectedTree,
  expectedPolicyDigest,
  bindingMode = 'exact-commit',
  artifactsDir,
  expectedSignerId,
  expectedTrustRootId,
  expectedTrustStoreDigest,
  expectedKeyId,
  expectedResultDigests,
  resolveReuseOrigin,
  mutationExpectations,
}) {
  const context = {
    resultsDir,
    taskPolicy,
    expectedRepository,
    expectedCommit,
    expectedTree,
    expectedPolicyDigest,
    bindingMode,
    artifactsDir,
    expectedResultDigests,
    mutationVerification: {
      ...mutationExpectations,
      mutationVerificationMode: 'offline',
      ...(resolveReuseOrigin !== undefined && { resolveReuseOrigin }),
    },
  };
  validateVerificationContext(context);
  validateEnvelope(envelope);

  const signature = envelope.signatures[0];
  const signer = resolveTrustedSigner({
    trustStore,
    signerId: signature.signerId,
    expectedSignerId,
    expectedTrustRootId,
    expectedTrustStoreDigest,
    expectedKeyId,
  });

  const payloadBytes = Buffer.from(envelope.payload, 'base64');
  if (
    !verifySignature(
      null,
      payloadBytes,
      createPublicKey(signer.publicKeyPem),
      Buffer.from(signature.signature, 'base64'),
    )
  ) {
    throw new VerificationError('SIGNATURE_INVALID', 'candidate receipt signature is invalid');
  }

  let receipt;
  try {
    receipt = JSON.parse(payloadBytes.toString('utf8'));
  } catch (error) {
    throw new VerificationError(
      'MALFORMED_JSON',
      `candidate receipt payload is invalid: ${error.message}`,
    );
  }
  validateReceipt(receipt);
  if (!payloadBytes.equals(canonicalBytes(receipt))) {
    throw new VerificationError(
      'NON_CANONICAL_JSON',
      'candidate receipt payload is not canonical JSON',
    );
  }
  return verifyValidatedCandidateReceipt({
    ...context,
    receipt,
    signerId: signature.signerId,
  });
}

export function loadAndVerify(options) {
  const parseSafeJson = (path, label) => {
    let bytes;
    try {
      bytes = readAbsoluteRegularFile(path, label);
    } catch (error) {
      if (error instanceof VerificationError) throw error;
      throw new VerificationError('INPUT_MISSING', `${label} is unavailable`);
    }
    try {
      return JSON.parse(bytes.toString('utf8'));
    } catch {
      throw new VerificationError('MALFORMED_JSON', `${label} is not valid JSON`);
    }
  };
  const trustStore = parseSafeJson(options.trustStorePath, 'trust store');
  return verifyCandidateEvidence({
    ...options,
    envelope: parseSafeJson(options.envelopePath, 'signed envelope'),
    taskPolicy: parseSafeJson(options.taskPolicyPath, 'task policy'),
    trustStore,
  });
}

export { PAYLOAD_TYPE };

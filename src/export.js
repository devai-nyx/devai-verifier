import { execFileSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { artifactMediaType, validateArtifactContent } from './artifact-safety.js';
import {
  VerificationError,
  assertString,
  canonicalBytes,
  canonicalize,
  sha256Hex,
} from './canonical.js';
import { buildExpectedTaskPolicy, readEnvironmentMap, readStringMap } from './policy-builder.js';
import { mutationContractVersion } from './mutation.js';
import { MUTATION_V21_SCHEMA } from './mutation-v21.js';
import { MUTATION_V22_SCHEMA } from './mutation-v22.js';
import { PAYLOAD_TYPE, verifyCandidateEvidence, verifyCandidateReceiptEvidence } from './verify.js';
import {
  copyRootRelativeRegularFile,
  readAbsoluteRegularFile,
  readRootRelativeRegularFile,
} from './safe-path.js';

const GIT_OBJECT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;

function git(repo, args) {
  try {
    return execFileSync('git', ['-C', repo, ...args], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    }).trim();
  } catch (error) {
    throw new VerificationError('GIT_ERROR', `git ${args[0]} failed: ${error.message}`);
  }
}

function outsideRepository(repo, path, label) {
  let root;
  try {
    root = realpathSync(repo);
  } catch {
    throw new VerificationError('REPOSITORY_INVALID', 'candidate repository is unreadable');
  }
  const absolute = resolve(path);
  let resolvedParent;
  try {
    resolvedParent = realpathSync(dirname(absolute));
  } catch {
    throw new VerificationError('INPUT_PARENT_MISSING', `${label} parent is unavailable`);
  }
  const candidate = join(resolvedParent, absolute.slice(dirname(absolute).length + 1));
  const pathFromRoot = relative(root, candidate);
  if (pathFromRoot === '' || (!pathFromRoot.startsWith(`..${sep}`) && pathFromRoot !== '..')) {
    throw new VerificationError(
      'TRUST_BOUNDARY_INVALID',
      `${label} must be outside the candidate repository`,
    );
  }
  return absolute;
}

function outputDestination(repo, path) {
  const absolute = resolve(path);
  const parent = dirname(absolute);
  let parentStat;
  try {
    parentStat = lstatSync(parent);
  } catch {
    throw new VerificationError('OUTPUT_PARENT_MISSING', 'evidence output parent is unavailable');
  }
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) {
    throw new VerificationError(
      'OUTPUT_PARENT_INVALID',
      'evidence output parent must be a real directory',
    );
  }
  const output = outsideRepository(repo, absolute, 'output directory');
  if (existsSync(output))
    throw new VerificationError('OUTPUT_EXISTS', 'output directory already exists');
  return output;
}

function controlledInput(repo, path, label) {
  assertString(path, `${label} path`);
  const absolute = outsideRepository(repo, path, label);
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch {
    throw new VerificationError('INPUT_MISSING', `${label} is unavailable`);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new VerificationError(
      'TRUST_BOUNDARY_INVALID',
      `${label} must be a regular non-symlink file`,
    );
  }
  return absolute;
}

function readCommittedDescriptor(repo, commit) {
  let text;
  try {
    text = execFileSync('git', ['-C', repo, 'show', `${commit}:test-tasks.json`], {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (error) {
    throw new VerificationError(
      'DESCRIPTOR_MISSING',
      `committed test-tasks.json is unreadable: ${error.message}`,
    );
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new VerificationError(
      'MALFORMED_JSON',
      `committed test-tasks.json is invalid: ${error.message}`,
    );
  }
}

function readExternalJson(path, label) {
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
}

function exactCandidate(repo, commit, tree) {
  if (!GIT_OBJECT.test(commit) || !GIT_OBJECT.test(tree)) {
    throw new VerificationError('SCHEMA_INVALID', 'exact commit and tree are required');
  }
  if (git(repo, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') {
    throw new VerificationError('DIRTY_CANDIDATE', 'candidate repository must be clean');
  }
  if (git(repo, ['rev-parse', 'HEAD']) !== commit) {
    throw new VerificationError(
      'COMMIT_MISMATCH',
      'candidate HEAD does not match requested commit',
    );
  }
  if (git(repo, ['rev-parse', `${commit}^{tree}`]) !== tree) {
    throw new VerificationError('TREE_MISMATCH', 'candidate tree does not match requested tree');
  }
}

function matchingKeyPair(privateKeyPath, publicKeyPath) {
  const privateKey = createPrivateKey(readAbsoluteRegularFile(privateKeyPath, 'private key'));
  const publicKey = createPublicKey(readAbsoluteRegularFile(publicKeyPath, 'public key'));
  if (privateKey.asymmetricKeyType !== 'ed25519' || publicKey.asymmetricKeyType !== 'ed25519') {
    throw new VerificationError('KEY_INVALID', 'signing key pair must use Ed25519');
  }
  const derived = createPublicKey(privateKey).export({
    type: 'spki',
    format: 'der',
  });
  const supplied = publicKey.export({ type: 'spki', format: 'der' });
  if (!derived.equals(supplied)) {
    throw new VerificationError('KEY_MISMATCH', 'private and public key do not form a pair');
  }
  return { privateKey, publicKey };
}

function validateSignerId(value) {
  if (!IDENTIFIER.test(value))
    throw new VerificationError('SCHEMA_INVALID', 'signer ID is invalid');
}

function declaredArtifactPaths(taskPolicy) {
  const paths = new Set();
  if (taskPolicy.schemaVersion !== '1.1.0') return [];
  for (const node of taskPolicy.requiredNodes) {
    for (const path of node.outputContract.paths ?? []) paths.add(path);
  }
  return [...paths].sort();
}

/**
 * Copies the declared schema 1.1 artifacts out of the candidate working tree into a
 * bundle laid out exactly as an exported one, refusing any path segment that
 * traverses a symbolic link out of the candidate.
 */
function stageArtifacts(repository, artifactPaths, artifactsDir) {
  mkdirSync(artifactsDir, { recursive: true });
  for (const path of artifactPaths) {
    const destination = join(artifactsDir, path);
    mkdirSync(dirname(destination), { recursive: true });
    copyRootRelativeRegularFile(repository, path, destination, `artifact ${path}`);
  }
}

function candidateRepository(repo) {
  try {
    return realpathSync(repo);
  } catch {
    throw new VerificationError('REPOSITORY_INVALID', 'candidate repository is unreadable');
  }
}

export function preflightCandidateEvidence(options) {
  const repository = candidateRepository(options.repo);
  exactCandidate(repository, options.commit, options.tree);
  validateSignerId(options.signerId);
  assertString(options.resultsDir, 'task results directory');
  const controlledToolchain = controlledInput(repository, options.toolchainPath, 'toolchain input');
  const controlledEnvironment = controlledInput(
    repository,
    options.environmentPath,
    'environment input',
  );
  // The private key is deliberately absent from preflight. Only the public key and the
  // signer ID keep their trust-boundary checks here, so a preflight is a genuinely
  // non-signing operation that runs against a key the operator has not unlocked.
  const controlledPublicKey = controlledInput(repository, options.publicKeyPath, 'public key');
  const output = outputDestination(repository, options.outputDir);
  const descriptor = readCommittedDescriptor(repository, options.commit);
  const receipt = readExternalJson(options.receiptPath, 'candidate receipt');
  const built = buildExpectedTaskPolicy({
    repo: repository,
    descriptor,
    profileId: options.profile,
    candidateCommit: options.commit,
    expectedTree: options.tree,
    baseCommit: options.baseCommit,
    toolchain: readStringMap(controlledToolchain, 'toolchain'),
    environment: readEnvironmentMap(controlledEnvironment, 'environment'),
    policySchemaVersion: receipt.schemaVersion === '1.1.0' ? '1.1.0' : '1.0.0',
  });
  for (const node of built.taskPolicy.requiredNodes) {
    const contract = node.outputContract;
    // Legacy v1 and draft v2.0 mutation evidence stays readable for historical
    // verification only. The forward v2.2 branch is accepted here exactly like
    // v2.1, but its strict kernel still refuses unless the hosting API supplies
    // the protected v2.2 expectations; this CLI supplies none.
    if (
      typeof contract?.kind === 'string' &&
      contract.kind.startsWith('mutation-') &&
      (mutationContractVersion(contract.kind) !== 2 ||
        (contract.schemaVersion !== MUTATION_V21_SCHEMA &&
          contract.schemaVersion !== MUTATION_V22_SCHEMA))
    ) {
      throw new VerificationError(
        'MUTATION_VERSION_UNSUPPORTED',
        'legacy mutation evidence is read-only and cannot be exported',
      );
    }
  }
  const artifactPaths = declaredArtifactPaths(built.taskPolicy);
  for (const path of artifactPaths) {
    validateArtifactContent({
      bytes: readRootRelativeRegularFile(repository, path, `artifact ${path}`),
      path,
      mediaType: artifactMediaType(path),
    });
  }
  // The candidate repository contains many non-artifact files, so the shared
  // semantic kernel verifies every declared artifact in place while deferring the
  // exact standalone-bundle population check to the normal export verification.
  // No preflight scratch directory or output is created.
  const verified = verifyCandidateReceiptEvidence({
    receipt,
    resultsDir: options.resultsDir,
    artifactsDir: repository,
    taskPolicy: built.taskPolicy,
    expectedRepository: descriptor.repositoryId,
    expectedCommit: options.commit,
    expectedTree: options.tree,
    expectedPolicyDigest: built.taskPolicyDigest,
    allowAdditionalArtifactFiles: true,
    resolveReuseOrigin: options.resolveReuseOrigin,
    mutationExpectations: options.mutationExpectations,
  });
  return {
    repository,
    output,
    descriptor,
    receipt,
    built,
    artifactPaths,
    controlledPublicKey,
    verified,
  };
}

export function exportCandidateEvidence(options) {
  // The signing key's trust boundary is asserted from its location alone, before any
  // other work: a candidate that supplies its own key is refused up front, and this
  // check neither opens nor reads the key file.
  assertString(options.privateKeyPath, 'private key path');
  outsideRepository(candidateRepository(options.repo), options.privateKeyPath, 'private key');

  const { repository, output, descriptor, receipt, built, artifactPaths, controlledPublicKey } =
    preflightCandidateEvidence(options);
  const { resultsDir, signerId, commit, tree, profile } = options;

  // Signing starts only once the non-signing preflight above has fully verified this
  // candidate, so the protected key is never applied to evidence that has not already
  // passed the same checks an independent verifier will apply to the exported bundle.
  const controlledPrivateKey = controlledInput(repository, options.privateKeyPath, 'private key');
  const keys = matchingKeyPair(controlledPrivateKey, controlledPublicKey);
  const payload = canonicalBytes(receipt);
  const envelope = {
    schemaVersion: '1.0.0',
    payloadType: PAYLOAD_TYPE,
    payload: payload.toString('base64'),
    signatures: [
      {
        signerId,
        signature: sign(null, payload, keys.privateKey).toString('base64'),
      },
    ],
  };
  const trustStore = {
    schemaVersion: '1.0.0',
    trustedSigners: [
      {
        signerId,
        publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      },
    ],
    revokedSignerIds: [],
  };

  const staging = mkdtempSync(join(dirname(output), '.devai-evidence-export-'));
  try {
    mkdirSync(join(staging, 'results'));
    mkdirSync(join(staging, 'artifacts'));
    writeFileSync(join(staging, 'envelope.json'), `${canonicalize(envelope)}\n`, { flag: 'wx' });
    writeFileSync(join(staging, 'task-policy.json'), `${canonicalize(built.taskPolicy)}\n`, {
      flag: 'wx',
    });
    if (built.taskPolicy.schemaVersion === '1.0.0') {
      writeFileSync(join(staging, 'trust-store.json'), `${canonicalize(trustStore)}\n`, {
        flag: 'wx',
      });
    }
    for (const task of receipt.tasks) {
      copyRootRelativeRegularFile(
        resultsDir,
        `${task.resultDigest}.json`,
        join(staging, 'results', `${task.resultDigest}.json`),
        `task result ${task.nodeId}`,
      );
    }
    stageArtifacts(repository, artifactPaths, join(staging, 'artifacts'));
    const verified = verifyCandidateEvidence({
      envelope,
      resultsDir: join(staging, 'results'),
      artifactsDir: join(staging, 'artifacts'),
      taskPolicy: built.taskPolicy,
      trustStore,
      expectedRepository: descriptor.repositoryId,
      expectedCommit: commit,
      expectedTree: tree,
      expectedPolicyDigest: built.taskPolicyDigest,
    });
    const manifest = {
      schemaVersion: built.taskPolicy.schemaVersion === '1.1.0' ? '1.1.0' : '1.0.0',
      repositoryId: descriptor.repositoryId,
      commit,
      tree,
      profile,
      signerId,
      taskPolicyDigest: built.taskPolicyDigest,
      envelopeDigest: sha256Hex(envelope),
      resultDigests: receipt.tasks.map((task) => task.resultDigest).sort(),
      ...(built.taskPolicy.schemaVersion === '1.1.0' && {
        artifacts: verified.verifiedArtifacts.map((path) => ({
          path,
          mediaType: artifactMediaType(path),
          sha256: sha256Hex(
            readRootRelativeRegularFile(join(staging, 'artifacts'), path, `artifact ${path}`),
          ),
        })),
      }),
    };
    writeFileSync(join(staging, 'manifest.json'), `${canonicalize(manifest)}\n`, { flag: 'wx' });
    renameSync(staging, output);
  } catch (error) {
    rmSync(staging, { recursive: true, force: true });
    throw error;
  }
  return {
    ok: true,
    outputDir: output,
    repositoryId: descriptor.repositoryId,
    commit,
    tree,
    profile,
    signerId,
    taskPolicyDigest: built.taskPolicyDigest,
    envelopeDigest: sha256Hex(envelope),
    verifiedNodes: built.taskPolicy.requiredNodes.map((node) => node.nodeId),
  };
}

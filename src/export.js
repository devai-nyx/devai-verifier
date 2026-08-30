import { execFileSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { artifactMediaType, validateArtifactContent } from './artifact-safety.js';
import { VerificationError, canonicalBytes, canonicalize, readJson, sha256Hex } from './canonical.js';
import {
  buildExpectedTaskPolicy,
  readEnvironmentMap,
  readStringMap,
} from './policy-builder.js';
import { PAYLOAD_TYPE, verifyCandidateEvidence } from './verify.js';

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
    throw new VerificationError('TRUST_BOUNDARY_INVALID', `${label} must be outside the candidate repository`);
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
    throw new VerificationError('OUTPUT_PARENT_INVALID', 'evidence output parent must be a real directory');
  }
  const output = outsideRepository(repo, absolute, 'output directory');
  if (existsSync(output)) throw new VerificationError('OUTPUT_EXISTS', 'output directory already exists');
  return output;
}

function controlledInput(repo, path, label) {
  const absolute = outsideRepository(repo, path, label);
  const stat = lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new VerificationError('TRUST_BOUNDARY_INVALID', `${label} must be a regular non-symlink file`);
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
    throw new VerificationError('DESCRIPTOR_MISSING', `committed test-tasks.json is unreadable: ${error.message}`);
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new VerificationError('MALFORMED_JSON', `committed test-tasks.json is invalid: ${error.message}`);
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
    throw new VerificationError('COMMIT_MISMATCH', 'candidate HEAD does not match requested commit');
  }
  if (git(repo, ['rev-parse', `${commit}^{tree}`]) !== tree) {
    throw new VerificationError('TREE_MISMATCH', 'candidate tree does not match requested tree');
  }
}

function matchingKeyPair(privateKeyPath, publicKeyPath) {
  const privateKey = createPrivateKey(readFileSync(privateKeyPath));
  const publicKey = createPublicKey(readFileSync(publicKeyPath));
  if (privateKey.asymmetricKeyType !== 'ed25519' || publicKey.asymmetricKeyType !== 'ed25519') {
    throw new VerificationError('KEY_INVALID', 'signing key pair must use Ed25519');
  }
  const derived = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const supplied = publicKey.export({ type: 'spki', format: 'der' });
  if (!derived.equals(supplied)) {
    throw new VerificationError('KEY_MISMATCH', 'private and public key do not form a pair');
  }
  return { privateKey, publicKey };
}

function validateSignerId(value) {
  if (!IDENTIFIER.test(value)) throw new VerificationError('SCHEMA_INVALID', 'signer ID is invalid');
}

function copyRegularFile(source, destination, label) {
  let stat;
  try {
    stat = lstatSync(source);
  } catch (error) {
    throw new VerificationError('INPUT_MISSING', `${label} is unreadable: ${error.message}`);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new VerificationError('ARTIFACT_INVALID', `${label} must be a regular non-symlink file`);
  }
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(source, destination);
}

function declaredArtifactPaths(taskPolicy) {
  const paths = new Set();
  if (taskPolicy.schemaVersion !== '1.1.0') return [];
  for (const node of taskPolicy.requiredNodes) {
    for (const path of node.outputContract.paths ?? []) paths.add(path);
  }
  return [...paths].sort();
}

export function preflightCandidateEvidence(options) {
  let repository;
  try {
    repository = realpathSync(options.repo);
  } catch {
    throw new VerificationError('REPOSITORY_INVALID', 'candidate repository is unreadable');
  }
  exactCandidate(repository, options.commit, options.tree);
  validateSignerId(options.signerId);
  const controlledToolchain = controlledInput(repository, options.toolchainPath, 'toolchain input');
  const controlledEnvironment = controlledInput(repository, options.environmentPath, 'environment input');
  const controlledPrivateKey = controlledInput(repository, options.privateKeyPath, 'private key');
  const controlledPublicKey = controlledInput(repository, options.publicKeyPath, 'public key');
  const output = outputDestination(repository, options.outputDir);
  const descriptor = readCommittedDescriptor(repository, options.commit);
  const receipt = readJson(options.receiptPath, 'candidate receipt');
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
  const payload = canonicalBytes(receipt);
  const keys = matchingKeyPair(controlledPrivateKey, controlledPublicKey);
  const envelope = {
    schemaVersion: '1.0.0', payloadType: PAYLOAD_TYPE, payload: payload.toString('base64'),
    signatures: [{ signerId: options.signerId, signature: sign(null, payload, keys.privateKey).toString('base64') }],
  };
  const trustStore = {
    schemaVersion: '1.0.0',
    trustedSigners: [{ signerId: options.signerId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }],
    revokedSignerIds: [],
  };
  const artifactPaths = declaredArtifactPaths(built.taskPolicy);
  for (const path of artifactPaths) {
    const absolute = join(repository, path);
    let stat;
    try {
      stat = lstatSync(absolute);
    } catch {
      throw new VerificationError('ARTIFACTS_MISSING', `artifact ${path} is unavailable`);
    }
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new VerificationError('ARTIFACT_INVALID', `artifact ${path} must be a regular non-symlink file`);
    }
    validateArtifactContent({ bytes: readFileSync(absolute), path, mediaType: artifactMediaType(path) });
  }
  return { repository, output, descriptor, receipt, built, envelope, trustStore, artifactPaths };
}

export function exportCandidateEvidence(options) {
  const { repository, output, descriptor, receipt, built, envelope, trustStore } = preflightCandidateEvidence(options);
  const { resultsDir, signerId, commit, tree, profile } = options;

  const staging = mkdtempSync(join(dirname(output), '.devai-evidence-export-'));
  try {
    mkdirSync(join(staging, 'results'));
    mkdirSync(join(staging, 'artifacts'));
    writeFileSync(join(staging, 'envelope.json'), `${canonicalize(envelope)}\n`, { flag: 'wx' });
    writeFileSync(join(staging, 'task-policy.json'), `${canonicalize(built.taskPolicy)}\n`, {
      flag: 'wx',
    });
    if (built.taskPolicy.schemaVersion === '1.0.0') {
      writeFileSync(join(staging, 'trust-store.json'), `${canonicalize(trustStore)}\n`, { flag: 'wx' });
    }
    for (const task of receipt.tasks) {
      copyRegularFile(
        join(resultsDir, `${task.resultDigest}.json`),
        join(staging, 'results', `${task.resultDigest}.json`),
        `task result ${task.nodeId}`,
      );
    }
    const artifactPaths = declaredArtifactPaths(built.taskPolicy);
    for (const path of artifactPaths) {
      const segments = path.split('/');
      let cursor = repository;
      for (const segment of segments) {
        cursor = join(cursor, segment);
        const stat = lstatSync(cursor);
        if (stat.isSymbolicLink()) {
          throw new VerificationError('ARTIFACT_SYMLINK', `artifact ${path} traverses a symbolic link`);
        }
      }
      copyRegularFile(cursor, join(staging, 'artifacts', path), `artifact ${path}`);
    }
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
          sha256: sha256Hex(readFileSync(join(staging, 'artifacts', path))),
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

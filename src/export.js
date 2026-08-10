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
import { VerificationError, canonicalBytes, canonicalize, readJson, sha256Hex } from './canonical.js';
import { buildExpectedTaskPolicy, readStringMap } from './policy-builder.js';
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
  const root = realpathSync(repo);
  const absolute = resolve(path);
  const resolvedParent = realpathSync(dirname(absolute));
  const candidate = join(resolvedParent, absolute.slice(dirname(absolute).length + 1));
  const pathFromRoot = relative(root, candidate);
  if (pathFromRoot === '' || (!pathFromRoot.startsWith(`..${sep}`) && pathFromRoot !== '..')) {
    throw new VerificationError('TRUST_BOUNDARY_INVALID', `${label} must be outside the candidate repository`);
  }
  return absolute;
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

export function exportCandidateEvidence({
  repo,
  receiptPath,
  resultsDir,
  profile,
  commit,
  tree,
  baseCommit,
  toolchainPath,
  environmentPath,
  privateKeyPath,
  publicKeyPath,
  signerId,
  outputDir,
}) {
  const repository = realpathSync(repo);
  exactCandidate(repository, commit, tree);
  validateSignerId(signerId);
  const controlledToolchain = controlledInput(repository, toolchainPath, 'toolchain input');
  const controlledEnvironment = controlledInput(repository, environmentPath, 'environment input');
  const controlledPrivateKey = controlledInput(repository, privateKeyPath, 'private key');
  const controlledPublicKey = controlledInput(repository, publicKeyPath, 'public key');
  const output = outsideRepository(repository, outputDir, 'output directory');
  if (existsSync(output)) throw new VerificationError('OUTPUT_EXISTS', 'output directory already exists');

  const descriptor = readCommittedDescriptor(repository, commit);
  const built = buildExpectedTaskPolicy({
    repo: repository,
    descriptor,
    profileId: profile,
    candidateCommit: commit,
    expectedTree: tree,
    baseCommit,
    toolchain: readStringMap(controlledToolchain, 'toolchain'),
    environment: readStringMap(controlledEnvironment, 'environment'),
  });
  const receipt = readJson(receiptPath, 'candidate receipt');
  const payload = canonicalBytes(receipt);
  const keys = matchingKeyPair(controlledPrivateKey, controlledPublicKey);
  const envelope = {
    schemaVersion: '1.0.0',
    payloadType: PAYLOAD_TYPE,
    payload: payload.toString('base64'),
    signatures: [
      { signerId, signature: sign(null, payload, keys.privateKey).toString('base64') },
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

  verifyCandidateEvidence({
    envelope,
    resultsDir,
    taskPolicy: built.taskPolicy,
    trustStore,
    expectedRepository: descriptor.repositoryId,
    expectedCommit: commit,
    expectedTree: tree,
    expectedPolicyDigest: built.taskPolicyDigest,
  });

  const staging = mkdtempSync(join(dirname(output), '.devai-evidence-export-'));
  try {
    mkdirSync(join(staging, 'results'));
    writeFileSync(join(staging, 'envelope.json'), `${canonicalize(envelope)}\n`, { flag: 'wx' });
    writeFileSync(join(staging, 'task-policy.json'), `${canonicalize(built.taskPolicy)}\n`, {
      flag: 'wx',
    });
    writeFileSync(join(staging, 'trust-store.json'), `${canonicalize(trustStore)}\n`, { flag: 'wx' });
    for (const task of receipt.tasks) {
      copyFileSync(join(resultsDir, `${task.resultDigest}.json`), join(staging, 'results', `${task.resultDigest}.json`));
    }
    const manifest = {
      schemaVersion: '1.0.0',
      repositoryId: descriptor.repositoryId,
      commit,
      tree,
      profile,
      signerId,
      taskPolicyDigest: built.taskPolicyDigest,
      envelopeDigest: sha256Hex(envelope),
      resultDigests: receipt.tasks.map((task) => task.resultDigest).sort(),
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

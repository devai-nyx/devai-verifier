import { execFileSync } from 'node:child_process';
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';
import {
  VerificationError,
  assertExactKeys,
  assertString,
  assertUniqueStrings,
  canonicalize,
  readJson,
  sha256Hex,
} from './canonical.js';
import { loadAndVerify } from './verify.js';

const SHA256 = /^[0-9a-f]{64}$/u;
const GIT_OBJECT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const TAG_PREFIX = 'devai-local-evidence/';

function exec(command, args, options = {}) {
  try {
    return execFileSync(command, args, {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      ...options,
    }).trim();
  } catch (error) {
    throw new VerificationError(
      'PUBLISH_COMMAND_FAILED',
      `${command} ${args[0] ?? ''} failed: ${error.message}`,
    );
  }
}

function git(repo, args) {
  return exec('git', ['-C', repo, ...args]);
}

function validatePortablePath(path, label) {
  assertString(path, label);
  if (
    path.startsWith('/') ||
    path.includes('\\') ||
    path.includes('\0') ||
    path.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')
  ) {
    throw new VerificationError('SCHEMA_INVALID', `${label} is not a portable relative path`);
  }
}

function canonicalJson(path, label) {
  const value = readJson(path, label);
  const text = readFileSync(path, 'utf8');
  if (text !== canonicalize(value) && text !== `${canonicalize(value)}\n`) {
    throw new VerificationError('NON_CANONICAL_JSON', `${label} is not canonical JSON`);
  }
  return value;
}

function filesBelow(root, current = root) {
  const files = [];
  for (const entry of readdirSync(current, { withFileTypes: true })) {
    const absolute = join(current, entry.name);
    if (entry.isSymbolicLink()) {
      throw new VerificationError('BUNDLE_SYMLINK', 'evidence bundle contains a symbolic link');
    }
    if (entry.isDirectory()) files.push(...filesBelow(root, absolute));
    else if (entry.isFile()) files.push(relative(root, absolute).split(sep).join('/'));
    else throw new VerificationError('BUNDLE_INVALID', 'evidence bundle contains a non-regular file');
  }
  return files;
}

function validateManifest(manifest) {
  assertExactKeys(
    manifest,
    [
      'artifacts',
      'commit',
      'envelopeDigest',
      'profile',
      'repositoryId',
      'resultDigests',
      'schemaVersion',
      'signerId',
      'taskPolicyDigest',
      'tree',
    ],
    'evidence manifest',
  );
  if (manifest.schemaVersion !== '1.1.0' || manifest.profile !== 'rc') {
    throw new VerificationError('SCHEMA_INVALID', 'publish requires an RC schema 1.1 manifest');
  }
  assertString(manifest.repositoryId, 'manifest repositoryId', IDENTIFIER);
  assertString(manifest.commit, 'manifest commit', GIT_OBJECT);
  assertString(manifest.tree, 'manifest tree', GIT_OBJECT);
  assertString(manifest.signerId, 'manifest signerId', IDENTIFIER);
  assertString(manifest.taskPolicyDigest, 'manifest taskPolicyDigest', SHA256);
  assertString(manifest.envelopeDigest, 'manifest envelopeDigest', SHA256);
  assertUniqueStrings(manifest.resultDigests, 'manifest resultDigests');
  manifest.resultDigests.forEach((digest) => assertString(digest, 'manifest result digest', SHA256));
  if (!Array.isArray(manifest.artifacts)) {
    throw new VerificationError('SCHEMA_INVALID', 'manifest artifacts must be an array');
  }
  const paths = [];
  for (const [index, artifact] of manifest.artifacts.entries()) {
    const label = `manifest artifacts[${index}]`;
    assertExactKeys(artifact, ['mediaType', 'path', 'sha256'], label);
    validatePortablePath(artifact.path, `${label}.path`);
    assertString(artifact.mediaType, `${label}.mediaType`);
    assertString(artifact.sha256, `${label}.sha256`, SHA256);
    paths.push(artifact.path);
  }
  assertUniqueStrings(paths, 'manifest artifact paths');
}

export function verifyPreparedBundle({ bundleDir, trustStorePath }) {
  const bundle = realpathSync(bundleDir);
  const manifest = canonicalJson(join(bundle, 'manifest.json'), 'evidence manifest');
  validateManifest(manifest);
  const expectedFiles = [
    'envelope.json',
    'manifest.json',
    'task-policy.json',
    ...manifest.resultDigests.map((digest) => `results/${digest}.json`),
    ...manifest.artifacts.map((artifact) => `artifacts/${artifact.path}`),
  ].sort();
  const actualFiles = filesBelow(bundle).sort();
  if (
    actualFiles.length !== expectedFiles.length ||
    actualFiles.some((path, index) => path !== expectedFiles[index])
  ) {
    throw new VerificationError('BUNDLE_POPULATION_MISMATCH', 'evidence bundle file population differs');
  }
  const envelope = canonicalJson(join(bundle, 'envelope.json'), 'signed envelope');
  const taskPolicy = canonicalJson(join(bundle, 'task-policy.json'), 'task policy');
  if (sha256Hex(envelope) !== manifest.envelopeDigest) {
    throw new VerificationError('ENVELOPE_DIGEST_MISMATCH', 'manifest envelope digest differs');
  }
  if (sha256Hex(taskPolicy) !== manifest.taskPolicyDigest) {
    throw new VerificationError('POLICY_DIGEST_MISMATCH', 'manifest task-policy digest differs');
  }
  for (const digest of manifest.resultDigests) {
    canonicalJson(join(bundle, 'results', `${digest}.json`), `task result ${digest}`);
  }
  for (const artifact of manifest.artifacts) {
    const actual = sha256Hex(readFileSync(join(bundle, 'artifacts', artifact.path)));
    if (actual !== artifact.sha256) {
      throw new VerificationError('ARTIFACT_DIGEST_MISMATCH', `manifest artifact ${artifact.path} differs`);
    }
  }
  const verified = loadAndVerify({
    envelopePath: join(bundle, 'envelope.json'),
    resultsDir: join(bundle, 'results'),
    artifactsDir: join(bundle, 'artifacts'),
    taskPolicyPath: join(bundle, 'task-policy.json'),
    trustStorePath,
    expectedRepository: manifest.repositoryId,
    expectedCommit: manifest.commit,
    expectedTree: manifest.tree,
    expectedPolicyDigest: manifest.taskPolicyDigest,
    bindingMode: 'exact-commit',
  });
  if (verified.signerId !== manifest.signerId) {
    throw new VerificationError('SIGNER_MISMATCH', 'manifest signer differs from signed envelope');
  }
  return { manifest, verified, bundle };
}

function githubRepositoryId(remoteUrl) {
  const match = remoteUrl.match(/github\.com[/:]([^/]+\/[^/]+?)(?:\.git)?$/u);
  return match?.[1];
}

function defaultDispatch({ repositoryId, workflow, candidateCommit, defaultBranch }) {
  exec('gh', [
    'workflow',
    'run',
    workflow,
    '--repo',
    repositoryId,
    '--ref',
    defaultBranch,
    '-f',
    `candidate_sha=${candidateCommit}`,
  ]);
}

export function publishCandidateEvidence({
  repo,
  bundleDir,
  trustStorePath,
  remote = 'origin',
  tagPrefix = TAG_PREFIX,
  workflow = 'devai-local-rc-verify.yml',
  defaultBranch = 'main',
  dispatchVerification = defaultDispatch,
  resolveRemoteRepositoryId = githubRepositoryId,
}) {
  const repository = realpathSync(repo);
  const { manifest } = verifyPreparedBundle({ bundleDir, trustStorePath });
  if (!tagPrefix.endsWith('/') || !tagPrefix.startsWith('devai-local-evidence/')) {
    throw new VerificationError('TAG_PREFIX_INVALID', 'evidence tag prefix is invalid');
  }
  if (git(repository, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') {
    throw new VerificationError('DIRTY_CANDIDATE', 'candidate repository must be clean before publication');
  }
  if (git(repository, ['rev-parse', 'HEAD']) !== manifest.commit) {
    throw new VerificationError('COMMIT_MISMATCH', 'candidate HEAD differs from evidence commit');
  }
  if (git(repository, ['rev-parse', 'HEAD^{tree}']) !== manifest.tree) {
    throw new VerificationError('TREE_MISMATCH', 'candidate tree differs from evidence tree');
  }
  const remoteUrl = git(repository, ['remote', 'get-url', remote]);
  if (resolveRemoteRepositoryId(remoteUrl)?.toLowerCase() !== manifest.repositoryId.toLowerCase()) {
    throw new VerificationError('REMOTE_MISMATCH', 'Git remote does not match evidence repository');
  }

  const tagName = `${tagPrefix}${manifest.tree}`;
  const temporary = mkdtempSync(join(tmpdir(), 'devai-evidence-publish-'));
  try {
    const proofRepo = join(temporary, 'proof');
    cpSync(resolve(bundleDir), proofRepo, { recursive: true, dereference: false, errorOnExist: true });
    git(proofRepo, ['init', '--quiet', '-b', 'evidence']);
    git(proofRepo, ['config', 'user.name', 'DEVAI Inspector Evidence']);
    git(proofRepo, ['config', 'user.email', 'devai-evidence@invalid']);
    git(proofRepo, ['add', '-A']);
    git(proofRepo, ['commit', '--quiet', '-m', `DEVAI local RC evidence ${manifest.tree}`]);
    git(proofRepo, ['tag', '-a', tagName, '-m', `DEVAI local RC evidence ${manifest.tree}`]);
    const proofTree = git(proofRepo, ['rev-parse', `${tagName}^{tree}`]);
    const existing = exec('git', [
      'ls-remote',
      '--tags',
      remoteUrl,
      `refs/tags/${tagName}`,
      `refs/tags/${tagName}^{}`,
    ]);
    let published = false;
    if (existing !== '') {
      git(proofRepo, ['fetch', '--quiet', '--no-tags', remoteUrl, `refs/tags/${tagName}:refs/tags/existing-evidence`]);
      const existingTree = git(proofRepo, ['rev-parse', 'refs/tags/existing-evidence^{tree}']);
      if (existingTree !== proofTree) {
        throw new VerificationError('TAG_COLLISION', `evidence tag ${tagName} already contains different bytes`);
      }
    } else {
      git(proofRepo, ['push', remoteUrl, `refs/tags/${tagName}:refs/tags/${tagName}`]);
      published = true;
    }
    dispatchVerification({
      repositoryId: manifest.repositoryId,
      workflow,
      candidateCommit: manifest.commit,
      defaultBranch,
    });
    return {
      ok: true,
      published,
      tag: tagName,
      candidateCommit: manifest.commit,
      candidateTree: manifest.tree,
      signerId: manifest.signerId,
      taskPolicyDigest: manifest.taskPolicyDigest,
    };
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

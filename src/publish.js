import { execFileSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import {
  VerificationError,
  assertExactKeys,
  assertString,
  assertUniqueStrings,
  canonicalize,
  sha256Hex,
} from './canonical.js';
import { mutationContractVersion } from './mutation.js';
import { readRootRelativeRegularFile } from './safe-path.js';
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
      `${command} command failed`,
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

function canonicalJson(root, path, label) {
  const text = readRootRelativeRegularFile(root, path, label).toString('utf8');
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new VerificationError('MALFORMED_JSON', `${label} is not valid JSON`);
  }
  if (text !== canonicalize(value) && text !== `${canonicalize(value)}\n`) {
    throw new VerificationError('NON_CANONICAL_JSON', `${label} is not canonical JSON`);
  }
  return value;
}

export function assertMutationWriteBoundary(taskPolicy, action = 'published') {
  for (const node of taskPolicy.requiredNodes ?? []) {
    const contract = node?.outputContract;
    if (typeof contract?.kind !== 'string' || !contract.kind.startsWith('mutation-')) continue;
    if (
      mutationContractVersion(contract.kind, 'mutation output contract') !== 2 ||
      contract.schemaVersion !== '2.1.0'
    ) {
      throw new VerificationError(
        'MUTATION_VERSION_UNSUPPORTED',
        `legacy mutation evidence is read-only and cannot be ${action}`,
      );
    }
  }
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

export function verifyPreparedBundle({
  bundleDir,
  trustStorePath,
  expectedRepository,
  expectedCommit,
  expectedTree,
  expectedPolicyDigest,
  expectedSignerId,
  expectedTrustRootId,
  expectedTrustStoreDigest,
  expectedKeyId,
  bindingMode = 'exact-commit',
}) {
  // Do not canonicalize the supplied directory: realpath would silently follow
  // a bundle-root symlink before the identity-pinned readers can reject it.
  const bundle = resolve(bundleDir);
  const manifest = canonicalJson(bundle, 'manifest.json', 'evidence manifest');
  validateManifest(manifest);
  const taskPolicy = canonicalJson(bundle, 'task-policy.json', 'task policy');
  const requiresV21Expectations = taskPolicy.requiredNodes?.some(
    (node) =>
      node.outputContract?.kind === 'mutation-report-set-v2' &&
      node.outputContract?.schemaVersion === '2.1.0',
  );
  if (requiresV21Expectations) {
    for (const [name, value] of Object.entries({
      expectedRepository,
      expectedCommit,
      expectedTree,
      expectedPolicyDigest,
      expectedSignerId,
      expectedTrustRootId,
      expectedTrustStoreDigest,
      expectedKeyId,
    })) {
      if (typeof value !== 'string' || value.length === 0) {
        throw new VerificationError(
          'MUTATION_OFFLINE_EXPECTATION_MISSING',
          `${name} is required for mutation v2.1 offline verification`,
        );
      }
    }
  }
  const repository = expectedRepository ?? manifest.repositoryId;
  const commit = expectedCommit ?? manifest.commit;
  const tree = expectedTree ?? manifest.tree;
  const policyDigest = expectedPolicyDigest ?? manifest.taskPolicyDigest;
  if (manifest.repositoryId !== repository) {
    throw new VerificationError('REPOSITORY_MISMATCH', 'manifest repository differs from candidate');
  }
  if (bindingMode === 'exact-commit' && manifest.commit !== commit) {
    throw new VerificationError('COMMIT_MISMATCH', 'manifest commit differs from candidate');
  }
  if (manifest.tree !== tree) {
    throw new VerificationError('TREE_MISMATCH', 'manifest tree differs from candidate');
  }
  if (manifest.taskPolicyDigest !== policyDigest) {
    throw new VerificationError('POLICY_DIGEST_MISMATCH', 'manifest policy differs from expected policy');
  }
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
  const envelope = canonicalJson(bundle, 'envelope.json', 'signed envelope');
  if (sha256Hex(envelope) !== manifest.envelopeDigest) {
    throw new VerificationError('ENVELOPE_DIGEST_MISMATCH', 'manifest envelope digest differs');
  }
  if (sha256Hex(taskPolicy) !== manifest.taskPolicyDigest) {
    throw new VerificationError('POLICY_DIGEST_MISMATCH', 'manifest task-policy digest differs');
  }
  for (const digest of manifest.resultDigests) {
    canonicalJson(bundle, `results/${digest}.json`, `task result ${digest}`);
  }
  for (const artifact of manifest.artifacts) {
    const actual = sha256Hex(
      readRootRelativeRegularFile(bundle, `artifacts/${artifact.path}`, `artifact ${artifact.path}`),
    );
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
    expectedRepository: repository,
    expectedCommit: commit,
    expectedTree: tree,
    expectedPolicyDigest: policyDigest,
    expectedSignerId,
    expectedTrustRootId,
    expectedTrustStoreDigest,
    expectedKeyId,
    expectedResultDigests: manifest.resultDigests,
    bindingMode,
  });
  if (verified.signerId !== manifest.signerId) {
    throw new VerificationError('SIGNER_MISMATCH', 'manifest signer differs from signed envelope');
  }
  return { manifest, verified, bundle };
}

/**
 * Materialize precisely the population that was just verified.  Do not use a
 * recursive copy here: a bundle directory is untrusted until every individual
 * member is opened through the identity-pinned reader.  This also makes the
 * proof repository independent of files that appear after verification.
 */
function materializeVerifiedBundle(bundle, manifest, destination) {
  const paths = [
    'envelope.json',
    'manifest.json',
    'task-policy.json',
    ...manifest.resultDigests.map((digest) => `results/${digest}.json`),
    ...manifest.artifacts.map((artifact) => `artifacts/${artifact.path}`),
  ];
  mkdirSync(destination, { recursive: false });
  for (const path of paths) {
    const bytes = readRootRelativeRegularFile(bundle, path, `bundle member ${path}`);
    const target = join(destination, path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, bytes, { flag: 'wx' });
  }
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
  expectedRepository,
  expectedCommit,
  expectedTree,
  expectedPolicyDigest,
  expectedSignerId,
  expectedTrustRootId,
  expectedTrustStoreDigest,
  expectedKeyId,
  remote = 'origin',
  tagPrefix = TAG_PREFIX,
  workflow = 'devai-local-rc-verify.yml',
  defaultBranch = 'main',
  dispatchVerification = defaultDispatch,
  resolveRemoteRepositoryId = githubRepositoryId,
}) {
  const repository = realpathSync(repo);
  const prepared = verifyPreparedBundle({
    bundleDir,
    trustStorePath,
    expectedRepository,
    expectedCommit,
    expectedTree,
    expectedPolicyDigest,
    expectedSignerId,
    expectedTrustRootId,
    expectedTrustStoreDigest,
    expectedKeyId,
  });
  assertMutationWriteBoundary(
    canonicalJson(prepared.bundle, 'task-policy.json', 'task policy'),
    'published',
  );
  const { manifest } = prepared;
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
    materializeVerifiedBundle(prepared.bundle, manifest, proofRepo);
    verifyPreparedBundle({
      bundleDir: proofRepo,
      trustStorePath,
      expectedRepository,
      expectedCommit,
      expectedTree,
      expectedPolicyDigest,
      expectedSignerId,
      expectedTrustRootId,
      expectedTrustStoreDigest,
      expectedKeyId,
    });
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

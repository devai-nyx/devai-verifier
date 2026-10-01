import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import {
  VerificationError,
  assertExactKeys,
  assertObject,
  assertString,
  assertUniqueStrings,
  canonicalBytes,
  sha256Hex,
} from './canonical.js';
import { resolveMutationDiscoveryContract } from './mutation.js';

const GIT_OBJECT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const ENVIRONMENT_KEY = /^[A-Z_][A-Z0-9_]*$/u;
const ENVIRONMENT_IDENTITY = /^sha256:[0-9a-f]{64}$/u;
const EXECUTABLE_DIGEST = /^[0-9a-f]{64}$/u;
const BARE_EXECUTABLE = /^[A-Za-z0-9._-]+$/u;
const HARNESS_MUTATED_PREFIXES = ['.devai/state/', 'record/', 'scratch/'];

function isHarnessMutatedPath(path) {
  return HARNESS_MUTATED_PREFIXES.some((prefix) => path.startsWith(prefix));
}

function git(repo, args, { encoding = 'utf8', input } = {}) {
  const result = spawnSync('git', ['-C', repo, ...args], {
    encoding,
    maxBuffer: 64 * 1024 * 1024,
    ...(input !== undefined && { input }),
  });
  if (result.error !== undefined || result.status !== 0) {
    const detail = result.error?.message ?? String(result.stderr || result.stdout).trim();
    throw new VerificationError('GIT_ERROR', `git ${args[0]} failed: ${detail}`);
  }
  return result.stdout;
}

function objectContentDigests(repo, objectIds) {
  const unique = [...new Set(objectIds)].sort();
  if (unique.length === 0) return new Map();
  const digests = new Map();
  const sizes = new Map();
  const sizeOutput = Buffer.from(
    git(repo, ['cat-file', '--batch-check'], {
      encoding: null,
      input: `${unique.join('\n')}\n`,
    }),
  );
  let sizeOffset = 0;
  for (const expectedObjectId of unique) {
    const newline = sizeOutput.indexOf(0x0a, sizeOffset);
    if (newline < 0) throw new VerificationError('GIT_ERROR', 'truncated cat-file header');
    const match = /^([0-9a-f]+) ([a-z]+) (\d+)$/u.exec(
      sizeOutput.subarray(sizeOffset, newline).toString('utf8'),
    );
    const size = Number(match?.[3]);
    if (match?.[1] !== expectedObjectId || !Number.isSafeInteger(size) || size < 0) {
      throw new VerificationError('GIT_ERROR', 'unexpected cat-file header');
    }
    sizes.set(expectedObjectId, size);
    sizeOffset = newline + 1;
  }
  if (sizeOffset !== sizeOutput.length) throw new VerificationError('GIT_ERROR', 'extra cat-file output');

  const maxBatchBytes = 32 * 1024 * 1024;
  for (let start = 0; start < unique.length; ) {
    const batch = [];
    let estimatedBytes = 0;
    while (start + batch.length < unique.length) {
      const objectId = unique[start + batch.length];
      const estimatedObjectBytes = objectId.length + 64 + sizes.get(objectId);
      if (batch.length > 0 && estimatedBytes + estimatedObjectBytes > maxBatchBytes) break;
      batch.push(objectId);
      estimatedBytes += estimatedObjectBytes;
    }
    const output = Buffer.from(
      git(repo, ['cat-file', '--batch'], { encoding: null, input: `${batch.join('\n')}\n` }),
    );
    let offset = 0;
    for (const expectedObjectId of batch) {
      const newline = output.indexOf(0x0a, offset);
      if (newline < 0) throw new VerificationError('GIT_ERROR', 'truncated cat-file header');
      const header = output.subarray(offset, newline).toString('utf8');
      const match = /^([0-9a-f]+) ([a-z]+) (\d+)$/u.exec(header);
      if (match?.[1] === undefined || match[3] === undefined || match[1] !== expectedObjectId) {
        throw new VerificationError('GIT_ERROR', 'unexpected cat-file header');
      }
      const size = Number(match[3]);
      const contentStart = newline + 1;
      const contentEnd = contentStart + size;
      if (!Number.isSafeInteger(size) || size < 0 || output[contentEnd] !== 0x0a) {
        throw new VerificationError('GIT_ERROR', 'truncated cat-file content');
      }
      digests.set(expectedObjectId, sha256Hex(output.subarray(contentStart, contentEnd)));
      offset = contentEnd + 1;
    }
    if (offset !== output.length) throw new VerificationError('GIT_ERROR', 'extra cat-file output');
    start += batch.length;
  }
  return digests;
}

function resolveCommit(repo, value, label) {
  assertString(value, label, GIT_OBJECT);
  const resolved = git(repo, ['rev-parse', '--verify', `${value}^{commit}`]).trim();
  if (resolved !== value) {
    throw new VerificationError('COMMIT_MISMATCH', `${label} does not resolve exactly`);
  }
  return value;
}

function normalizePath(value, label, { prefix = false } = {}) {
  assertString(value, label);
  if (
    value.startsWith('/') ||
    value.includes('\\') ||
    value.split('/').some((part) => part === '..' || part === '.') ||
    value.includes('\0')
  ) {
    throw new VerificationError('SCHEMA_INVALID', `${label} is not a canonical repository path`);
  }
  if (prefix && !value.endsWith('/')) {
    throw new VerificationError('SCHEMA_INVALID', `${label} prefix must end with /`);
  }
  return value;
}

function globExpression(pattern) {
  let expression = '^';
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === '*') {
      if (pattern[index + 1] === '*') {
        if (pattern[index + 2] === '/') {
          expression += '(?:.*/)?';
          index += 1;
        } else {
          expression += '.*';
        }
        index += 1;
      } else {
        expression += '[^/]*';
      }
    } else if (character === '?') {
      expression += '[^/]';
    } else {
      expression += character.replace(/[|\\{}()[\]^$+?.]/gu, '\\$&');
    }
  }
  return new RegExp(`${expression}$`, 'u');
}

function validateSelector(selector, label) {
  assertExactKeys(selector, ['kind', 'pattern'], label);
  if (!['exact', 'prefix', 'glob'].includes(selector.kind)) {
    throw new VerificationError('SCHEMA_INVALID', `${label}.kind is invalid`);
  }
  normalizePath(selector.pattern, `${label}.pattern`, {
    prefix: selector.kind === 'prefix',
  });
  if (selector.kind === 'glob') globExpression(selector.pattern);
}

export function selectorMatches(selector, path) {
  if (selector.kind === 'exact') return path === selector.pattern;
  if (selector.kind === 'prefix') return path.startsWith(selector.pattern);
  return globExpression(selector.pattern).test(path);
}

function validateStringMap(value, label) {
  assertObject(value, label);
  for (const [key, entry] of Object.entries(value)) {
    assertString(key, `${label} key`, IDENTIFIER);
    assertString(entry, `${label}.${key}`);
  }
}

function validateEnvironmentMap(value, label) {
  assertObject(value, label);
  for (const [key, entry] of Object.entries(value)) {
    assertString(key, `${label} key`, IDENTIFIER);
    if (entry !== null) assertString(entry, `${label}.${key}`);
  }
}

function protectedExecutableIdentity(toolchain, executable) {
  const encoded = toolchain[`executable:${executable}`];
  if (encoded === undefined) return undefined;
  let identity;
  try {
    identity = JSON.parse(encoded);
  } catch {
    throw new VerificationError(
      'EXECUTABLE_IDENTITY_INVALID',
      `executable:${executable} must be canonical JSON`,
    );
  }
  assertExactKeys(identity, ['path', 'sha256'], `executable:${executable}`);
  assertString(identity.path, `executable:${executable}.path`);
  assertString(identity.sha256, `executable:${executable}.sha256`, EXECUTABLE_DIGEST);
  if (JSON.stringify(identity) !== encoded) {
    throw new VerificationError(
      'EXECUTABLE_IDENTITY_INVALID',
      `executable:${executable} must use canonical key order`,
    );
  }
  return identity;
}

function validateDescriptor(descriptor) {
  assertExactKeys(
    descriptor,
    [
      'descriptorVersion',
      'dynamicFallbackSelectors',
      'fallbackNodeId',
      'profiles',
      'repositoryId',
      'schemaVersion',
      'tasks',
    ],
    'task descriptor',
  );
  if (descriptor.schemaVersion !== '1.0.0') {
    throw new VerificationError('SCHEMA_INVALID', 'unsupported task-descriptor schemaVersion');
  }
  assertString(descriptor.descriptorVersion, 'task descriptor version', IDENTIFIER);
  assertString(descriptor.repositoryId, 'task descriptor repositoryId', IDENTIFIER);
  if (descriptor.fallbackNodeId !== null) {
    assertString(descriptor.fallbackNodeId, 'task descriptor fallbackNodeId', IDENTIFIER);
  }
  if (!Array.isArray(descriptor.dynamicFallbackSelectors)) {
    throw new VerificationError('SCHEMA_INVALID', 'dynamicFallbackSelectors must be an array');
  }
  descriptor.dynamicFallbackSelectors.forEach((selector, index) =>
    validateSelector(selector, `dynamicFallbackSelectors[${index}]`),
  );
  if (!Array.isArray(descriptor.tasks) || descriptor.tasks.length === 0) {
    throw new VerificationError('SCHEMA_INVALID', 'task descriptor tasks must be nonempty');
  }
  const taskIds = [];
  for (const [index, task] of descriptor.tasks.entries()) {
    const label = `tasks[${index}]`;
    assertExactKeys(
      task,
      [
        'allowlistedEnv',
        'argv',
        'cwd',
        'dependencies',
        'inputSelectors',
        'nodeId',
        'outputContract',
        'runner',
        'toolchainKeys',
      ],
      label,
    );
    assertString(task.nodeId, `${label}.nodeId`, IDENTIFIER);
    assertUniqueStrings(task.dependencies, `${label}.dependencies`);
    if (!Array.isArray(task.argv) || task.argv.length === 0) {
      throw new VerificationError('SCHEMA_INVALID', `${label}.argv must be nonempty`);
    }
    for (const [argumentIndex, argument] of task.argv.entries()) {
      assertString(argument, `${label}.argv[${argumentIndex}]`);
      if (argument.includes('\0')) {
        throw new VerificationError('SCHEMA_INVALID', `${label}.argv contains NUL`);
      }
    }
    if (!BARE_EXECUTABLE.test(task.argv[0])) {
      throw new VerificationError(
        'SCHEMA_INVALID',
        `${label}.argv[0] must be a bare executable name`,
      );
    }
    if (task.cwd !== '.') normalizePath(task.cwd, `${label}.cwd`);
    assertString(task.runner, `${label}.runner`, IDENTIFIER);
    if (!Array.isArray(task.inputSelectors) || task.inputSelectors.length === 0) {
      throw new VerificationError('SCHEMA_INVALID', `${label}.inputSelectors must be nonempty`);
    }
    task.inputSelectors.forEach((selector, selectorIndex) =>
      validateSelector(selector, `${label}.inputSelectors[${selectorIndex}]`),
    );
    assertUniqueStrings(task.toolchainKeys, `${label}.toolchainKeys`);
    task.toolchainKeys.forEach((key) => assertString(key, `${label} toolchain key`, IDENTIFIER));
    assertUniqueStrings(task.allowlistedEnv, `${label}.allowlistedEnv`);
    task.allowlistedEnv.forEach((key) =>
      assertString(key, `${label} environment key`, ENVIRONMENT_KEY),
    );
    assertObject(task.outputContract, `${label}.outputContract`);
    canonicalBytes(task.outputContract);
    taskIds.push(task.nodeId);
  }
  assertUniqueStrings(taskIds, 'task node IDs');
  const knownTasks = new Set(taskIds);
  if (descriptor.fallbackNodeId !== null && !knownTasks.has(descriptor.fallbackNodeId)) {
    throw new VerificationError('SCHEMA_INVALID', 'fallbackNodeId does not name a task');
  }
  if (descriptor.dynamicFallbackSelectors.length > 0 && descriptor.fallbackNodeId === null) {
    throw new VerificationError('SCHEMA_INVALID', 'dynamic selectors require a fallbackNodeId');
  }
  for (const task of descriptor.tasks) {
    for (const dependency of task.dependencies) {
      if (!knownTasks.has(dependency)) {
        throw new VerificationError(
          'UNKNOWN_DEPENDENCY',
          `task ${task.nodeId} names unknown dependency ${dependency}`,
        );
      }
    }
  }
  if (!Array.isArray(descriptor.profiles) || descriptor.profiles.length === 0) {
    throw new VerificationError('SCHEMA_INVALID', 'task descriptor profiles must be nonempty');
  }
  const profileIds = [];
  for (const [index, profile] of descriptor.profiles.entries()) {
    const label = `profiles[${index}]`;
    assertExactKeys(
      profile,
      profile.mode === 'affected'
        ? ['eligibleNodes', 'mode', 'profileId', 'requiredNodes']
        : ['mode', 'profileId', 'requiredNodes'],
      label,
    );
    assertString(profile.profileId, `${label}.profileId`, IDENTIFIER);
    if (profile.mode !== 'affected' && profile.mode !== 'fixed') {
      throw new VerificationError('SCHEMA_INVALID', `${label}.mode is invalid`);
    }
    assertUniqueStrings(profile.requiredNodes, `${label}.requiredNodes`);
    if (profile.mode === 'affected') {
      assertUniqueStrings(profile.eligibleNodes, `${label}.eligibleNodes`);
    }
    const eligible = new Set(profile.eligibleNodes ?? []);
    for (const nodeId of [...profile.requiredNodes, ...eligible]) {
      if (!knownTasks.has(nodeId)) {
        throw new VerificationError(
          'PROFILE_NODE_UNKNOWN',
          `${label} names unknown node ${nodeId}`,
        );
      }
    }
    if (
      profile.mode === 'affected' &&
      (profile.requiredNodes.some((nodeId) => !eligible.has(nodeId)) ||
        (descriptor.fallbackNodeId !== null && !eligible.has(descriptor.fallbackNodeId)) ||
        descriptor.tasks.some(
          (task) =>
            eligible.has(task.nodeId) &&
            task.dependencies.some((dependency) => !eligible.has(dependency)),
        ))
    ) {
      throw new VerificationError('SCHEMA_INVALID', `${label} is not closed over required nodes`);
    }
    profileIds.push(profile.profileId);
  }
  assertUniqueStrings(profileIds, 'profile IDs');
}

function topologicalTasks(descriptor) {
  const byId = new Map(descriptor.tasks.map((task) => [task.nodeId, task]));
  const visiting = new Set();
  const visited = new Set();
  const ordered = [];
  const visit = (nodeId) => {
    if (visiting.has(nodeId)) {
      throw new VerificationError('TASK_CYCLE', `task dependency cycle reaches ${nodeId}`);
    }
    if (visited.has(nodeId)) return;
    visiting.add(nodeId);
    for (const dependency of byId.get(nodeId).dependencies) visit(dependency);
    visiting.delete(nodeId);
    visited.add(nodeId);
    ordered.push(byId.get(nodeId));
  };
  for (const task of descriptor.tasks) visit(task.nodeId);
  return ordered;
}

function snapshot(repo, commit) {
  const output = git(repo, ['ls-tree', '-r', '-z', '--full-tree', commit], {
    encoding: null,
  });
  const entries = [];
  for (const record of output.toString('utf8').split('\0')) {
    if (record === '') continue;
    const match = /^(\d+) ([a-z]+) ([0-9a-f]+)\t(.+)$/u.exec(record);
    if (match === null) {
      throw new VerificationError('GIT_ERROR', 'git ls-tree emitted an unknown record');
    }
    const [, mode, type, objectId, path] = match;
    normalizePath(path, 'Git tree path');
    entries.push({ mode, type, objectId, path });
  }
  return entries.sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
  );
}

function changedPaths(repo, base, candidate) {
  const output = git(
    repo,
    ['diff', '--name-status', '-z', '-M', '--find-renames', base, candidate],
    { encoding: null },
  );
  const fields = output.toString('utf8').split('\0');
  const paths = new Set();
  let index = 0;
  while (index < fields.length && fields[index] !== '') {
    const status = fields[index++];
    if (/^[RC]\d+$/u.test(status)) {
      const before = fields[index++];
      const after = fields[index++];
      if (before === undefined || after === undefined) {
        throw new VerificationError('GIT_ERROR', 'truncated Git rename/copy record');
      }
      normalizePath(before, 'changed preimage path');
      normalizePath(after, 'changed candidate path');
      paths.add(before);
      paths.add(after);
    } else if (/^[AMDTUXB]$/u.test(status)) {
      const path = fields[index++];
      if (path === undefined)
        throw new VerificationError('GIT_ERROR', 'truncated Git change record');
      normalizePath(path, 'changed path');
      paths.add(path);
    } else {
      throw new VerificationError('GIT_ERROR', `unsupported Git change status ${status}`);
    }
  }
  return [...paths].sort();
}

function selectedNodeIds(descriptor, profile, changes) {
  const selected = new Set(profile.requiredNodes);
  const impacted = new Set();
  const eligible = profile.mode === 'affected' ? new Set(profile.eligibleNodes) : null;
  if (profile.mode === 'affected') {
    for (const path of changes) {
      if (descriptor.dynamicFallbackSelectors.some((selector) => selectorMatches(selector, path))) {
        impacted.add(descriptor.fallbackNodeId);
        continue;
      }
      const matched = descriptor.tasks.filter(
        (task) =>
          eligible.has(task.nodeId) &&
          task.nodeId !== descriptor.fallbackNodeId &&
          task.inputSelectors.some((selector) => selectorMatches(selector, path)),
      );
      if (matched.length === 0) {
        if (descriptor.fallbackNodeId === null) {
          throw new VerificationError(
            'UNKNOWN_PATH',
            `changed path ${path} matches no approved task`,
          );
        }
        impacted.add(descriptor.fallbackNodeId);
      } else {
        matched.forEach((task) => impacted.add(task.nodeId));
      }
    }
  }

  const dependents = new Map(descriptor.tasks.map((task) => [task.nodeId, []]));
  for (const task of descriptor.tasks) {
    for (const dependency of task.dependencies) dependents.get(dependency).push(task.nodeId);
  }
  const downstreamQueue = [...impacted];
  for (let index = 0; index < downstreamQueue.length; index += 1) {
    const nodeId = downstreamQueue[index];
    selected.add(nodeId);
    for (const dependent of dependents.get(nodeId)) {
      const aggregateFallback = dependent === descriptor.fallbackNodeId;
      if (
        !aggregateFallback &&
        (eligible === null || eligible.has(dependent)) &&
        !impacted.has(dependent)
      ) {
        impacted.add(dependent);
        downstreamQueue.push(dependent);
      }
    }
  }

  const byId = new Map(descriptor.tasks.map((task) => [task.nodeId, task]));
  const dependencyQueue = [...selected];
  for (let index = 0; index < dependencyQueue.length; index += 1) {
    for (const dependency of byId.get(dependencyQueue[index]).dependencies) {
      if (!selected.has(dependency)) {
        selected.add(dependency);
        dependencyQueue.push(dependency);
      }
    }
  }
  if (selected.size === 0) {
    throw new VerificationError('PROFILE_EMPTY', `profile ${profile.profileId} selects no nodes`);
  }
  return selected;
}

const PROFILE_ID_SEPARATOR = /[/\\]/u;

/**
 * A profile id is a descriptor identifier, never a path (ADR-REL-0031). The grammar
 * alone decides: an id with a path separator is refused before any descriptor is read,
 * so a usage mistake is never reported as PROFILE_UNKNOWN, which stays reserved for a
 * well-formed id the descriptor does not declare.
 */
export function assertProfileId(profileId) {
  if (
    typeof profileId !== 'string' ||
    profileId === '' ||
    profileId.includes('\0') ||
    PROFILE_ID_SEPARATOR.test(profileId)
  ) {
    throw new VerificationError(
      'PROFILE_ID_INVALID',
      'profile must be a descriptor profile id, not a path',
    );
  }
}

function candidateSnapshot(repo, candidateCommit) {
  const entries = snapshot(repo, candidateCommit).filter(
    (entry) => !isHarnessMutatedPath(entry.path),
  );
  return { entries };
}

/**
 * Task keys and required nodes for an already-selected node set. Schema 1.0.0 omits
 * output contracts; schema 1.1.0 and the release form 1.2.0 carry them and require
 * every selected environment value to be a SHA-256 identity or null.
 */
function requiredNodesFor({
  repo,
  descriptor,
  ordered,
  selected,
  candidateCommit,
  entries,
  toolchain,
  environment,
  policySchemaVersion,
}) {
  const portable = policySchemaVersion !== '1.0.0';
  const descriptorDigest = sha256Hex(descriptor);
  const blobDigests = objectContentDigests(
    repo,
    entries.map((entry) => entry.objectId),
  );
  const outputContracts = new Map(
    ordered.map((task) => [
      task.nodeId,
      resolveMutationDiscoveryContract(repo, candidateCommit, task.outputContract),
    ]),
  );
  const taskKeys = new Map();
  for (const task of ordered) {
    if (!selected.has(task.nodeId)) continue;
    const selectedToolchain = {};
    for (const key of [...task.toolchainKeys].sort()) {
      if (toolchain[key] === undefined) {
        throw new VerificationError(
          'TOOLCHAIN_MISSING',
          `task ${task.nodeId} requires toolchain ${key}`,
        );
      }
      selectedToolchain[key] = toolchain[key];
    }
    const selectedEnvironment = {};
    for (const key of [...task.allowlistedEnv].sort()) {
      if (!Object.hasOwn(environment, key)) {
        throw new VerificationError(
          'ENVIRONMENT_MISSING',
          `task ${task.nodeId} requires environment ${key}`,
        );
      }
      if (portable && environment[key] !== null && !ENVIRONMENT_IDENTITY.test(environment[key])) {
        throw new VerificationError(
          'ENVIRONMENT_IDENTITY_INVALID',
          `task ${task.nodeId} environment ${key} must be a SHA-256 identity`,
        );
      }
      selectedEnvironment[key] = environment[key];
    }
    const inputs = [];
    for (const entry of entries) {
      if (!task.inputSelectors.some((selector) => selectorMatches(selector, entry.path))) continue;
      const digest = blobDigests.get(entry.objectId);
      if (digest === undefined) throw new VerificationError('GIT_ERROR', 'object digest missing');
      inputs.push({
        path: entry.path,
        mode: entry.mode,
        type: entry.type,
        contentDigest: digest,
      });
    }
    const dependencies = task.dependencies.map((nodeId) => ({
      nodeId,
      taskKey: taskKeys.get(nodeId),
    }));
    const executable = protectedExecutableIdentity(toolchain, task.argv[0]);
    taskKeys.set(
      task.nodeId,
      sha256Hex({
        schemaVersion: '1.0.0',
        descriptorDigest,
        descriptorVersion: descriptor.descriptorVersion,
        nodeId: task.nodeId,
        argv: task.argv,
        ...(executable === undefined ? {} : { executable }),
        cwd: task.cwd,
        runner: task.runner,
        toolchain: selectedToolchain,
        environment: selectedEnvironment,
        outputContract: outputContracts.get(task.nodeId),
        inputs,
        dependencies,
      }),
    );
  }
  const requiredNodes = ordered
    .filter((task) => selected.has(task.nodeId))
    .map((task) => {
      const node = {
        nodeId: task.nodeId,
        taskKey: taskKeys.get(task.nodeId),
        dependencies: [...task.dependencies],
      };
      if (portable) node.outputContract = outputContracts.get(task.nodeId);
      return node;
    });
  return { descriptorDigest, requiredNodes, blobDigests };
}

export function buildExpectedTaskPolicy({
  repo,
  descriptor,
  profileId,
  candidateCommit,
  expectedTree,
  baseCommit,
  toolchain,
  environment,
  policySchemaVersion = '1.0.0',
}) {
  assertProfileId(profileId);
  if (policySchemaVersion !== '1.0.0' && policySchemaVersion !== '1.1.0') {
    throw new VerificationError('SCHEMA_INVALID', 'unsupported task-policy schemaVersion');
  }
  validateDescriptor(descriptor);
  validateStringMap(toolchain, 'toolchain');
  validateEnvironmentMap(environment, 'environment');
  const ordered = topologicalTasks(descriptor);
  resolveCommit(repo, candidateCommit, 'candidate commit');
  const candidateTree = git(repo, ['show', '-s', '--format=%T', candidateCommit]).trim();
  assertString(expectedTree, 'expected tree', GIT_OBJECT);
  if (candidateTree !== expectedTree) {
    throw new VerificationError(
      'TREE_MISMATCH',
      'candidate commit tree does not match expected tree',
    );
  }
  const profile = descriptor.profiles.find((entry) => entry.profileId === profileId);
  if (profile === undefined) {
    throw new VerificationError('PROFILE_UNKNOWN', `unknown profile ${profileId}`);
  }
  let changes = [];
  if (profile.mode === 'affected') {
    if (baseCommit === undefined) {
      throw new VerificationError(
        'BASE_REQUIRED',
        'affected profile requires an exact base commit',
      );
    }
    resolveCommit(repo, baseCommit, 'base commit');
    const ancestor = spawnSync('git', [
      '-C',
      repo,
      'merge-base',
      '--is-ancestor',
      baseCommit,
      candidateCommit,
    ]);
    if (ancestor.status !== 0) {
      throw new VerificationError(
        'BASE_NOT_ANCESTOR',
        'base commit is not an ancestor of candidate',
      );
    }
    changes = changedPaths(repo, baseCommit, candidateCommit).filter(
      (path) => !isHarnessMutatedPath(path),
    );
  }
  const selected = selectedNodeIds(descriptor, profile, changes);
  const { entries } = candidateSnapshot(repo, candidateCommit);
  const { descriptorDigest, requiredNodes } = requiredNodesFor({
    repo,
    descriptor,
    ordered,
    selected,
    candidateCommit,
    entries,
    toolchain,
    environment,
    policySchemaVersion,
  });
  const taskPolicy = {
    schemaVersion: policySchemaVersion,
    repositoryId: descriptor.repositoryId,
    requiredNodes,
  };
  return {
    taskPolicy,
    taskPolicyDigest: sha256Hex(taskPolicy),
    descriptorDigest,
    profileId,
    candidateTree,
    changedPaths: changes,
  };
}

// ---------------------------------------------------------------------------------------
// Release-intent reconstruction (ADR-REL-0031).
//
// An independent port of the release verification decision and task selection of the
// DEVAI check runner (packages/cli/src/services/release-profile.ts and the release target
// of its task planner). A release run selects its nodes by capability from a pinned
// release intent and a release verification profile and pins the release form of the
// task policy: schema 1.2.0 with an exact-candidate-tree input projection. The exporter
// rebuilds that policy from the pins alone and never from the task set a receipt claims.
// ---------------------------------------------------------------------------------------

const RELEASE_STAGES = ['preflight', 'certify'];
const RELEASE_INPUT_PROJECTION = Object.freeze({
  schemaVersion: '1.0.0',
  source: 'exact-candidate-tree',
  excludedPrefixes: Object.freeze([...HARNESS_MUTATED_PREFIXES].sort()),
});
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const KNOWN_RISKS = new Set([
  'authentication',
  'authorization',
  'tenancy',
  'rls',
  'cryptography',
  'secrets',
  'credentials',
  'database',
  'migration',
  'release-integrity',
  'evidence',
  'provenance',
  'publication',
  'ledger',
  'mutation-policy',
  'test-policy',
  'test-configuration',
  'sanitization',
  'public-api',
  'export-map',
  'package-boundary',
  'lockfile',
  'toolchain',
  'cross-package',
  'large-change',
  'protected-resource',
]);
const UNCONDITIONAL_FLOOR = [
  'formatting-hygiene',
  'lint',
  'type-integrity',
  'schema-consistency',
  'secret-scan',
  'path-portability',
  'package-integrity',
  'exact-candidate',
];
/** The capabilities a release preflight executes; mirrors release-preflight.ts. */
const PREFLIGHT_CAPABILITIES = [...UNCONDITIONAL_FLOOR];
const BROAD_CAPABILITIES = [
  'unit',
  'integration',
  'e2e',
  'consumer',
  'api-compatibility',
  'migration',
  'rollback',
  'adopter-materialization',
  'security',
  'database',
  'tenancy',
  'provenance',
  'reproducibility',
];
const TRANSITION_CAPABILITIES = {
  patch: ['affected-checks', 'dependent-checks', 'build-integrity'],
  prerelease: ['affected-checks', 'dependent-checks', 'build-integrity'],
  minor: ['unit', 'integration', 'e2e', 'consumer', 'api-compatibility', 'adopter-materialization'],
  major: BROAD_CAPABILITIES,
  'support-promotion': [...BROAD_CAPABILITIES, 'operational-matrix'],
};
const LTS_CAPABILITIES = [...BROAD_CAPABILITIES, 'operational-matrix'];
// Prerelease ladder of law/policy/release-lifecycle.json (ADR-REL-0028).
const PRERELEASE_IDENTIFIER = /^(alpha|beta|rc)\.(0|[1-9][0-9]*)$/u;
const RUNG_ORDER = ['alpha', 'beta', 'rc'];
const STABLE_FROM = 'rc';
const RUNG_CAPABILITIES = {
  alpha: [...UNCONDITIONAL_FLOOR, 'affected-checks', 'dependent-checks'],
  beta: [...UNCONDITIONAL_FLOOR, 'affected-checks', 'dependent-checks', 'unit', 'integration'],
  rc: [...UNCONDITIONAL_FLOOR, 'affected-checks', 'dependent-checks', ...BROAD_CAPABILITIES],
};
const INTENT_KEYS = [
  'schemaVersion',
  'release_unit',
  'current_version',
  'target_version',
  'support',
  'support_promotion',
  'change_kind',
  'channel',
  'changed_paths',
  'changed_packages',
  'risks',
  'owner_escalations',
  'candidate',
  'base',
];
const INTENT_REQUIRED = [
  'schemaVersion',
  'release_unit',
  'current_version',
  'target_version',
  'support',
  'changed_paths',
  'changed_packages',
  'candidate',
  'base',
];
const RISK_IDENTIFIER = /^[a-z][a-z0-9-]{0,63}$/u;

function parseVersion(value) {
  const match = SEMVER.exec(value);
  if (match === null) return undefined;
  const prerelease = (match[4] ?? '')
    .split('.')
    .filter(Boolean)
    .map((identifier) => (/^\d+$/u.test(identifier) ? Number(identifier) : identifier));
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]), prerelease };
}

/** `null` for a stable version, `undefined` for a prerelease outside the ladder. */
function resolveRung(version) {
  if (version.prerelease.length === 0) return null;
  const match = PRERELEASE_IDENTIFIER.exec(version.prerelease.join('.'));
  if (match === null) return undefined;
  return { rung: match[1], suffix: Number(match[2]) };
}

function sameCore(left, right) {
  return left.major === right.major && left.minor === right.minor && left.patch === right.patch;
}

function ladderPromotionAllowed(current, target) {
  if (current === null) return target === null;
  if (target === null) return current.rung === STABLE_FROM;
  if (current.rung === target.rung) return target.suffix > current.suffix;
  return RUNG_ORDER.indexOf(target.rung) === RUNG_ORDER.indexOf(current.rung) + 1;
}

function comparePrerelease(left, right) {
  if (left.length === 0 && right.length === 0) return 0;
  if (left.length === 0) return 1;
  if (right.length === 0) return -1;
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const a = left[index];
    const b = right[index];
    if (a === undefined) return -1;
    if (b === undefined) return 1;
    if (a === b) continue;
    if (typeof a === 'number' && typeof b === 'string') return -1;
    if (typeof a === 'string' && typeof b === 'number') return 1;
    return a < b ? -1 : 1;
  }
  return 0;
}

function compareVersions(left, right) {
  for (const key of ['major', 'minor', 'patch']) {
    if (left[key] !== right[key]) return left[key] < right[key] ? -1 : 1;
  }
  return comparePrerelease(left.prerelease, right.prerelease);
}

function classifyTransition(current, target, promotion) {
  const comparison = compareVersions(current, target);
  if (comparison === 0) return promotion ? 'support-promotion' : undefined;
  if (comparison > 0) return undefined;
  if (current.prerelease.length > 0 || target.prerelease.length > 0) return 'prerelease';
  if (current.major !== target.major) return 'major';
  if (current.minor !== target.minor) return 'minor';
  return 'patch';
}

function blockedDecision(support, reason) {
  return {
    schemaVersion: '1.0.0',
    verdict: 'block',
    support,
    capabilities: [],
    mutation: 'none',
    mutationDisposition: { status: 'blocked', reason: 'policy-invalid' },
    blockingReasons: [reason],
  };
}

function addRiskCapabilities(capabilities, risks) {
  const any = (names) => risks.some((risk) => names.includes(risk));
  if (risks.length > 0) {
    capabilities.add('security');
    capabilities.add('integration');
  }
  if (any(['tenancy', 'rls'])) capabilities.add('tenancy');
  if (any(['database', 'migration'])) capabilities.add('database');
  if (any(['public-api', 'export-map', 'package-boundary'])) {
    capabilities.add('api-compatibility');
    capabilities.add('consumer');
  }
  if (any(['release-integrity', 'evidence', 'provenance', 'publication', 'ledger'])) {
    capabilities.add('provenance');
    capabilities.add('reproducibility');
  }
  if (any(['lockfile', 'toolchain', 'cross-package', 'large-change'])) {
    capabilities.add('integration');
    capabilities.add('consumer');
  }
}

/** The release verification decision a release run derives from its intent and policy. */
function releaseDecision(intent, releaseProfile) {
  const current = parseVersion(intent.current_version);
  const target = parseVersion(intent.target_version);
  if (current === undefined || target === undefined) {
    return blockedDecision(intent.support, 'invalid-semver');
  }
  const currentRung = resolveRung(current);
  const targetRung = resolveRung(target);
  if (currentRung === undefined || targetRung === undefined) {
    return blockedDecision(intent.support, 'invalid-semver');
  }
  const order = compareVersions(current, target);
  if (order > 0) return blockedDecision(intent.support, 'downgrade');
  if (order < 0 && sameCore(current, target) && !ladderPromotionAllowed(currentRung, targetRung)) {
    return blockedDecision(intent.support, 'downgrade');
  }
  const transition = classifyTransition(current, target, intent.support_promotion === true);
  if (transition === undefined) {
    return blockedDecision(intent.support, 'same-version-without-support-promotion');
  }
  if (transition === 'support-promotion' && intent.support !== 'lts') {
    return blockedDecision(intent.support, 'support-promotion-requires-lts');
  }
  const channel = targetRung === null ? 'stable' : targetRung.rung;
  if (intent.channel !== undefined && intent.channel !== channel) {
    return blockedDecision(intent.support, 'channel-mismatch');
  }
  const declaredRiskClasses = new Set(Object.keys(releaseProfile.risk_capabilities));
  const risks = intent.risks ?? [];
  const unknownRisks = risks.filter(
    (risk) => !KNOWN_RISKS.has(risk) && !declaredRiskClasses.has(risk),
  );
  if (unknownRisks.length > 0) {
    return blockedDecision(intent.support, `unknown-risk:${unknownRisks.sort().join(',')}`);
  }
  const capabilities = new Set([...UNCONDITIONAL_FLOOR, ...TRANSITION_CAPABILITIES[transition]]);
  const rung = targetRung?.rung ?? (currentRung === null ? undefined : STABLE_FROM);
  if (rung !== undefined) RUNG_CAPABILITIES[rung].forEach((value) => capabilities.add(value));
  if (intent.support === 'lts') LTS_CAPABILITIES.forEach((value) => capabilities.add(value));
  addRiskCapabilities(capabilities, risks);
  for (const risk of risks) {
    for (const capability of releaseProfile.risk_capabilities[risk] ?? []) {
      capabilities.add(capability);
    }
  }
  for (const escalation of intent.owner_escalations ?? []) capabilities.add(escalation);
  return {
    schemaVersion: '1.0.0',
    verdict: 'ready',
    transition,
    support: intent.support,
    capabilities: [...capabilities].sort(),
    mutation: 'none',
    mutationDisposition: { status: 'not-required', reason: 'mutation-external-hardening' },
    blockingReasons: [],
  };
}

/** Task roots for the selected capabilities, refusing an unsatisfied capability. */
function releaseRoots(capabilities, capabilityTasks, knownTasks) {
  const missing = [];
  const selected = new Set();
  for (const capability of capabilities) {
    const nodes = capabilityTasks[capability] ?? [];
    if (nodes.length === 0) {
      missing.push(capability);
      continue;
    }
    for (const nodeId of nodes) {
      if (!knownTasks.has(nodeId)) {
        throw new VerificationError(
          'PROFILE_NODE_UNKNOWN',
          `release profile capability ${capability} names unknown task ${nodeId}`,
        );
      }
      selected.add(nodeId);
    }
  }
  if (missing.length > 0) {
    throw new VerificationError(
      'INTENT_DECISION_BLOCKED',
      `release decision is not satisfiable: capability-unsatisfied:${missing.sort().join(',')}`,
    );
  }
  return [...selected].sort();
}

function assertStringArray(value, label, pattern) {
  assertUniqueStrings(value, label);
  value.forEach((entry, index) => assertString(entry, `${label}[${index}]`, pattern));
}

function assertGitIdentity(value, label) {
  assertExactKeys(value, ['commit', 'tree'], label);
  assertString(value.commit, `${label}.commit`, GIT_OBJECT);
  assertString(value.tree, `${label}.tree`, GIT_OBJECT);
}

/** Structural validation of the fields of release-intent.schema.json the reconstruction reads. */
export function validateReleaseIntent(intent) {
  assertObject(intent, 'release intent');
  for (const key of Object.keys(intent)) {
    if (!INTENT_KEYS.includes(key)) {
      throw new VerificationError('SCHEMA_INVALID', `release intent has unknown key ${key}`);
    }
  }
  for (const key of INTENT_REQUIRED) {
    if (!Object.hasOwn(intent, key)) {
      throw new VerificationError('SCHEMA_INVALID', `release intent requires ${key}`);
    }
  }
  if (intent.schemaVersion !== '1.0.0') {
    throw new VerificationError('SCHEMA_INVALID', 'unsupported release-intent schemaVersion');
  }
  assertString(intent.release_unit, 'release intent release_unit', /^.{1,200}$/su);
  assertString(intent.current_version, 'release intent current_version');
  assertString(intent.target_version, 'release intent target_version');
  if (!['preview', 'current', 'lts'].includes(intent.support)) {
    throw new VerificationError('SCHEMA_INVALID', 'release intent support is invalid');
  }
  if (intent.support_promotion !== undefined && typeof intent.support_promotion !== 'boolean') {
    throw new VerificationError('SCHEMA_INVALID', 'release intent support_promotion is invalid');
  }
  if (
    intent.change_kind !== undefined &&
    !['documentation', 'metadata', 'behavioral'].includes(intent.change_kind)
  ) {
    throw new VerificationError('SCHEMA_INVALID', 'release intent change_kind is invalid');
  }
  if (intent.channel !== undefined && !['alpha', 'beta', 'rc', 'stable'].includes(intent.channel)) {
    throw new VerificationError('SCHEMA_INVALID', 'release intent channel is invalid');
  }
  assertUniqueStrings(intent.changed_paths, 'release intent changed_paths');
  intent.changed_paths.forEach((path, index) =>
    normalizePath(path, `release intent changed_paths[${index}]`),
  );
  assertUniqueStrings(intent.changed_packages, 'release intent changed_packages');
  if (intent.risks !== undefined) {
    assertStringArray(intent.risks, 'release intent risks', RISK_IDENTIFIER);
  }
  if (intent.owner_escalations !== undefined) {
    assertStringArray(
      intent.owner_escalations,
      'release intent owner_escalations',
      RISK_IDENTIFIER,
    );
  }
  assertGitIdentity(intent.candidate, 'release intent candidate');
  assertGitIdentity(intent.base, 'release intent base');
}

/** Structural validation of the release verification profile fields the reconstruction reads. */
export function validateReleaseProfile(releaseProfile) {
  assertObject(releaseProfile, 'release verification profile');
  assertString(
    releaseProfile.release_unit,
    'release verification profile release_unit',
    /^.{1,200}$/su,
  );
  assertObject(releaseProfile.capability_tasks, 'release verification profile capability_tasks');
  for (const [capability, nodes] of Object.entries(releaseProfile.capability_tasks)) {
    assertStringArray(nodes, `release verification profile capability_tasks.${capability}`);
  }
  assertObject(releaseProfile.risk_capabilities, 'release verification profile risk_capabilities');
  for (const [risk, capabilities] of Object.entries(releaseProfile.risk_capabilities)) {
    assertStringArray(
      capabilities,
      `release verification profile risk_capabilities.${risk}`,
      RISK_IDENTIFIER,
    );
  }
  if (!Array.isArray(releaseProfile.mutation_roster)) {
    throw new VerificationError(
      'SCHEMA_INVALID',
      'release verification profile mutation_roster must be an array',
    );
  }
}

function sameIdentity(left, right) {
  return left?.commit === right?.commit && left?.tree === right?.tree;
}

/**
 * Reconstructs the release task policy a release-intent run pinned for one stage, from the
 * pinned intent, release verification profile, descriptor, toolchain, environment, base,
 * and candidate. Every drift is refused with its own code before any task key is built.
 */
export function buildExpectedReleaseTaskPolicy({
  repo,
  descriptor,
  releaseIntent,
  releaseProfile,
  stage,
  candidateCommit,
  expectedTree,
  baseCommit,
  toolchain,
  environment,
}) {
  if (!RELEASE_STAGES.includes(stage)) {
    throw new VerificationError(
      'INTENT_STAGE_MISMATCH',
      `release stage must be preflight or certify, not ${String(stage)}`,
    );
  }
  validateDescriptor(descriptor);
  validateStringMap(toolchain, 'toolchain');
  validateEnvironmentMap(environment, 'environment');
  validateReleaseIntent(releaseIntent);
  validateReleaseProfile(releaseProfile);
  if (releaseProfile.release_unit !== releaseIntent.release_unit) {
    throw new VerificationError(
      'INTENT_POLICY_STALE',
      'release verification profile release_unit differs from the intent release_unit',
    );
  }

  const candidateMismatch = (message) =>
    new VerificationError('INTENT_CANDIDATE_MISMATCH', message);
  if (!sameIdentity(releaseIntent.candidate, { commit: candidateCommit, tree: expectedTree })) {
    throw candidateMismatch('candidate commit and tree differ from the intent candidate');
  }
  let candidateTree;
  try {
    resolveCommit(repo, candidateCommit, 'candidate commit');
    candidateTree = git(repo, ['rev-parse', '--verify', `${candidateCommit}^{tree}`]).trim();
  } catch (error) {
    if (!(error instanceof VerificationError)) throw error;
    throw candidateMismatch(`candidate commit does not resolve: ${error.message}`);
  }
  if (candidateTree !== expectedTree) {
    throw candidateMismatch('candidate commit tree differs from the intent candidate tree');
  }

  const baseMismatch = (message) => new VerificationError('INTENT_BASE_MISMATCH', message);
  if (baseCommit !== releaseIntent.base.commit) {
    throw baseMismatch('base commit differs from the intent base');
  }
  let baseTree;
  try {
    resolveCommit(repo, baseCommit, 'base commit');
    baseTree = git(repo, ['rev-parse', '--verify', `${baseCommit}^{tree}`]).trim();
  } catch (error) {
    if (!(error instanceof VerificationError)) throw error;
    throw baseMismatch(`base commit does not resolve: ${error.message}`);
  }
  if (baseTree !== releaseIntent.base.tree) {
    throw baseMismatch('base commit does not resolve to the intent base tree');
  }
  const ancestor = spawnSync('git', [
    '-C',
    repo,
    'merge-base',
    '--is-ancestor',
    baseCommit,
    candidateCommit,
  ]);
  if (ancestor.status !== 0) {
    throw baseMismatch('base commit is not an ancestor of the candidate');
  }

  const decision = releaseDecision(releaseIntent, releaseProfile);
  if (decision.verdict !== 'ready') {
    throw new VerificationError(
      'INTENT_DECISION_BLOCKED',
      `release decision is ${decision.verdict}: ${decision.blockingReasons.join(',')}`,
    );
  }

  const ordered = topologicalTasks(descriptor);
  const knownTasks = new Set(descriptor.tasks.map((task) => task.nodeId));
  // Mutation roster selection adds no task node while mutation evidence stays external
  // hardening (decision.mutation is always none), so the certify roots are the capability
  // roots alone and no task key carries a release mutation binding.
  const capabilities =
    stage === 'preflight'
      ? decision.capabilities.filter((capability) => PREFLIGHT_CAPABILITIES.includes(capability))
      : decision.capabilities;
  const roots = releaseRoots(capabilities, releaseProfile.capability_tasks, knownTasks);
  const affectedSelection =
    stage === 'certify' && decision.capabilities.includes('affected-checks');
  let changes = [];
  let selectionProfile = { profileId: `release:${stage}`, mode: 'fixed', requiredNodes: roots };
  if (affectedSelection) {
    const affected = descriptor.profiles.find((entry) => entry.profileId === 'affected');
    if (affected?.mode !== 'affected') {
      throw new VerificationError(
        'PROFILE_UNKNOWN',
        'release affected-checks selection requires the descriptor profile affected',
      );
    }
    changes = changedPaths(repo, baseCommit, candidateCommit).filter(
      (path) => !isHarnessMutatedPath(path),
    );
    selectionProfile = {
      ...selectionProfile,
      mode: 'affected',
      eligibleNodes: affected.eligibleNodes,
    };
  }
  const selected = selectedNodeIds(descriptor, selectionProfile, changes);
  const { entries } = candidateSnapshot(repo, candidateCommit);
  const { descriptorDigest, requiredNodes, blobDigests } = requiredNodesFor({
    repo,
    descriptor,
    ordered,
    selected,
    candidateCommit,
    entries,
    toolchain,
    environment,
    policySchemaVersion: '1.2.0',
  });
  const projection = entries.map((entry) => ({
    path: entry.path,
    mode: entry.mode,
    type: entry.type,
    contentDigest: blobDigests.get(entry.objectId),
  }));
  const taskPolicy = {
    schemaVersion: '1.2.0',
    repositoryId: descriptor.repositoryId,
    requiredNodes,
    inputProjection: {
      ...RELEASE_INPUT_PROJECTION,
      excludedPrefixes: [...RELEASE_INPUT_PROJECTION.excludedPrefixes],
      digest: sha256Hex(projection),
    },
  };
  return {
    taskPolicy,
    taskPolicyDigest: sha256Hex(taskPolicy),
    descriptorDigest,
    decision,
    stage,
    candidateTree,
    changedPaths: changes,
  };
}

export function readStringMap(path, label) {
  let value;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new VerificationError('MALFORMED_JSON', `${label} is invalid: ${error.message}`);
  }
  validateStringMap(value, label);
  return value;
}

export function readEnvironmentMap(path, label) {
  let value;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new VerificationError('MALFORMED_JSON', `${label} is invalid: ${error.message}`);
  }
  validateEnvironmentMap(value, label);
  return value;
}

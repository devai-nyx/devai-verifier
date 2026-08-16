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
  const output = Buffer.from(
    git(repo, ['cat-file', '--batch'], { encoding: null, input: `${unique.join('\n')}\n` }),
  );
  const digests = new Map();
  let offset = 0;
  for (const expectedObjectId of unique) {
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
  normalizePath(selector.pattern, `${label}.pattern`, { prefix: selector.kind === 'prefix' });
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
        throw new VerificationError('PROFILE_NODE_UNKNOWN', `${label} names unknown node ${nodeId}`);
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
  const output = git(repo, ['ls-tree', '-r', '-z', '--full-tree', commit], { encoding: null });
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
  return entries.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
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
      if (path === undefined) throw new VerificationError('GIT_ERROR', 'truncated Git change record');
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
          throw new VerificationError('UNKNOWN_PATH', `changed path ${path} matches no approved task`);
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
      if (!aggregateFallback && (eligible === null || eligible.has(dependent)) && !impacted.has(dependent)) {
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
    throw new VerificationError('TREE_MISMATCH', 'candidate commit tree does not match expected tree');
  }
  const profile = descriptor.profiles.find((entry) => entry.profileId === profileId);
  if (profile === undefined) {
    throw new VerificationError('PROFILE_UNKNOWN', `unknown profile ${profileId}`);
  }
  let changes = [];
  if (profile.mode === 'affected') {
    if (baseCommit === undefined) {
      throw new VerificationError('BASE_REQUIRED', 'affected profile requires an exact base commit');
    }
    resolveCommit(repo, baseCommit, 'base commit');
    const ancestor = spawnSync('git', ['-C', repo, 'merge-base', '--is-ancestor', baseCommit, candidateCommit]);
    if (ancestor.status !== 0) {
      throw new VerificationError('BASE_NOT_ANCESTOR', 'base commit is not an ancestor of candidate');
    }
    changes = changedPaths(repo, baseCommit, candidateCommit);
  }
  const selected = selectedNodeIds(descriptor, profile, changes);
  const entries = snapshot(repo, candidateCommit);
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
        throw new VerificationError('TOOLCHAIN_MISSING', `task ${task.nodeId} requires toolchain ${key}`);
      }
      selectedToolchain[key] = toolchain[key];
    }
    const selectedEnvironment = {};
    for (const key of [...task.allowlistedEnv].sort()) {
      if (!Object.hasOwn(environment, key)) {
        throw new VerificationError('ENVIRONMENT_MISSING', `task ${task.nodeId} requires environment ${key}`);
      }
      if (
        policySchemaVersion === '1.1.0' &&
        environment[key] !== null &&
        !ENVIRONMENT_IDENTITY.test(environment[key])
      ) {
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
      inputs.push({ path: entry.path, mode: entry.mode, type: entry.type, contentDigest: digest });
    }
    const dependencies = task.dependencies.map((nodeId) => ({
      nodeId,
      taskKey: taskKeys.get(nodeId),
    }));
    taskKeys.set(
      task.nodeId,
      sha256Hex({
        schemaVersion: '1.0.0',
        descriptorDigest,
        descriptorVersion: descriptor.descriptorVersion,
        nodeId: task.nodeId,
        argv: task.argv,
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
      if (policySchemaVersion === '1.1.0') node.outputContract = outputContracts.get(task.nodeId);
      return node;
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

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { sha256Hex } from '../src/canonical.js';
import { buildExpectedTaskPolicy, selectorMatches } from '../src/policy-builder.js';

const CLI = resolve(import.meta.dirname, '../src/build-policy-cli.js');
const TOOLCHAIN = { node: '24.5.0', git: '2.50.1' };
const ENVIRONMENT = { CI: 'false', IGNORED_SECRET: 'not-bound' };
const PORTABLE_ENVIRONMENT = Object.fromEntries(
  Object.entries(ENVIRONMENT).map(([key, value]) => [key, `sha256:${sha256Hex(value)}`]),
);
const temporaryDirectories = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function git(repo, args) {
  return execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim();
}

function put(repo, path, content) {
  mkdirSync(dirname(join(repo, path)), { recursive: true });
  writeFileSync(join(repo, path), content);
}

function commit(repo, message) {
  git(repo, ['add', '-A']);
  git(repo, ['commit', '--quiet', '--allow-empty', '-m', message]);
  return {
    commit: git(repo, ['rev-parse', 'HEAD']),
    tree: git(repo, ['show', '-s', '--format=%T', 'HEAD']),
  };
}

function repository() {
  const repo = mkdtempSync(join(tmpdir(), 'devai-policy-builder-'));
  temporaryDirectories.push(repo);
  git(repo, ['init', '--quiet', '-b', 'main']);
  git(repo, ['config', 'user.name', 'Verifier Test']);
  git(repo, ['config', 'user.email', 'verifier@example.invalid']);
  put(repo, 'package-lock.json', '{"lockfileVersion":3}\n');
  put(repo, 'config.json', '{"strict":true}\n');
  put(repo, 'src/a.js', 'export const value = 1;\n');
  put(repo, 'tests/helper.js', 'export const fixture = 1;\n');
  put(repo, 'tests/root.test.js', 'export const testCase = 1;\n');
  put(repo, 'tests/unit/a.test.js', 'export const unit = 1;\n');
  return { repo, base: commit(repo, 'base') };
}

function task({
  nodeId,
  dependencies = [],
  inputSelectors,
  argv = ['node', '--test'],
  cwd = '.',
  runner = 'node-test-v1',
  toolchainKeys = ['node'],
  allowlistedEnv = ['CI'],
  outputContract = { kind: 'none' },
}) {
  return {
    nodeId,
    dependencies,
    argv,
    cwd,
    runner,
    inputSelectors,
    toolchainKeys,
    allowlistedEnv,
    outputContract,
  };
}

function descriptor({ fallbackNodeId = 'full', dynamic = true } = {}) {
  return {
    schemaVersion: '1.0.0',
    descriptorVersion: 'reference-1',
    repositoryId: 'fixture-repository',
    fallbackNodeId,
    dynamicFallbackSelectors: dynamic ? [{ kind: 'prefix', pattern: 'scripts/' }] : [],
    tasks: [
      task({
        nodeId: 'prepare',
        inputSelectors: [
          { kind: 'exact', pattern: 'package-lock.json' },
          { kind: 'exact', pattern: 'config.json' },
        ],
        argv: ['node', 'prepare.js'],
        outputContract: { kind: 'files', paths: ['generated.json'] },
      }),
      task({
        nodeId: 'unit',
        dependencies: ['prepare'],
        inputSelectors: [
          { kind: 'prefix', pattern: 'src/' },
          { kind: 'exact', pattern: 'tests/helper.js' },
        ],
      }),
      task({
        nodeId: 'contract',
        dependencies: ['unit'],
        inputSelectors: [{ kind: 'glob', pattern: 'tests/**/*.test.js' }],
        argv: ['node', '--test', 'tests'],
      }),
      task({
        nodeId: 'full',
        dependencies: ['contract'],
        inputSelectors: [{ kind: 'glob', pattern: '**' }],
        argv: ['node', '--test'],
        toolchainKeys: ['git', 'node'],
        allowlistedEnv: ['CI'],
        outputContract: { kind: 'report', mediaType: 'application/json' },
      }),
    ],
    profiles: [
      {
        profileId: 'affected',
        mode: 'affected',
        requiredNodes: ['prepare'],
        eligibleNodes: ['prepare', 'unit', 'contract', 'full'],
      },
      {
        profileId: 'rc',
        mode: 'fixed',
        requiredNodes: ['prepare', 'unit', 'contract', 'full'],
      },
      { profileId: 'contract-only', mode: 'fixed', requiredNodes: ['contract'] },
    ],
  };
}

function build({
  repo,
  candidate,
  base,
  policy = descriptor(),
  profileId = 'affected',
  environment,
  ...rest
}) {
  return buildExpectedTaskPolicy({
    repo,
    descriptor: policy,
    profileId,
    candidateCommit: candidate.commit,
    expectedTree: candidate.tree,
    baseCommit: base?.commit,
    toolchain: TOOLCHAIN,
    environment:
      environment ?? (rest.policySchemaVersion === '1.1.0' ? PORTABLE_ENVIRONMENT : ENVIRONMENT),
    ...rest,
  });
}

function keyMap(built) {
  return new Map(built.taskPolicy.requiredNodes.map((node) => [node.nodeId, node.taskKey]));
}

function expectCode(code, action) {
  assert.throws(action, (error) => error?.code === code);
}

describe('selector semantics', () => {
  it('distinguishes exact, prefix, and glob including zero-directory globstar', () => {
    const cases = [
      [{ kind: 'exact', pattern: 'config.json' }, 'config.json', true],
      [{ kind: 'exact', pattern: 'config.json' }, 'config.json.bak', false],
      [{ kind: 'prefix', pattern: 'src/' }, 'src/a.js', true],
      [{ kind: 'prefix', pattern: 'src/' }, 'srcology/a.js', false],
      [{ kind: 'glob', pattern: 'tests/**/*.test.js' }, 'tests/root.test.js', true],
      [{ kind: 'glob', pattern: 'tests/**/*.test.js' }, 'tests/unit/a.test.js', true],
      [{ kind: 'glob', pattern: 'tests/**/*.test.js' }, 'tests/unit/a.spec.js', false],
    ];
    for (const [selector, path, expected] of cases) {
      assert.equal(selectorMatches(selector, path), expected, `${selector.kind}:${path}`);
    }
  });
});

describe('task-policy schema compatibility', () => {
  it('emits output contracts only in schema 1.1 policies', () => {
    const state = repository();
    const legacy = build({
      repo: state.repo,
      base: state.base,
      candidate: state.base,
      profileId: 'rc',
    });
    const portable = build({
      repo: state.repo,
      base: state.base,
      candidate: state.base,
      profileId: 'rc',
      policySchemaVersion: '1.1.0',
    });
    assert.equal(legacy.taskPolicy.schemaVersion, '1.0.0');
    assert.equal(Object.hasOwn(legacy.taskPolicy.requiredNodes[0], 'outputContract'), false);
    assert.equal(portable.taskPolicy.schemaVersion, '1.1.0');
    assert.deepEqual(portable.taskPolicy.requiredNodes[0].outputContract, {
      kind: 'files',
      paths: ['generated.json'],
    });
  });
});

describe('candidate snapshot and affected derivation', () => {
  it('selects source, helper, config, lockfile, and test changes with dependency closure', () => {
    const mutations = [
      ['src/a.js', 'export const value = 2;\n', ['prepare', 'unit', 'contract']],
      ['tests/helper.js', 'export const fixture = 2;\n', ['prepare', 'unit', 'contract']],
      ['tests/root.test.js', 'export const testCase = 2;\n', ['prepare', 'unit', 'contract']],
      ['config.json', '{"strict":false}\n', ['prepare', 'unit', 'contract']],
      ['package-lock.json', '{"lockfileVersion":3,"changed":true}\n', ['prepare', 'unit', 'contract']],
    ];
    for (const [path, content, expectedNodes] of mutations) {
      const state = repository();
      put(state.repo, path, content);
      const candidate = commit(state.repo, `change ${path}`);
      const built = build({ repo: state.repo, base: state.base, candidate });
      assert.deepEqual(
        built.taskPolicy.requiredNodes.map((node) => node.nodeId),
        expectedNodes,
        path,
      );
      assert.deepEqual(built.changedPaths, [path]);
    }
  });

  it('classifies both sides of renames and deleted paths against candidate inputs', () => {
    const renamed = repository();
    renameSync(join(renamed.repo, 'src/a.js'), join(renamed.repo, 'src/renamed.js'));
    const renamedCandidate = commit(renamed.repo, 'rename source');
    const renameBuilt = build({ repo: renamed.repo, base: renamed.base, candidate: renamedCandidate });
    assert.deepEqual(renameBuilt.changedPaths, ['src/a.js', 'src/renamed.js']);
    assert.deepEqual(
      renameBuilt.taskPolicy.requiredNodes.map((node) => node.nodeId),
      ['prepare', 'unit', 'contract'],
    );

    const deleted = repository();
    unlinkSync(join(deleted.repo, 'tests/helper.js'));
    const deletedCandidate = commit(deleted.repo, 'delete helper');
    const deleteBuilt = build({ repo: deleted.repo, base: deleted.base, candidate: deletedCandidate });
    assert.deepEqual(deleteBuilt.changedPaths, ['tests/helper.js']);
    assert.deepEqual(
      deleteBuilt.taskPolicy.requiredNodes.map((node) => node.nodeId),
      ['prepare', 'unit', 'contract'],
    );
  });

  it('falls back for unknown and declared dynamic paths, but rejects unknown without fallback', () => {
    for (const path of ['notes.txt', 'scripts/dynamic-loader.js']) {
      const state = repository();
      put(state.repo, path, 'changed\n');
      const candidate = commit(state.repo, `add ${path}`);
      const built = build({ repo: state.repo, base: state.base, candidate });
      assert.deepEqual(
        built.taskPolicy.requiredNodes.map((node) => node.nodeId),
        ['prepare', 'unit', 'contract', 'full'],
      );
    }

    const state = repository();
    put(state.repo, 'unknown.bin', 'unknown\n');
    const candidate = commit(state.repo, 'unknown without fallback');
    const noFallback = descriptor({ fallbackNodeId: null, dynamic: false });
    noFallback.tasks = noFallback.tasks.filter((entry) => entry.nodeId !== 'full');
    noFallback.profiles = noFallback.profiles.map((profile) => ({
      ...profile,
      requiredNodes: profile.requiredNodes.filter((nodeId) => nodeId !== 'full'),
      ...(profile.eligibleNodes !== undefined && {
        eligibleNodes: profile.eligibleNodes.filter((nodeId) => nodeId !== 'full'),
      }),
    }));
    expectCode('UNKNOWN_PATH', () =>
      build({
        repo: state.repo,
        base: state.base,
        candidate,
        policy: noFallback,
      }),
    );
  });

  it('adds dependencies omitted by a fixed profile without adding downstream nodes', () => {
    const state = repository();
    const built = build({
      repo: state.repo,
      candidate: state.base,
      profileId: 'contract-only',
      toolchain: { node: TOOLCHAIN.node },
    });
    assert.deepEqual(
      built.taskPolicy.requiredNodes.map((node) => node.nodeId),
      ['prepare', 'unit', 'contract'],
    );
  });
});

describe('reusable task identity', () => {
  it('excludes commit identity and mtimes for an identical tree', () => {
    const state = repository();
    const first = build({ repo: state.repo, candidate: state.base, profileId: 'rc' });
    const identicalCommit = commit(state.repo, 'empty successor');
    assert.equal(identicalCommit.tree, state.base.tree);
    const second = build({ repo: state.repo, candidate: identicalCommit, profileId: 'rc' });
    assert.deepEqual(second.taskPolicy, first.taskPolicy);
    assert.equal(second.taskPolicyDigest, first.taskPolicyDigest);
  });

  it('propagates source and lockfile invalidation through dependency task keys', () => {
    for (const [path, content, expectedChanged] of [
      ['src/a.js', 'export const value = 9;\n', ['unit', 'contract', 'full']],
      [
        'package-lock.json',
        '{"lockfileVersion":3,"packages":{"changed":true}}\n',
        ['prepare', 'unit', 'contract', 'full'],
      ],
    ]) {
      const state = repository();
      const before = keyMap(build({ repo: state.repo, candidate: state.base, profileId: 'rc' }));
      put(state.repo, path, content);
      const candidate = commit(state.repo, `invalidate ${path}`);
      const after = keyMap(build({ repo: state.repo, candidate, profileId: 'rc' }));
      const changed = [...after.keys()].filter((nodeId) => after.get(nodeId) !== before.get(nodeId));
      assert.deepEqual(changed, expectedChanged, path);
    }
  });

  it('binds argv, cwd, runner, toolchain, allowlisted environment, and output contract', () => {
    const state = repository();
    const baseline = keyMap(build({ repo: state.repo, candidate: state.base, profileId: 'rc' }));
    const variants = [
      { mutate: (value) => value.tasks[1].argv.push('--test-name-pattern=current') },
      { mutate: (value) => (value.tasks[1].cwd = 'src') },
      { mutate: (value) => (value.tasks[1].runner = 'node-test-v2') },
      { mutate: (value) => (value.tasks[1].outputContract = { kind: 'report' }) },
    ];
    for (const variant of variants) {
      const policy = descriptor();
      variant.mutate(policy);
      const changed = keyMap(
        build({ repo: state.repo, candidate: state.base, profileId: 'rc', policy }),
      );
      assert.notEqual(changed.get('unit'), baseline.get('unit'));
      assert.notEqual(changed.get('contract'), baseline.get('contract'));
    }

    const changedToolchain = keyMap(
      build({
        repo: state.repo,
        candidate: state.base,
        profileId: 'rc',
        toolchain: { ...TOOLCHAIN, node: '24.6.0' },
      }),
    );
    assert.notEqual(changedToolchain.get('unit'), baseline.get('unit'));

    const changedEnvironment = keyMap(
      build({
        repo: state.repo,
        candidate: state.base,
        profileId: 'rc',
        environment: { ...ENVIRONMENT, CI: 'true' },
      }),
    );
    assert.notEqual(changedEnvironment.get('unit'), baseline.get('unit'));

    const ignoredEnvironment = keyMap(
      build({
        repo: state.repo,
        candidate: state.base,
        profileId: 'rc',
        environment: { ...ENVIRONMENT, IGNORED_SECRET: 'different' },
      }),
    );
    assert.equal(ignoredEnvironment.get('unit'), baseline.get('unit'));

    const absentEnvironment = keyMap(
      build({
        repo: state.repo,
        candidate: state.base,
        profileId: 'rc',
        environment: { ...ENVIRONMENT, CI: null },
      }),
    );
    const emptyEnvironment = keyMap(
      build({
        repo: state.repo,
        candidate: state.base,
        profileId: 'rc',
        environment: { ...ENVIRONMENT, CI: '' },
      }),
    );
    assert.notEqual(absentEnvironment.get('unit'), emptyEnvironment.get('unit'));
    assert.notEqual(absentEnvironment.get('unit'), baseline.get('unit'));
  });

  it('binds a protected resolved executable identity when supplied', () => {
    const state = repository();
    const candidate = commit(state.repo, 'candidate');
    const first = build({
      repo: state.repo,
      candidate,
      base: state.base.commit,
      profileId: 'rc',
      toolchain: {
        ...TOOLCHAIN,
        'executable:node': JSON.stringify({ path: '/opt/node/bin/node', sha256: 'a'.repeat(64) }),
      },
    });
    const changed = build({
      repo: state.repo,
      candidate,
      base: state.base.commit,
      profileId: 'rc',
      toolchain: {
        ...TOOLCHAIN,
        'executable:node': JSON.stringify({ path: '/opt/node/bin/node', sha256: 'b'.repeat(64) }),
      },
    });
    assert.notEqual(first.taskPolicyDigest, changed.taskPolicyDigest);
  });

  it('rejects malformed protected executable identities', () => {
    const state = repository();
    const candidate = commit(state.repo, 'candidate');
    assert.throws(
      () =>
        build({
          repo: state.repo,
          candidate,
          base: state.base.commit,
          profileId: 'rc',
          toolchain: { ...TOOLCHAIN, 'executable:node': '{"path":"/opt/node"}' },
        }),
      /executable:node/,
    );
  });
});

describe('fail-closed descriptor and Git boundaries', () => {
  it('rejects cycles, unknown dependencies, and profile node omissions', () => {
    const state = repository();

    const cycle = descriptor();
    cycle.tasks[0].dependencies = ['contract'];
    expectCode('TASK_CYCLE', () =>
      build({ repo: state.repo, candidate: state.base, profileId: 'rc', policy: cycle }),
    );

    const unknownDependency = descriptor();
    unknownDependency.tasks[1].dependencies = ['missing'];
    expectCode('UNKNOWN_DEPENDENCY', () =>
      build({
        repo: state.repo,
        candidate: state.base,
        profileId: 'rc',
        policy: unknownDependency,
      }),
    );

    const omitted = descriptor();
    omitted.profiles[1].requiredNodes.push('missing');
    expectCode('PROFILE_NODE_UNKNOWN', () =>
      build({ repo: state.repo, candidate: state.base, profileId: 'rc', policy: omitted }),
    );
  });

  it('rejects a wrong expected tree', () => {
    const state = repository();
    expectCode('TREE_MISMATCH', () =>
      buildExpectedTaskPolicy({
        repo: state.repo,
        descriptor: descriptor(),
        profileId: 'rc',
        candidateCommit: state.base.commit,
        expectedTree: 'f'.repeat(40),
        toolchain: TOOLCHAIN,
        environment: ENVIRONMENT,
      }),
    );
  });

  it('accepts null only for environment values and still requires every allowlisted key', () => {
    const state = repository();
    assert.doesNotThrow(() =>
      build({
        repo: state.repo,
        candidate: state.base,
        profileId: 'rc',
        environment: { CI: null },
      }),
    );
    expectCode('ENVIRONMENT_MISSING', () =>
      build({
        repo: state.repo,
        candidate: state.base,
        profileId: 'rc',
        environment: {},
      }),
    );
    expectCode('SCHEMA_INVALID', () =>
      build({
        repo: state.repo,
        candidate: state.base,
        profileId: 'rc',
        toolchain: { ...TOOLCHAIN, node: null },
      }),
    );
    expectCode('SCHEMA_INVALID', () =>
      build({
        repo: state.repo,
        candidate: state.base,
        profileId: 'rc',
        environment: { CI: false },
      }),
    );
    expectCode('ENVIRONMENT_IDENTITY_INVALID', () =>
      build({
        repo: state.repo,
        candidate: state.base,
        profileId: 'rc',
        policySchemaVersion: '1.1.0',
        environment: ENVIRONMENT,
      }),
    );
  });
});

describe('mutation output discovery', () => {
  function mutationDescriptor() {
    return {
      schemaVersion: '1.0.0',
      descriptorVersion: 'mutation-discovery-1',
      repositoryId: 'fixture-repository',
      fallbackNodeId: null,
      dynamicFallbackSelectors: [],
      tasks: [
        task({
          nodeId: 'test:mutation',
          inputSelectors: [
            { kind: 'glob', pattern: 'packages/*/package.json' },
            { kind: 'glob', pattern: 'packages/*/stryker.*' },
            { kind: 'exact', pattern: 'tools/repo-config/test-policy.json' },
          ],
          outputContract: {
            kind: 'mutation-report-set-discovery-v1',
            workspaceRoots: ['packages'],
            testPolicyPath: 'tools/repo-config/test-policy.json',
            artifactRoot: '.devai/local/evidence/mutation',
            summaryPath: '.devai/local/evidence/mutation/summary.json',
          },
        }),
      ],
      profiles: [{ profileId: 'rc', mode: 'fixed', requiredNodes: ['test:mutation'] }],
    };
  }

  it('derives the exact package roster and thresholds from committed candidate inputs', () => {
    const state = repository();
    put(
      state.repo,
      'tools/repo-config/test-policy.json',
      JSON.stringify({
        policies: { mutation: { tier3: { break: 90, high: 100, low: 90 } } },
        defaults: { mutation: 'tier3' },
        perPackage: {},
      }),
    );
    put(
      state.repo,
      'packages/core/package.json',
      JSON.stringify({ name: '@stynx/core', scripts: { stryker: 'stryker run' } }),
    );
    put(state.repo, 'packages/core/stryker.conf.mjs', 'export default { threshold: 70 }\n');
    put(
      state.repo,
      'packages/plain/package.json',
      JSON.stringify({ name: '@stynx/plain', scripts: { test: 'node --test' } }),
    );
    const first = commit(state.repo, 'one mutation package');
    const firstPolicy = build({
      repo: state.repo,
      candidate: first,
      profileId: 'rc',
      policy: mutationDescriptor(),
      policySchemaVersion: '1.1.0',
    });
    const firstNode = firstPolicy.taskPolicy.requiredNodes[0];
    assert.equal(firstNode.outputContract.expectedPackageCount, 1);
    assert.deepEqual(firstNode.outputContract.packages, [
      {
        packageName: '@stynx/core',
        workspace: 'packages/core',
        resultPath: '.devai/local/evidence/mutation/packages-core.result.json',
        reportPath: '.devai/local/evidence/mutation/packages-core.stryker.json',
        thresholds: { break: 70, high: 70, low: 60 },
      },
    ]);

    put(
      state.repo,
      'packages/extra/package.json',
      JSON.stringify({ name: '@stynx/extra', scripts: { stryker: 'stryker run' } }),
    );
    put(state.repo, 'packages/extra/stryker.config.mjs', 'export default {}\n');
    const second = commit(state.repo, 'two mutation packages');
    const secondPolicy = build({
      repo: state.repo,
      candidate: second,
      profileId: 'rc',
      policy: mutationDescriptor(),
      policySchemaVersion: '1.1.0',
    });
    assert.equal(secondPolicy.taskPolicy.requiredNodes[0].outputContract.expectedPackageCount, 2);
    assert.notEqual(firstNode.taskKey, secondPolicy.taskPolicy.requiredNodes[0].taskKey);
  });

  it('fails closed when a Stryker command and configuration are not paired', () => {
    const state = repository();
    put(
      state.repo,
      'tools/repo-config/test-policy.json',
      JSON.stringify({
        policies: { mutation: { default: 90 } },
        defaults: { mutation: 'default' },
      }),
    );
    put(
      state.repo,
      'packages/broken/package.json',
      JSON.stringify({ name: '@stynx/broken', scripts: { stryker: 'stryker run' } }),
    );
    const candidate = commit(state.repo, 'broken mutation package');
    expectCode('MUTATION_ROSTER_MISMATCH', () =>
      build({
        repo: state.repo,
        candidate,
        profileId: 'rc',
        policy: mutationDescriptor(),
        policySchemaVersion: '1.1.0',
      }),
    );
  });
});

describe('policy-builder CLI', () => {
  it('writes the exact verifier policy and reports its digest', () => {
    const state = repository();
    put(state.repo, 'src/a.js', 'export const value = 4;\n');
    const candidate = commit(state.repo, 'CLI candidate');
    const inputs = {
      descriptor: join(state.repo, '.descriptor.json'),
      toolchain: join(state.repo, '.toolchain.json'),
      environment: join(state.repo, '.environment.json'),
      output: join(state.repo, '.expected-policy.json'),
    };
    writeFileSync(inputs.descriptor, JSON.stringify(descriptor()));
    writeFileSync(inputs.toolchain, JSON.stringify(TOOLCHAIN));
    writeFileSync(inputs.environment, JSON.stringify(ENVIRONMENT));
    const result = spawnSync(
      process.execPath,
      [
        CLI,
        '--repo',
        state.repo,
        '--descriptor',
        inputs.descriptor,
        '--profile',
        'affected',
        '--commit',
        candidate.commit,
        '--tree',
        candidate.tree,
        '--base',
        state.base.commit,
        '--toolchain',
        inputs.toolchain,
        '--environment',
        inputs.environment,
        '--output',
        inputs.output,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    const report = JSON.parse(result.stdout);
    const policy = JSON.parse(readFileSync(inputs.output, 'utf8'));
    assert.equal(report.taskPolicyDigest, sha256Hex(policy));
    assert.deepEqual(
      policy.requiredNodes.map((node) => node.nodeId),
      ['prepare', 'unit', 'contract'],
    );
  });
});

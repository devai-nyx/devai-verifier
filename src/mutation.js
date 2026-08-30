import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  VerificationError,
  assertExactKeys,
  assertObject,
  assertString,
  assertUniqueStrings,
  canonicalize,
  sha256Hex,
} from "./canonical.js";

const PACKAGE_NAME = /^@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*$/u;
const PORTABLE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\\)(?!.*\0)[^/]+(?:\/[^/]+)*$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const GIT_OBJECT = /^(?!0+$)(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const MUTANT_STATUSES = [
  "CompileError",
  "Ignored",
  "Killed",
  "NoCoverage",
  "Pending",
  "RuntimeError",
  "Survived",
  "Timeout",
];
const STRYKER_CONFIG = /^stryker\.(?:conf|config)\.(?:cjs|js|json|mjs|ts)$/u;

function git(repo, args) {
  const result = spawnSync("git", ["-C", repo, ...args], { encoding: "utf8" });
  if (result.status !== 0) {
    throw new VerificationError(
      "GIT_ERROR",
      result.stderr.trim() || `git ${args[0]} failed`,
    );
  }
  return result.stdout;
}

function committedJson(repo, commit, path, label) {
  try {
    return JSON.parse(git(repo, ["show", `${commit}:${path}`]));
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    throw new VerificationError(
      "MUTATION_ROSTER_MISMATCH",
      `${label} is not valid JSON`,
    );
  }
}

function mutationThresholds(policy, packageName, literalOverride) {
  if (literalOverride !== undefined) {
    return {
      break: literalOverride,
      high: literalOverride,
      low: Math.max(60, literalOverride - 10),
    };
  }
  const override = policy.perPackage?.[packageName]?.mutation;
  if (typeof override === "number") {
    return {
      break: override,
      high: override,
      low: Math.max(60, override - 10),
    };
  }
  const policyName = override ?? policy.defaults?.mutation ?? "default";
  const selected = policy.policies?.mutation?.[policyName];
  if (typeof selected === "number") {
    return {
      break: selected,
      high: selected,
      low: Math.max(60, selected - 10),
    };
  }
  if (
    selected !== null &&
    typeof selected === "object" &&
    typeof selected.break === "number"
  ) {
    return {
      break: selected.break,
      high: typeof selected.high === "number" ? selected.high : selected.break,
      low:
        typeof selected.low === "number"
          ? selected.low
          : Math.max(60, selected.break - 10),
    };
  }
  throw new VerificationError(
    "MUTATION_THRESHOLD_MISMATCH",
    `unknown mutation policy ${String(policyName)} for ${packageName}`,
  );
}

export function resolveMutationDiscoveryContract(repo, commit, contract) {
  if (contract.kind !== "mutation-report-set-discovery-v1") return contract;
  assertExactKeys(
    contract,
    ["artifactRoot", "kind", "summaryPath", "testPolicyPath", "workspaceRoots"],
    "mutation discovery contract",
  );
  assertString(
    contract.artifactRoot,
    "mutation discovery artifactRoot",
    PORTABLE_PATH,
  );
  assertString(
    contract.summaryPath,
    "mutation discovery summaryPath",
    PORTABLE_PATH,
  );
  assertString(
    contract.testPolicyPath,
    "mutation discovery testPolicyPath",
    PORTABLE_PATH,
  );
  assertUniqueStrings(
    contract.workspaceRoots,
    "mutation discovery workspaceRoots",
  );
  for (const root of contract.workspaceRoots) {
    assertString(root, "mutation discovery workspace root", PORTABLE_PATH);
  }
  if (contract.summaryPath !== `${contract.artifactRoot}/summary.json`) {
    throw new VerificationError(
      "SCHEMA_INVALID",
      "mutation discovery summaryPath must be artifactRoot/summary.json",
    );
  }

  const paths = git(repo, ["ls-tree", "-r", "--name-only", commit])
    .trim()
    .split("\n")
    .filter(Boolean);
  const testPolicy = committedJson(
    repo,
    commit,
    contract.testPolicyPath,
    "mutation test policy",
  );
  const packages = [];
  for (const root of contract.workspaceRoots) {
    const prefix = `${root}/`;
    const manifests = paths.filter((path) => {
      if (!path.startsWith(prefix) || !path.endsWith("/package.json"))
        return false;
      return path.slice(prefix.length).split("/").length === 2;
    });
    for (const manifestPath of manifests) {
      const workspace = manifestPath.slice(0, -"/package.json".length);
      const manifest = committedJson(
        repo,
        commit,
        manifestPath,
        `manifest ${manifestPath}`,
      );
      const strykerScript = manifest.scripts?.stryker;
      const configs = paths.filter((path) => {
        if (!path.startsWith(`${workspace}/`)) return false;
        const relative = path.slice(workspace.length + 1);
        return !relative.includes("/") && STRYKER_CONFIG.test(relative);
      });
      if (
        configs.length > 1 ||
        (configs.length === 1) !== (typeof strykerScript === "string")
      ) {
        throw new VerificationError(
          "MUTATION_ROSTER_MISMATCH",
          `${workspace} must declare exactly one Stryker command and configuration together`,
        );
      }
      if (configs.length === 0) continue;
      assertString(
        manifest.name,
        `manifest ${manifestPath} package name`,
        PACKAGE_NAME,
      );
      const configSource = git(repo, ["show", `${commit}:${configs[0]}`]);
      const literalMatches = [
        ...configSource.matchAll(/\bthreshold\s*:\s*(\d+(?:\.\d+)?)/gu),
      ];
      if (literalMatches.length > 1) {
        throw new VerificationError(
          "MUTATION_THRESHOLD_MISMATCH",
          `${workspace} declares multiple literal threshold overrides`,
        );
      }
      const literalThreshold =
        literalMatches[0]?.[1] === undefined
          ? undefined
          : Number(literalMatches[0][1]);
      const stem = workspace.replaceAll("/", "-");
      packages.push({
        packageName: manifest.name,
        workspace,
        resultPath: `${contract.artifactRoot}/${stem}.result.json`,
        reportPath: `${contract.artifactRoot}/${stem}.stryker.json`,
        thresholds: mutationThresholds(
          testPolicy,
          manifest.name,
          literalThreshold,
        ),
      });
    }
  }
  packages.sort((left, right) =>
    left.packageName.localeCompare(right.packageName),
  );
  if (
    packages.length === 0 ||
    new Set(packages.map((entry) => entry.packageName)).size !== packages.length
  ) {
    throw new VerificationError(
      "MUTATION_ROSTER_MISMATCH",
      "mutation package roster is empty or duplicated",
    );
  }
  const artifactPaths = [
    contract.summaryPath,
    ...packages.flatMap((entry) => [entry.resultPath, entry.reportPath]),
  ];
  return {
    kind: "mutation-report-set-v1",
    expectedPackageCount: packages.length,
    summaryPath: contract.summaryPath,
    packages,
    paths: artifactPaths,
  };
}

function assertNonnegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new VerificationError(
      "MUTATION_REPORT_INVALID",
      `${label} must be a nonnegative integer`,
    );
  }
}

function assertFiniteNumber(value, label) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new VerificationError(
      "MUTATION_REPORT_INVALID",
      `${label} must be a finite number`,
    );
  }
}

function validateThresholds(value, label) {
  assertExactKeys(value, ["break", "high", "low"], label);
  for (const key of ["break", "high", "low"])
    assertFiniteNumber(value[key], `${label}.${key}`);
  if (
    value.break < 0 ||
    value.break > 100 ||
    value.high < 0 ||
    value.high > 100 ||
    value.low < 0 ||
    value.low > 100 ||
    value.low > value.high
  ) {
    throw new VerificationError(
      "MUTATION_REPORT_INVALID",
      `${label} ordering is invalid`,
    );
  }
}

function validateStatusTotals(value, label) {
  assertExactKeys(value, MUTANT_STATUSES, label);
  for (const status of MUTANT_STATUSES)
    assertNonnegativeInteger(value[status], `${label}.${status}`);
}

function validateSuccessfulProcess(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new VerificationError(
      "MUTATION_REPORT_INVALID",
      `${label} must be an object`,
    );
  }
  assertExactKeys(value, ["errorAbsent", "signal", "status"], label);
  if (
    value.errorAbsent !== true ||
    value.signal !== null ||
    value.status !== 0
  ) {
    throw new VerificationError(
      "MUTATION_REPORT_INVALID",
      `${label} must record an exact successful process`,
    );
  }
}

function readCanonicalJson(path, label) {
  let text;
  let value;
  try {
    text = readFileSync(path, "utf8");
    value = JSON.parse(text);
  } catch (error) {
    throw new VerificationError(
      "MUTATION_REPORT_INVALID",
      `${label} is unreadable: ${error.message}`,
    );
  }
  if (text !== canonicalize(value) && text !== `${canonicalize(value)}\n`) {
    throw new VerificationError(
      "NON_CANONICAL_JSON",
      `${label} is not canonical JSON`,
    );
  }
  return {
    value,
    bytes: Buffer.from(text.endsWith("\n") ? text.slice(0, -1) : text, "utf8"),
  };
}

function reportMetrics(report, label) {
  assertObject(report, label);
  assertObject(report.files, `${label}.files`);
  assertObject(report.testFiles, `${label}.testFiles`);
  assertObject(report.config, `${label}.config`);
  if (Object.keys(report.config).length !== 0) {
    throw new VerificationError(
      "MUTATION_REPORT_INVALID",
      `${label}.config must be normalized to {}`,
    );
  }
  assertObject(report.thresholds, `${label}.thresholds`);
  validateThresholds(report.thresholds, `${label}.thresholds`);
  if (report.projectRoot !== ".") {
    throw new VerificationError(
      "MUTATION_REPORT_INVALID",
      `${label}.projectRoot must be normalized to .`,
    );
  }
  for (const testFile of Object.keys(report.testFiles)) {
    assertString(testFile, `${label} test file`, PORTABLE_PATH);
  }
  const totals = Object.fromEntries(
    MUTANT_STATUSES.map((status) => [status, 0]),
  );
  for (const [file, fileResult] of Object.entries(report.files)) {
    assertString(file, `${label} file`, PORTABLE_PATH);
    assertObject(fileResult, `${label}.files.${file}`);
    if (!Array.isArray(fileResult.mutants)) {
      throw new VerificationError(
        "MUTATION_REPORT_INVALID",
        `${label}.files.${file}.mutants must be an array`,
      );
    }
    for (const mutant of fileResult.mutants) {
      assertObject(mutant, `${label} mutant`);
      if (!MUTANT_STATUSES.includes(mutant.status)) {
        throw new VerificationError(
          "MUTATION_REPORT_INVALID",
          `${label} has unknown mutant status`,
        );
      }
      totals[mutant.status] += 1;
    }
  }
  const detected = totals.Killed + totals.Timeout;
  const scored = detected + totals.Survived + totals.NoCoverage;
  const score = scored === 0 ? 100 : (detected / scored) * 100;
  return {
    totals,
    score,
    targetCensus: {
      targetFileCount: Object.keys(report.files).length,
      totalMutants: MUTANT_STATUSES.reduce(
        (total, status) => total + totals[status],
        0,
      ),
    },
  };
}

function validatePackageContract(entry, label) {
  assertExactKeys(
    entry,
    ["packageName", "reportPath", "resultPath", "thresholds", "workspace"],
    label,
  );
  assertString(entry.packageName, `${label}.packageName`, PACKAGE_NAME);
  assertString(entry.workspace, `${label}.workspace`, PORTABLE_PATH);
  assertString(entry.reportPath, `${label}.reportPath`, PORTABLE_PATH);
  assertString(entry.resultPath, `${label}.resultPath`, PORTABLE_PATH);
  validateThresholds(entry.thresholds, `${label}.thresholds`);
}

export function validateMutationContract(contract, label) {
  assertExactKeys(
    contract,
    ["expectedPackageCount", "kind", "packages", "paths", "summaryPath"],
    label,
  );
  if (contract.kind !== "mutation-report-set-v1") {
    throw new VerificationError(
      "SCHEMA_INVALID",
      `${label}.kind is unsupported`,
    );
  }
  assertNonnegativeInteger(
    contract.expectedPackageCount,
    `${label}.expectedPackageCount`,
  );
  if (
    contract.expectedPackageCount === 0 ||
    !Array.isArray(contract.packages)
  ) {
    throw new VerificationError(
      "SCHEMA_INVALID",
      `${label}.packages must be nonempty`,
    );
  }
  assertString(contract.summaryPath, `${label}.summaryPath`, PORTABLE_PATH);
  const packageNames = [];
  const workspaces = [];
  const declaredPaths = [contract.summaryPath];
  for (const [index, entry] of contract.packages.entries()) {
    validatePackageContract(entry, `${label}.packages[${index}]`);
    packageNames.push(entry.packageName);
    workspaces.push(entry.workspace);
    declaredPaths.push(entry.resultPath, entry.reportPath);
  }
  if (contract.packages.length !== contract.expectedPackageCount) {
    throw new VerificationError(
      "SCHEMA_INVALID",
      `${label} package count differs`,
    );
  }
  assertUniqueStrings(packageNames, `${label} package names`);
  assertUniqueStrings(workspaces, `${label} workspaces`);
  assertUniqueStrings(declaredPaths, `${label} artifact paths`);
  assertUniqueStrings(contract.paths, `${label}.paths`);
  const expected = [...declaredPaths].sort();
  const actual = [...contract.paths].sort();
  if (
    actual.length !== expected.length ||
    actual.some((path, index) => path !== expected[index])
  ) {
    throw new VerificationError(
      "SCHEMA_INVALID",
      `${label}.paths differs from the mutation artifact roster`,
    );
  }
}

function validatePackageResult(
  result,
  contract,
  report,
  reportDigest,
  metrics,
  label,
) {
  assertObject(result, label);
  const keys = [
    "durationMs",
    "kind",
    "packageName",
    "passed",
    "reportDigest",
    "schemaVersion",
    "score",
    "statusTotals",
    "thresholds",
    "toolVersions",
    "workspace",
  ];
  if (Object.hasOwn(result, "process")) keys.push("process");
  assertExactKeys(result, keys, label);
  if (
    result.schemaVersion !== "1.0.0" ||
    result.kind !== "mutation-package-result-v1"
  ) {
    throw new VerificationError(
      "MUTATION_REPORT_INVALID",
      `${label} schema or kind is unsupported`,
    );
  }
  if (
    result.packageName !== contract.packageName ||
    result.workspace !== contract.workspace
  ) {
    throw new VerificationError(
      "MUTATION_ROSTER_MISMATCH",
      `${label} package identity differs`,
    );
  }
  validateThresholds(result.thresholds, `${label}.thresholds`);
  if (
    canonicalize(result.thresholds) !== canonicalize(contract.thresholds) ||
    canonicalize(report.thresholds) !== canonicalize(contract.thresholds)
  ) {
    throw new VerificationError(
      "MUTATION_THRESHOLD_MISMATCH",
      `${label} thresholds differ from policy`,
    );
  }
  assertFiniteNumber(result.score, `${label}.score`);
  validateStatusTotals(result.statusTotals, `${label}.statusTotals`);
  assertNonnegativeInteger(result.durationMs, `${label}.durationMs`);
  assertString(result.reportDigest, `${label}.reportDigest`, SHA256);
  assertObject(result.toolVersions, `${label}.toolVersions`);
  if (Object.keys(result.toolVersions).length === 0) {
    throw new VerificationError(
      "MUTATION_REPORT_INVALID",
      `${label}.toolVersions must be nonempty`,
    );
  }
  for (const [tool, version] of Object.entries(result.toolVersions)) {
    assertString(tool, `${label} tool`);
    assertString(version, `${label}.${tool}`);
  }
  if (Object.hasOwn(result, "process")) {
    validateSuccessfulProcess(result.process, `${label}.process`);
  }
  if (result.reportDigest !== reportDigest) {
    throw new VerificationError(
      "ARTIFACT_DIGEST_MISMATCH",
      `${label} report digest differs`,
    );
  }
  if (
    canonicalize(result.statusTotals) !== canonicalize(metrics.totals) ||
    result.score !== metrics.score
  ) {
    throw new VerificationError(
      "MUTATION_METRIC_MISMATCH",
      `${label} metrics do not match the canonical report`,
    );
  }
  const passed = metrics.score >= contract.thresholds.break;
  if (result.passed !== passed || !passed) {
    throw new VerificationError(
      "MUTATION_THRESHOLD_FAILED",
      `${label} does not satisfy the break threshold`,
    );
  }
}

function mutationSummaryMismatch() {
  throw new VerificationError(
    "MUTATION_SUMMARY_MISMATCH",
    "composed mutation summary does not match its strict schema and evidence",
  );
}

function validateComposedSummary(
  summary,
  candidateCommit,
  candidateTree,
  expectedPackageCount,
) {
  try {
    assertExactKeys(
      summary,
      [
        "aggregate",
        "baseline",
        "candidate",
        "complete",
        "kind",
        "packages",
        "passed",
        "schemaVersion",
        "semanticRebindComparison",
      ],
      "composed mutation summary",
    );
    if (
      summary.schemaVersion !== "1.0.0" ||
      summary.kind !== "mutation-composed-report-set-v1" ||
      summary.complete !== true ||
      summary.passed !== true
    ) {
      mutationSummaryMismatch();
    }
    assertString(
      candidateCommit,
      "composed mutation candidate commit",
      GIT_OBJECT,
    );
    assertString(candidateTree, "composed mutation candidate tree", GIT_OBJECT);
    assertExactKeys(
      summary.candidate,
      ["commit", "tree"],
      "composed mutation candidate",
    );
    assertString(
      summary.candidate.commit,
      "composed mutation candidate.commit",
      GIT_OBJECT,
    );
    assertString(
      summary.candidate.tree,
      "composed mutation candidate.tree",
      GIT_OBJECT,
    );

    assertExactKeys(
      summary.baseline,
      ["commit", "summaryBytes", "summarySha256", "tree"],
      "composed mutation baseline",
    );
    assertString(
      summary.baseline.commit,
      "composed mutation baseline.commit",
      GIT_OBJECT,
    );
    assertString(
      summary.baseline.tree,
      "composed mutation baseline.tree",
      GIT_OBJECT,
    );
    assertNonnegativeInteger(
      summary.baseline.summaryBytes,
      "composed mutation baseline.summaryBytes",
    );
    if (summary.baseline.summaryBytes === 0) mutationSummaryMismatch();
    assertString(
      summary.baseline.summarySha256,
      "composed mutation baseline.summarySha256",
      SHA256,
    );

    const semantic = summary.semanticRebindComparison;
    assertExactKeys(
      semantic,
      [
        "allowedScriptTransitions",
        "canonicalContractBytes",
        "canonicalContractSha256",
        "comparison",
        "kind",
        "sourceRootManifest",
        "targetRootManifest",
      ],
      "composed mutation semantic comparison",
    );
    if (semantic.kind !== "root-manifest-unchanged-with-historical-input-v1") {
      mutationSummaryMismatch();
    }
    assertUniqueStrings(
      semantic.allowedScriptTransitions,
      "composed mutation semantic comparison.allowedScriptTransitions",
    );
    if (semantic.allowedScriptTransitions.length !== 0)
      mutationSummaryMismatch();
    assertNonnegativeInteger(
      semantic.canonicalContractBytes,
      "composed mutation semantic comparison.canonicalContractBytes",
    );
    if (semantic.canonicalContractBytes === 0) mutationSummaryMismatch();
    assertString(
      semantic.canonicalContractSha256,
      "composed mutation semantic comparison.canonicalContractSha256",
      SHA256,
    );
    assertExactKeys(
      semantic.comparison,
      [
        "historicalMutationInputTreeEntries",
        "otherMutationInputTreeEntries",
        "rootManifest",
      ],
      "composed mutation semantic comparison.comparison",
    );
    if (
      semantic.comparison.historicalMutationInputTreeEntries !==
        "match-explicit-historical-candidate-mode-type-oid" ||
      semantic.comparison.otherMutationInputTreeEntries !==
        "identical-mode-type-oid" ||
      semantic.comparison.rootManifest !== "source-and-target-identical"
    ) {
      mutationSummaryMismatch();
    }
    for (const [name, manifest] of [
      ["sourceRootManifest", semantic.sourceRootManifest],
      ["targetRootManifest", semantic.targetRootManifest],
    ]) {
      const label = `composed mutation semantic comparison.${name}`;
      assertExactKeys(manifest, ["bytes", "gitBlobOid", "sha256"], label);
      assertNonnegativeInteger(manifest.bytes, `${label}.bytes`);
      if (manifest.bytes === 0) mutationSummaryMismatch();
      assertString(manifest.gitBlobOid, `${label}.gitBlobOid`, GIT_OBJECT);
      assertString(manifest.sha256, `${label}.sha256`, SHA256);
    }
    if (
      canonicalize(semantic.sourceRootManifest) !==
      canonicalize(semantic.targetRootManifest)
    ) {
      mutationSummaryMismatch();
    }

    if (
      !Array.isArray(summary.packages) ||
      summary.packages.length !== expectedPackageCount
    ) {
      mutationSummaryMismatch();
    }
    assertExactKeys(
      summary.aggregate,
      [
        "durationMs",
        "freshDurationMs",
        "freshPackageCount",
        "packageCount",
        "reusedPackageCount",
        "score",
        "statusTotals",
      ],
      "composed mutation aggregate",
    );
  } catch (error) {
    if (
      error instanceof VerificationError &&
      error.code === "MUTATION_SUMMARY_MISMATCH"
    ) {
      throw error;
    }
    mutationSummaryMismatch();
  }
  return {
    baseline: summary.baseline,
    semanticRebindComparison: summary.semanticRebindComparison,
  };
}

function composedInputProjectionDigest(entry, index) {
  try {
    assertObject(entry, `composed mutation packages[${index}]`);
    assertString(
      entry.inputProjectionDigest,
      `composed mutation packages[${index}].inputProjectionDigest`,
      SHA256,
    );
    return entry.inputProjectionDigest;
  } catch {
    mutationSummaryMismatch();
  }
}

export function verifyMutationReportSet(contract, artifactsDir, options = {}) {
  validateMutationContract(contract, "mutation output contract");
  const summaryFile = readCanonicalJson(
    join(artifactsDir, contract.summaryPath),
    "mutation summary",
  );
  const summary = summaryFile.value;
  const composed = summary?.kind === "mutation-composed-report-set-v1";
  const composedMetadata = composed
    ? validateComposedSummary(
        summary,
        options.candidateCommit,
        options.candidateTree,
        contract.expectedPackageCount,
      )
    : undefined;
  const aggregateTotals = Object.fromEntries(
    MUTANT_STATUSES.map((status) => [status, 0]),
  );
  const summaryEntries = [];
  let durationMs = 0;
  let freshDurationMs = 0;
  let freshPackageCount = 0;
  for (const [index, packageContract] of contract.packages.entries()) {
    const reportFile = readCanonicalJson(
      join(artifactsDir, packageContract.reportPath),
      `mutation report ${packageContract.packageName}`,
    );
    const resultFile = readCanonicalJson(
      join(artifactsDir, packageContract.resultPath),
      `mutation result ${packageContract.packageName}`,
    );
    const reportDigest = sha256Hex(reportFile.bytes);
    const resultDigest = sha256Hex(resultFile.bytes);
    const metrics = reportMetrics(
      reportFile.value,
      `mutation report ${packageContract.packageName}`,
    );
    if (composed) {
      try {
        if (
          canonicalize(summary.packages[index].thresholds) !==
          canonicalize(resultFile.value.thresholds)
        ) {
          mutationSummaryMismatch();
        }
      } catch (error) {
        if (
          error instanceof VerificationError &&
          error.code === "MUTATION_SUMMARY_MISMATCH"
        ) {
          throw error;
        }
        mutationSummaryMismatch();
      }
    }
    validatePackageResult(
      resultFile.value,
      packageContract,
      reportFile.value,
      reportDigest,
      metrics,
      `mutation result ${packageContract.packageName}`,
    );
    for (const status of MUTANT_STATUSES)
      aggregateTotals[status] += metrics.totals[status];
    durationMs += resultFile.value.durationMs;
    if (composed) {
      const fresh = Object.hasOwn(resultFile.value, "process");
      if (fresh) {
        freshPackageCount += 1;
        freshDurationMs += resultFile.value.durationMs;
      }
      summaryEntries.push({
        baselineCommit: fresh ? null : composedMetadata.baseline.commit,
        baselineTree: fresh ? null : composedMetadata.baseline.tree,
        durationMs: resultFile.value.durationMs,
        inputProjectionDigest: composedInputProjectionDigest(
          summary.packages[index],
          index,
        ),
        packageName: packageContract.packageName,
        passed: true,
        ...(fresh && { process: resultFile.value.process }),
        provenance: fresh ? "fresh" : "reused",
        reportDigest,
        reportPath: packageContract.reportPath,
        resultDigest,
        resultPath: packageContract.resultPath,
        score: metrics.score,
        statusTotals: metrics.totals,
        targetCensus: metrics.targetCensus,
        thresholds: packageContract.thresholds,
        workspace: packageContract.workspace,
      });
    } else {
      summaryEntries.push({
        packageName: packageContract.packageName,
        workspace: packageContract.workspace,
        resultPath: packageContract.resultPath,
        reportPath: packageContract.reportPath,
        resultDigest,
        reportDigest,
        score: metrics.score,
        passed: true,
      });
    }
  }
  const detected = aggregateTotals.Killed + aggregateTotals.Timeout;
  const scored =
    detected + aggregateTotals.Survived + aggregateTotals.NoCoverage;
  const aggregateScore = scored === 0 ? 100 : (detected / scored) * 100;
  const reusedPackageCount = contract.expectedPackageCount - freshPackageCount;
  if (composed && (freshPackageCount === 0 || reusedPackageCount === 0)) {
    mutationSummaryMismatch();
  }
  const expectedSummary = composed
    ? {
        schemaVersion: "1.0.0",
        kind: "mutation-composed-report-set-v1",
        candidate: {
          commit: options.candidateCommit,
          tree: options.candidateTree,
        },
        baseline: composedMetadata.baseline,
        semanticRebindComparison: composedMetadata.semanticRebindComparison,
        complete: true,
        passed: true,
        packages: summaryEntries,
        aggregate: {
          packageCount: contract.expectedPackageCount,
          freshPackageCount,
          reusedPackageCount,
          durationMs,
          freshDurationMs,
          score: aggregateScore,
          statusTotals: aggregateTotals,
        },
      }
    : {
        schemaVersion: "1.0.0",
        kind: "mutation-report-set-v1",
        complete: true,
        passed: true,
        packages: summaryEntries,
        aggregate: {
          packageCount: contract.expectedPackageCount,
          durationMs,
          score: aggregateScore,
          statusTotals: aggregateTotals,
        },
      };
  if (canonicalize(summary) !== canonicalize(expectedSummary)) {
    throw new VerificationError(
      "MUTATION_SUMMARY_MISMATCH",
      "mutation summary does not match reports",
    );
  }
  return {
    packageCount: contract.expectedPackageCount,
    score: aggregateScore,
    statusTotals: aggregateTotals,
  };
}

export { MUTANT_STATUSES };

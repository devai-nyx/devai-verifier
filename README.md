# DEVAI evidence verifier reference

This standalone repository is the candidate-independent reference verifier for a
DEVAI RC evidence receipt. It uses Node.js built-ins only and contains no
production private key.

The verifier accepts a canonical, Ed25519-signed candidate receipt and checks:

- trusted and non-revoked signer identity;
- exact repository and Git tree binding, with exact-commit PR mode and explicit
  tree-equivalent merged-main mode;
- an independently supplied task-policy digest;
- exact required-node population and task keys;
- task-result content digests and dependency-result bindings; and
- PASS-only reusable task results; and
- schema 1.1 declared-output population and byte digests; and
- bounded content-safety inspection of declared text and JSON artifacts.

The `mutation-report-set-v1` output contract is semantic, not opaque. The
verifier independently checks the exact package and artifact roster, canonical
JSON, normalized paths, Stryker status totals and score calculation, package
thresholds, report/result digests, aggregate totals, and the complete/pass
verdict. Absolute workstation paths and incomplete report sets are rejected.
A v1 contract accepts either the standard `mutation-report-set-v1` summary or
the `mutation-composed-report-set-v1` summary, and a composed v1 summary must
still mix fresh and reused packages.

## `mutation-report-set-v2`

A `mutation-report-set-v2` output contract pins `schemaVersion` `2.0.0` and
always requires the `mutation-composed-report-set-v2` summary, with everything
v1 checks plus:

- **Strict all-fresh, all-reused, and mixed compositions.** All three are
  accepted, and each package's provenance is derived from its own digest-bound
  package result rather than read from the summary. Fresh packages must carry
  exact successful process metadata and null baseline identity; reused packages
  must carry no process metadata and the exact declared baseline commit and tree.
- **Immutable per-package evidence references.** Every summary package carries a
  `mutation-package-evidence-ref-v2` reference binding the package name,
  workspace, report and result paths, report and result digests, provenance,
  baseline identity, and input projection digest. Each reference is
  content-addressed by `evidenceRefDigest`, and `aggregate.evidenceSetDigest`
  binds the ordered list of those digests, so no package evidence can be
  substituted, reordered, added, or dropped without breaking a digest the
  verifier recomputes from the artifacts themselves.
- **Mandatory v2 metadata.** `candidate`, `baseline`, `semanticRebindComparison`,
  `aggregate.reusedDurationMs`, and `aggregate.evidenceSetDigest` are required
  even when every package is fresh; the reduced all-fresh summary that omits
  them is rejected rather than silently accepted.
- **Explicit version rejection.** Any mutation report-set or evidence-reference
  kind this verifier does not implement fails closed with
  `MUTATION_VERSION_UNSUPPORTED`, including a v1 summary under a v2 contract and
  a v2 summary under a v1 contract. Contracts are no longer skipped when their
  kind is unrecognized.
- **Content safety inside the report set.** v2 mutation artifacts are inspected
  for credential material and workstation-specific absolute paths as they are
  read, so standalone mutation verification rejects them without depending on an
  enclosing bundle walk. Roster and digest divergences use the stable
  `MUTATION_ROSTER_MISMATCH` and `ARTIFACT_DIGEST_MISMATCH` codes.

Verification stays pure and offline: `preflightCandidateEvidence` and
`verifyPreparedBundle` check a v2 report set with no network, and
`verifyPreparedBundle` needs no candidate checkout or Git remote.

Schema `2.1.0` is the content-addressed mutation-v2 contract. It preserves
`executed`, `reused`, and `not-required` dispositions; recomputes the complete
input projection, report/result addresses, five mutation thresholds, all eight
Stryker status totals, aggregate evidence-set digest, and semantic-receipt
digest; and treats empty or pending required populations as incomplete rather
than passed. Its pure finalizer reads only supplied immutable documents and
opens no process. Legacy v1 and draft v2.0 evidence remain readable for
historical verification only; neither may be preflighted, exported, or
published as new evidence. Every other `mutation-*` kind is reserved and
rejected.

Certify callers that select a `reused` v2.1 package must supply a protected
`resolveReuseOrigin(origin)` function. It resolves the origin outside the
candidate repository and returns the exact trusted producing semantic receipt
and composition. The verifier then requires matching candidate, evidence-set,
receipt, package input/report/result identities, and a passing origin entry.
The portable offline verifier intentionally does not invoke that resolver: its
boundary is the signed current semantic receipt produced by certify.

Offline verification of a `2.1.0` bundle additionally requires all eight
external identities: repository, commit, tree, task-policy digest, signer ID,
trust-root ID, trust-store digest, and key ID. A trust-store `1.1.0` document
binds the latter identities. The verifier rejects symlinks in trust-store and
mutation-artifact paths and requires the signed receipt, manifest, and supplied
task-result populations to close exactly.

Declared UTF-8 text and JSON artifacts are also rejected when they contain
high-confidence credential material, private-key blocks, credential-bearing
URLs, or workstation-specific absolute paths. Rejections use stable
`ARTIFACT_CREDENTIAL_MATERIAL` and `ARTIFACT_HOST_PATH` codes and never include
the matching content. Opaque binary artifacts remain digest-bound but are not
interpreted as text; this boundary is defense in depth, not a guarantee that
pattern matching can identify every possible secret.

## Trust boundary

This is **trusted local attestation**, not proof that a test executed. A valid
signature proves which approved signer asserted the result and that the signed
bytes have not changed. It cannot prove that the signer ran the stated command
or used an uncompromised local runner. Remote UI and documentation must not call
this independently reproduced CI evidence.

The verifier, task policy, trusted public keys, and revocations must be controlled
outside the candidate repository. A candidate must never approve its own signer,
policy digest, or verifier implementation.

## Inputs

- A signed envelope containing canonical candidate-receipt JSON.
- A directory of task-result JSON files named `<sha256>.json`.
- A task policy with exact required nodes, task keys, and dependencies.
- A trust store with Ed25519 public keys and revoked signer IDs.
- Expected repository ID, commit, tree, and task-policy digest supplied by the
  independent caller; v2.1 bundle verification and publication also require
  expected signer ID, trust-root ID, trust-store digest, and key ID.

Schemas are under `schemas/`. The executable verifier performs strict shape
validation without a third-party schema library.

## CLI

```text
node src/cli.js \
  --envelope receipt.dsse.json \
  --results-dir results \
  --task-policy task-policy.json \
  --trust trust.json \
  --repository devaii \
  --commit <40-or-64-hex> \
  --tree <40-or-64-hex> \
  --policy-digest <64-hex> \
  --binding exact-commit
```

Exit contract:

- `0`: verified; one JSON object on stdout and empty stderr.
- `2`: evidence rejected; empty stdout and one JSON error object on stderr.
- `64`: invalid CLI usage; empty stdout and one JSON error object on stderr.
- `70`: unexpected verifier failure; empty stdout and one JSON error object on stderr.

Run focused tests with `node --test`.

For a bundle containing mutation schema `2.1.0`, use `src/bundle-cli.js` with
all eight externally pinned identities. The direct `src/cli.js` example above
does not expose the four additional trust-identity flags. Replace every
placeholder below with an independently approved value, not a value inferred
from the candidate or its bundle:

```text
node src/bundle-cli.js \
  --bundle /protected/evidence/<exact-commit> \
  --trust /protected/control/trust-store.json \
  --repository <expected-repository-id> \
  --commit <exact-commit> \
  --tree <exact-tree> \
  --policy-digest <expected-task-policy-sha256> \
  --signer-id <expected-signer-id> \
  --trust-root-id <expected-trust-root-id> \
  --trust-store-digest <expected-canonical-trust-store-sha256> \
  --key-id <expected-key-id> \
  --binding exact-commit
```

The trust-store digest is `sha256Hex(trustStore)` over the **parsed JSON
object**: SHA-256 of its canonical UTF-8 JSON bytes, with sorted object keys
and no insignificant whitespace. Array order is preserved. It is not a hash of
the raw file bytes; do not use `sha256sum trust-store.json` or
`shasum -a 256 trust-store.json` as the general computation. From the approved
verifier checkout, an operator can compute the digest of the independently
controlled trust store without printing its contents:

```sh
node --input-type=module - /protected/control/trust-store.json <<'JS'
import { sha256Hex } from './src/canonical.js';
import { readAbsoluteRegularFile } from './src/safe-path.js';
const trustStore = JSON.parse(
  readAbsoluteRegularFile(process.argv[2], 'trust store').toString('utf8'),
);
console.log(sha256Hex(trustStore));
JS
```

Pin that digest through protected operator configuration. Computing a digest
does not approve a trust store or its keys, and a candidate-supplied trust
store must never establish its own expected identity.

## Trusted local export

`src/export-cli.js` is the candidate-independent bridge between a local DEVAI
runner cache and the verifier inputs above. It does not run tests and does not
make execution truthful. It independently requires a clean exact candidate,
reads `test-tasks.json` from the committed Git tree, rebuilds the selected task
policy, checks the unsigned receipt and every required result through the same
verifier, and only then signs the canonical receipt bytes.

The private key, public key, toolchain map, environment map, and output directory
must be outside the candidate repository. The command never generates a key and
never accepts a candidate-controlled key. The resulting trust store is a setup
artifact containing only the explicitly supplied public key; repository secrets
and revocations remain protected operator configuration.

```text
node src/export-cli.js \
  --repo /exact/candidate \
  --receipt /exact/candidate/.devai/state/check-cache/v1/receipts/<digest>.json \
  --results-dir /exact/candidate/.devai/state/check-cache/v1/results \
  --profile rc \
  --commit <exact-commit> \
  --tree <exact-tree> \
  --toolchain /protected/control/toolchain.json \
  --environment /protected/control/environment.json \
  --private-key /protected/control/ed25519-private.pem \
  --public-key /protected/control/ed25519-public.pem \
  --signer-id local-rc-signer \
  --output-dir /protected/evidence/<exact-commit>
```

Adding `--preflight true` runs the complete unsigned receipt, task-result,
artifact, and mutation-semantic verification without creating an output or
performing any signing, key generation, or private-key operation. In preflight
mode `--private-key` is not required; normal export continues to require it and
performs the sole signing operation only after preflight succeeds.

The CLI has no candidate-supplied reuse resolver. Consequently, a candidate
with reused v2.1 evidence is refused by CLI preflight unless its hosting API
supplies the protected resolver; callers must not work around that refusal by
relabeling reused evidence as fresh.

Affected-mode export additionally requires `--base <exact-ancestor-commit>`.
The output directory is created atomically. Legacy schema 1.0 bundles contain
`envelope.json`, `task-policy.json`, `trust-store.json`, `manifest.json`, and the
exact digest-named results. Schema 1.1 bundles contain no trust store: remote
verification must supply default-branch or protected-environment trust. They
also contain only declared output files under `artifacts/`.
Content safety is checked through the same verifier path before the atomic
output rename, during explicit bundle re-verification, and again before
publication or remote acceptance.

Export is network-free. Publication is an explicit second command that
re-verifies the prepared bundle with an external trust store, creates an orphan
proof commit, creates or confirms the immutable annotated evidence tag, pushes
only that tag, and dispatches the default-branch verifier workflow:

```text
node src/publish-cli.js \
  --repo /exact/candidate \
  --bundle /protected/evidence/<exact-commit> \
  --trust /protected/control/trust-store.json \
  --repository <expected-repository-id> \
  --commit <exact-commit> \
  --tree <exact-tree> \
  --policy-digest <expected-task-policy-sha256> \
  --signer-id <expected-signer-id> \
  --trust-root-id <expected-trust-root-id> \
  --trust-store-digest <expected-canonical-trust-store-sha256> \
  --key-id <expected-key-id> \
  --tag-prefix devai-local-evidence/ \
  --workflow devai-local-rc-verify.yml \
  --default-branch main
```

All eight identity flags are mandatory when publishing mutation v2.1 evidence,
even though the CLI parser also supports legacy inputs. Use the same protected
pins as the offline bundle verification above. An omitted expectation is
rejected with `MUTATION_OFFLINE_EXPECTATION_MISSING` before publication.

An existing tag is accepted only when its proof-tree bytes are identical.
Different bytes fail with `TAG_COLLISION`; tags are never updated or deleted.

To prepare the existing GitHub workflow inputs from a protected shell, encode
the three JSON files directly and create the result archive with a stable name:

```text
base64 < envelope.json
base64 < task-policy.json
base64 < trust-store.json
tar -C results -czf results.tgz .
base64 < results.tgz
```

Configure the corresponding protected values as
`DEVAI_LEDGER_ENVELOPE_B64`, `DEVAI_LEDGER_TASK_POLICY_B64`,
`DEVAI_LEDGER_TRUST_STORE_B64`, `DEVAI_LEDGER_RESULTS_TGZ_B64`, and set
`DEVAI_LEDGER_POLICY_DIGEST` to `manifest.json.taskPolicyDigest`. Publishing
those values is an operator action; the export command performs no network or
GitHub mutation.

## Expected-policy builder

`src/build-policy-cli.js` derives the verifier's expected task policy from an
approved task descriptor and an exact Git candidate snapshot. Reusable task keys
bind selected candidate blob contents, modes and paths; canonical argv, cwd,
runner, toolchain and allowlisted environment values; output contract; and
dependency task keys. They deliberately exclude commit identity and mtimes.

Affected mode classifies both sides of deletions and renames. Unmatched paths
fail closed unless the approved descriptor names a fallback task. Selectors
explicitly marked dynamic also choose that fallback. Fixed profiles select their
declared node closure without a base commit.

```text
node src/build-policy-cli.js \
  --repo /exact/local/repository \
  --descriptor task-descriptor.json \
  --profile affected \
  --commit <exact-commit> \
  --tree <exact-tree> \
  --base <exact-base-commit> \
  --toolchain toolchain.json \
  --environment environment.json \
  --output expected-task-policy.json
```

The command writes only the expected task-policy JSON to `--output` and reports
its SHA-256 digest on stdout. The verifier and policy builder remain separate:
the independently controlled caller must pin the descriptor, toolchain values,
environment inputs, and resulting policy digest.

# DEVAI evidence verifier reference

This standalone repository is the candidate-independent reference verifier for a
DEVAI v1.0 RC evidence receipt. It uses Node.js built-ins only and contains no
production private key.

The verifier accepts a canonical, Ed25519-signed candidate receipt and checks:

- trusted and non-revoked signer identity;
- exact repository, commit, and Git tree binding;
- an independently supplied task-policy digest;
- exact required-node population and task keys;
- task-result content digests and dependency-result bindings; and
- PASS-only reusable task results.

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
  independent caller.

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
  --policy-digest <64-hex>
```

Exit contract:

- `0`: verified; one JSON object on stdout and empty stderr.
- `2`: evidence rejected; empty stdout and one JSON error object on stderr.
- `64`: invalid CLI usage; empty stdout and one JSON error object on stderr.
- `70`: unexpected verifier failure; empty stdout and one JSON error object on stderr.

Run focused tests with `node --test`.

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

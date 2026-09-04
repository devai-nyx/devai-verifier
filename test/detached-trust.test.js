import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, it } from 'node:test';
import { sha256Hex } from '../src/canonical.js';
import {
  resolveDetachedSigner,
  resolveTrustedSigner,
  verifyDetachedSignature,
} from '../src/trust.js';

const SIGNER_ID = 'fixture-signer';
const KEY_ID = 'fixture-key';
const TRUST_ROOT_ID = 'fixture/trust-root';
const PAYLOAD = Buffer.from('exact detached evidence bytes\x00ç', 'utf8');

function keys() {
  return generateKeyPairSync('ed25519');
}

function trustFixture() {
  const approved = keys();
  const alternate = keys();
  const trustStore = {
    schemaVersion: '1.1.0',
    trustRootId: TRUST_ROOT_ID,
    trustedSigners: [
      {
        signerId: SIGNER_ID,
        keyId: KEY_ID,
        publicKeyPem: approved.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      },
    ],
    revokedSignerIds: [],
    revokedKeyIds: [],
  };
  return {
    approved,
    alternate,
    trustStore,
    signature: sign(null, PAYLOAD, approved.privateKey),
  };
}

function strictOptions(fixture, overrides = {}) {
  return {
    trustStore: fixture.trustStore,
    expectedSignerId: SIGNER_ID,
    expectedTrustRootId: TRUST_ROOT_ID,
    expectedTrustStoreDigest: sha256Hex(fixture.trustStore),
    expectedKeyId: KEY_ID,
    algorithm: 'ed25519',
    ...overrides,
  };
}

function expectCode(code, action) {
  let thrown;
  assert.throws(action, (error) => {
    thrown = error;
    return error?.code === code;
  });
  return thrown;
}

describe('path-free detached trust resolution', () => {
  it('resolves and verifies only the exact v1.1 trust identity and payload bytes', () => {
    const fixture = trustFixture();
    const expected = {
      signerId: SIGNER_ID,
      keyId: KEY_ID,
      publicKeyPem: fixture.trustStore.trustedSigners[0].publicKeyPem,
      trustRootId: TRUST_ROOT_ID,
      trustStoreDigest: sha256Hex(fixture.trustStore),
      algorithm: 'ed25519',
    };

    const resolved = resolveDetachedSigner(strictOptions(fixture));
    const verified = verifyDetachedSignature({
      ...strictOptions(fixture),
      payloadBytes: Buffer.from(PAYLOAD),
      signatureBytes: Buffer.from(fixture.signature),
    });

    assert.deepEqual(resolved, expected);
    assert.deepEqual(verified, expected);
    assert.equal(Object.isFrozen(resolved), true);
    assert.equal(Object.isFrozen(verified), true);
  });

  it('binds the parsed canonical trust-store digest, never incidental raw serialization', () => {
    const fixture = trustFixture();
    const reordered = {
      revokedKeyIds: [],
      trustedSigners: fixture.trustStore.trustedSigners,
      schemaVersion: '1.1.0',
      revokedSignerIds: [],
      trustRootId: TRUST_ROOT_ID,
    };
    const canonicalDigest = sha256Hex(fixture.trustStore);
    const rawDigest = sha256Hex(Buffer.from(JSON.stringify(fixture.trustStore), 'utf8'));

    assert.equal(sha256Hex(reordered), canonicalDigest);
    assert.notEqual(rawDigest, canonicalDigest);
    assert.deepEqual(
      resolveDetachedSigner(strictOptions(fixture, { trustStore: reordered })),
      resolveDetachedSigner(strictOptions(fixture)),
    );
    expectCode('TRUST_STORE_MISMATCH', () =>
      resolveDetachedSigner(strictOptions(fixture, { expectedTrustStoreDigest: rawDigest })),
    );
  });

  it('keeps legacy receipt trust selection available without weakening strict detached resolution', () => {
    const fixture = trustFixture();
    const legacy = {
      schemaVersion: '1.0.0',
      trustedSigners: [
        {
          signerId: SIGNER_ID,
          publicKeyPem: fixture.trustStore.trustedSigners[0].publicKeyPem,
        },
      ],
      revokedSignerIds: [],
    };

    assert.deepEqual(resolveTrustedSigner({ trustStore: legacy, signerId: SIGNER_ID }), {
      signerId: SIGNER_ID,
      publicKeyPem: fixture.trustStore.trustedSigners[0].publicKeyPem,
      trustStoreDigest: sha256Hex(legacy),
      algorithm: 'ed25519',
    });
    expectCode('SCHEMA_INVALID', () =>
      resolveDetachedSigner(strictOptions(fixture, { trustStore: legacy })),
    );
  });

  it('requires every detached expectation and rejects malformed trust versions, types, and duplicates', () => {
    const fixture = trustFixture();
    for (const omitted of [
      'expectedSignerId',
      'expectedTrustRootId',
      'expectedTrustStoreDigest',
      'expectedKeyId',
      'algorithm',
    ]) {
      const options = strictOptions(fixture);
      delete options[omitted];
      expectCode('SCHEMA_INVALID', () => resolveDetachedSigner(options));
    }
    expectCode('SCHEMA_INVALID', () =>
      resolveDetachedSigner(strictOptions(fixture, { trustStore: [] })),
    );
    expectCode('SCHEMA_INVALID', () =>
      resolveDetachedSigner(
        strictOptions(fixture, { trustStore: { ...fixture.trustStore, schemaVersion: '2.0.0' } }),
      ),
    );
    expectCode('SCHEMA_INVALID', () =>
      resolveDetachedSigner(
        strictOptions(fixture, {
          trustStore: {
            ...fixture.trustStore,
            trustedSigners: [
              ...fixture.trustStore.trustedSigners,
              { ...fixture.trustStore.trustedSigners[0] },
            ],
          },
        }),
      ),
    );
    expectCode('SCHEMA_INVALID', () =>
      resolveDetachedSigner(
        strictOptions(fixture, {
          trustStore: {
            ...fixture.trustStore,
            revokedSignerIds: [SIGNER_ID, SIGNER_ID],
          },
        }),
      ),
    );
  });

  it('classifies identity, root, key, revocation, and algorithm mismatches without fallback', () => {
    const fixture = trustFixture();
    expectCode('SIGNER_MISMATCH', () =>
      resolveTrustedSigner({
        trustStore: fixture.trustStore,
        signerId: SIGNER_ID,
        expectedSignerId: 'other-signer',
      }),
    );
    expectCode('TRUST_ROOT_MISMATCH', () =>
      resolveDetachedSigner(strictOptions(fixture, { expectedTrustRootId: 'other/root' })),
    );
    expectCode('TRUST_STORE_MISMATCH', () =>
      resolveDetachedSigner(strictOptions(fixture, { expectedTrustStoreDigest: '0'.repeat(64) })),
    );
    expectCode('KEY_MISMATCH', () =>
      resolveDetachedSigner(strictOptions(fixture, { expectedKeyId: 'other-key' })),
    );
    expectCode('SIGNATURE_ALGORITHM_UNSUPPORTED', () =>
      resolveDetachedSigner(strictOptions(fixture, { algorithm: 'rsa-pss-sha256' })),
    );
    expectCode('SIGNER_REVOKED', () =>
      (() => {
        const trustStore = { ...fixture.trustStore, revokedSignerIds: [SIGNER_ID] };
        return resolveDetachedSigner(
          strictOptions(fixture, { trustStore, expectedTrustStoreDigest: sha256Hex(trustStore) }),
        );
      })(),
    );
    expectCode('SIGNER_REVOKED', () =>
      (() => {
        const trustStore = { ...fixture.trustStore, revokedKeyIds: [KEY_ID] };
        return resolveDetachedSigner(
          strictOptions(fixture, { trustStore, expectedTrustStoreDigest: sha256Hex(trustStore) }),
        );
      })(),
    );
    expectCode('SIGNER_UNTRUSTED', () =>
      (() => {
        const trustStore = {
          ...fixture.trustStore,
          trustedSigners: [
            {
              ...fixture.trustStore.trustedSigners[0],
              signerId: 'other-signer',
              keyId: 'other-key',
            },
          ],
        };
        return resolveDetachedSigner(
          strictOptions(fixture, { trustStore, expectedTrustStoreDigest: sha256Hex(trustStore) }),
        );
      })(),
    );
  });

  it('refuses altered, cross-key, and truncated signatures over exact payload bytes', () => {
    const fixture = trustFixture();
    expectCode('SIGNATURE_INVALID', () =>
      verifyDetachedSignature({
        ...strictOptions(fixture),
        payloadBytes: Buffer.from(`${PAYLOAD} altered`, 'utf8'),
        signatureBytes: fixture.signature,
      }),
    );
    expectCode('SIGNATURE_INVALID', () =>
      verifyDetachedSignature({
        ...strictOptions(fixture),
        payloadBytes: PAYLOAD,
        signatureBytes: sign(null, PAYLOAD, fixture.alternate.privateKey),
      }),
    );
    expectCode('SCHEMA_INVALID', () =>
      verifyDetachedSignature({
        ...strictOptions(fixture),
        payloadBytes: PAYLOAD,
        signatureBytes: fixture.signature.subarray(0, -1),
      }),
    );
    expectCode('SCHEMA_INVALID', () =>
      verifyDetachedSignature({
        ...strictOptions(fixture),
        payloadBytes: new Uint8Array(PAYLOAD),
        signatureBytes: fixture.signature,
      }),
    );
  });

  it('copies native Buffer bytes with intrinsics and refuses shared mutable backing', () => {
    const fixture = trustFixture();
    const payload = Buffer.from(PAYLOAD);
    const signature = Buffer.from(fixture.signature);
    let lengthReads = 0;
    let iteratorReads = 0;
    Object.defineProperty(payload, 'length', {
      enumerable: true,
      get() {
        lengthReads += 1;
        throw new Error('hostile length getter');
      },
    });
    Object.defineProperty(signature, Symbol.iterator, {
      enumerable: true,
      get() {
        iteratorReads += 1;
        throw new Error('hostile iterator getter');
      },
    });

    assert.deepEqual(
      verifyDetachedSignature({
        ...strictOptions(fixture),
        payloadBytes: payload,
        signatureBytes: signature,
      }),
      resolveDetachedSigner(strictOptions(fixture)),
    );
    assert.equal(lengthReads, 0);
    assert.equal(iteratorReads, 0);

    const backing = new SharedArrayBuffer(PAYLOAD.length);
    const shared = Buffer.from(backing);
    Uint8Array.prototype.set.call(shared, PAYLOAD);
    expectCode('SCHEMA_INVALID', () =>
      verifyDetachedSignature({
        ...strictOptions(fixture),
        payloadBytes: shared,
        signatureBytes: fixture.signature,
      }),
    );
  });

  it('refuses accessors and proxies without running hostile traps or leaking key material', () => {
    const fixture = trustFixture();
    let accessorReads = 0;
    const accessorStore = {};
    Object.defineProperty(accessorStore, 'schemaVersion', {
      enumerable: true,
      get() {
        accessorReads += 1;
        return '1.1.0';
      },
    });
    const proxyReads = { value: 0 };
    const proxyStore = new Proxy(fixture.trustStore, {
      get() {
        proxyReads.value += 1;
        throw new Error('hostile proxy trap');
      },
    });
    const secret = 'PRIVATE-KEY-MUST-NOT-LEAK';
    const privatePem = fixture.approved.privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
    const malformed = {
      ...fixture.trustStore,
      trustedSigners: [{ ...fixture.trustStore.trustedSigners[0], publicKeyPem: privatePem }],
    };

    expectCode('SCHEMA_INVALID', () =>
      resolveDetachedSigner(strictOptions(fixture, { trustStore: accessorStore })),
    );
    assert.equal(accessorReads, 0);
    expectCode('SCHEMA_INVALID', () =>
      resolveDetachedSigner(strictOptions(fixture, { trustStore: proxyStore })),
    );
    assert.equal(proxyReads.value, 0);
    const error = expectCode('SCHEMA_INVALID', () =>
      resolveDetachedSigner(strictOptions(fixture, { trustStore: malformed })),
    );
    assert.equal(String(error.message).includes(secret), false);
    assert.equal(String(error.message).includes(privatePem), false);
  });

  it('refuses sparse arrays and newline-tainted identities before key handling', () => {
    const fixture = trustFixture();
    const sparse = [];
    sparse.length = 1;
    expectCode('SCHEMA_INVALID', () =>
      resolveDetachedSigner(
        strictOptions(fixture, {
          trustStore: { ...fixture.trustStore, revokedSignerIds: sparse },
        }),
      ),
    );
    expectCode('SCHEMA_INVALID', () =>
      resolveDetachedSigner(strictOptions(fixture, { expectedSignerId: `${SIGNER_ID}\n` })),
    );
    expectCode('SCHEMA_INVALID', () =>
      resolveDetachedSigner(strictOptions(fixture, { expectedTrustRootId: `${TRUST_ROOT_ID}\n` })),
    );
  });
});

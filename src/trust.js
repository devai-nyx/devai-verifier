import { createPublicKey, verify } from 'node:crypto';
import { types } from 'node:util';
import { VerificationError, sha256Hex } from './canonical-json.js';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const EXPECTATIONS = [
  'expectedSignerId',
  'expectedTrustRootId',
  'expectedTrustStoreDigest',
  'expectedKeyId',
];

function reject(code, message) {
  throw new VerificationError(code, message);
}

// These APIs accept inert parsed JSON, not objects with executable properties.
// Capture descriptors before reading values so callers cannot swap identities
// between validation, canonical hashing and key selection.
function record(value, required, optional = []) {
  if (value === null || typeof value !== 'object' || types.isProxy(value)) {
    reject('SCHEMA_INVALID', 'trust input must be an inert JSON record');
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    reject('SCHEMA_INVALID', 'trust input must be a plain JSON record');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    required.some((key) => !Object.hasOwn(descriptors, key)) ||
    keys.some((key) => typeof key !== 'string' || ![...required, ...optional].includes(key))
  ) {
    reject('SCHEMA_INVALID', 'trust input has an invalid field population');
  }
  const result = Object.create(null);
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      reject('SCHEMA_INVALID', 'trust input must contain enumerable data properties');
    }
    result[key] = descriptor.value;
  }
  return result;
}

function array(value) {
  if (
    types.isProxy(value) ||
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype
  ) {
    reject('SCHEMA_INVALID', 'trust population must be a plain array');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const length = descriptors.length.value;
  if (Reflect.ownKeys(descriptors).length !== length + 1) {
    reject('SCHEMA_INVALID', 'trust population must be dense and contain no extra fields');
  }
  const result = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[index];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      reject('SCHEMA_INVALID', 'trust population must contain only data entries');
    }
    result.push(descriptor.value);
  }
  return result;
}

function string(value, pattern) {
  if (typeof value !== 'string' || (pattern !== undefined && value.match(pattern)?.[0] !== value)) {
    reject('SCHEMA_INVALID', 'trust identity or key field is invalid');
  }
  return value;
}

function unique(values) {
  if (values.some((value) => typeof value !== 'string') || new Set(values).size !== values.length) {
    reject('SCHEMA_INVALID', 'trust identities must be unique strings');
  }
  return values;
}

function publicKey(pem) {
  // createPublicKey also accepts private PEMs. The public trust store must not.
  if (
    !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----(?:\r?\n)?$/u.test(
      pem,
    )
  ) {
    reject('SCHEMA_INVALID', 'trust key must contain only a public SPKI PEM');
  }
  let key;
  try {
    key = createPublicKey(pem);
  } catch {
    reject('SCHEMA_INVALID', 'trust key is not a valid public key');
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    reject('SCHEMA_INVALID', 'trust key must be Ed25519');
  }
  return key;
}

function captureTrustStore(value) {
  const header = record(
    value,
    ['schemaVersion', 'trustedSigners', 'revokedSignerIds'],
    ['trustRootId', 'revokedKeyIds'],
  );
  const v11 = header.schemaVersion === '1.1.0';
  if (!v11 && header.schemaVersion !== '1.0.0') {
    reject('SCHEMA_INVALID', 'unsupported trust-store schemaVersion');
  }
  const trust = record(
    header,
    v11
      ? ['schemaVersion', 'trustedSigners', 'revokedSignerIds', 'trustRootId', 'revokedKeyIds']
      : ['schemaVersion', 'trustedSigners', 'revokedSignerIds'],
  );
  if (v11) string(trust.trustRootId, IDENTIFIER);
  trust.revokedSignerIds = unique(array(trust.revokedSignerIds));
  if (v11) trust.revokedKeyIds = unique(array(trust.revokedKeyIds));
  trust.trustedSigners = array(trust.trustedSigners).map((value) => {
    const signer = record(
      value,
      v11 ? ['signerId', 'keyId', 'publicKeyPem'] : ['signerId', 'publicKeyPem'],
    );
    string(signer.signerId, IDENTIFIER);
    if (v11) string(signer.keyId, IDENTIFIER);
    string(signer.publicKeyPem);
    publicKey(signer.publicKeyPem);
    return signer;
  });
  if (trust.trustedSigners.length === 0)
    reject('SCHEMA_INVALID', 'trustedSigners must be nonempty');
  unique(trust.trustedSigners.map((signer) => signer.signerId));
  if (v11) unique(trust.trustedSigners.map((signer) => signer.keyId));
  return trust;
}

function resolve(options, strict) {
  const trust = captureTrustStore(options.trustStore);
  if (strict && trust.schemaVersion !== '1.1.0') {
    reject('SCHEMA_INVALID', 'detached verification requires trust-store schema 1.1.0');
  }
  const signerId = string(strict ? options.expectedSignerId : options.signerId, IDENTIFIER);
  for (const key of EXPECTATIONS) {
    if (strict || options[key] !== undefined)
      string(options[key], key === 'expectedTrustStoreDigest' ? SHA256 : IDENTIFIER);
  }
  if (options.expectedSignerId !== undefined && signerId !== options.expectedSignerId) {
    reject('SIGNER_MISMATCH', 'signature signer differs from expected signer');
  }
  const trustStoreDigest = sha256Hex(trust);
  if (
    options.expectedTrustStoreDigest !== undefined &&
    trustStoreDigest !== options.expectedTrustStoreDigest
  ) {
    reject('TRUST_STORE_MISMATCH', 'trust store digest differs from expected digest');
  }
  if (
    options.expectedTrustRootId !== undefined &&
    trust.trustRootId !== options.expectedTrustRootId
  ) {
    reject('TRUST_ROOT_MISMATCH', 'trust root differs from expected trust root');
  }
  if (trust.revokedSignerIds.includes(signerId)) reject('SIGNER_REVOKED', 'signer is revoked');
  const signer = trust.trustedSigners.find((entry) => entry.signerId === signerId);
  if (signer === undefined) reject('SIGNER_UNTRUSTED', 'signer is not trusted');
  if (options.expectedKeyId !== undefined && signer.keyId !== options.expectedKeyId) {
    reject('KEY_MISMATCH', 'trusted signer key differs from expected key');
  }
  if (trust.revokedKeyIds?.includes(signer.keyId))
    reject('SIGNER_REVOKED', 'signer key is revoked');
  return Object.freeze({
    signerId,
    ...(signer.keyId !== undefined && { keyId: signer.keyId }),
    publicKeyPem: signer.publicKeyPem,
    ...(trust.trustRootId !== undefined && { trustRootId: trust.trustRootId }),
    trustStoreDigest,
    algorithm: 'ed25519',
  });
}

/** Shared receipt compatibility kernel. Optional expectations remain legacy-only. */
export function resolveTrustedSigner(options) {
  return resolve(record(options, ['trustStore', 'signerId'], EXPECTATIONS), false);
}

function detachedOptions(options, byteFields = []) {
  const captured = record(options, ['trustStore', 'algorithm', ...EXPECTATIONS, ...byteFields]);
  if (captured.algorithm !== 'ed25519') {
    reject('SIGNATURE_ALGORITHM_UNSUPPORTED', 'canonical detached signatures support Ed25519 only');
  }
  return captured;
}

function captureBytes(value) {
  if (
    types.isProxy(value) ||
    !Buffer.isBuffer(value) ||
    Object.getPrototypeOf(value) !== Buffer.prototype
  ) {
    reject('SCHEMA_INVALID', 'detached verification requires native Buffer bytes');
  }
  // Use typed-array intrinsics, not caller-overridable length/iterator/copy.
  const prototype = Object.getPrototypeOf(Uint8Array.prototype);
  const backing = Object.getOwnPropertyDescriptor(prototype, 'buffer').get.call(value);
  if (types.isSharedArrayBuffer(backing)) {
    reject('SCHEMA_INVALID', 'detached verification refuses concurrently mutable shared bytes');
  }
  const length = Object.getOwnPropertyDescriptor(prototype, 'byteLength').get.call(value);
  const copy = Buffer.alloc(length);
  Uint8Array.prototype.set.call(copy, value);
  return copy;
}

/** Path-free key selection; protected callers supply every expectation independently. */
export function resolveDetachedSigner(options) {
  return resolve(detachedOptions(options), true);
}

/** Verify the exact transcript bytes; this is not evidence of test execution. */
export function verifyDetachedSignature(options) {
  const captured = detachedOptions(options, ['payloadBytes', 'signatureBytes']);
  const signer = resolve(captured, true);
  const payload = captureBytes(captured.payloadBytes);
  const signature = captureBytes(captured.signatureBytes);
  if (signature.length !== 64) {
    reject('SCHEMA_INVALID', 'detached signature requires payload bytes and a 64-byte signature');
  }
  if (!verify(null, payload, publicKey(signer.publicKeyPem), signature)) {
    reject('SIGNATURE_INVALID', 'detached signature is invalid');
  }
  return signer;
}

import { createHash } from 'node:crypto';

export function containsAsciiControl(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

export class VerificationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'VerificationError';
    this.code = code;
  }
}

export function canonicalize(value, path = '$') {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new VerificationError('NON_CANONICAL_JSON', `${path} contains a non-finite number`);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry, index) => canonicalize(entry, `${path}[${index}]`)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new VerificationError('NON_CANONICAL_JSON', `${path} is not a plain JSON object`);
    }
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key], `${path}.${key}`)}`)
      .join(',')}}`;
  }
  throw new VerificationError('NON_CANONICAL_JSON', `${path} contains a non-JSON value`);
}

export function canonicalBytes(value) {
  return Buffer.from(canonicalize(value), 'utf8');
}

export function sha256Hex(value) {
  const bytes = Buffer.isBuffer(value) ? value : canonicalBytes(value);
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Computes the mutation-v2.1 domain-separated digest.
 *
 * The framing is deliberately explicit: ASCII domain, one NUL octet, an unsigned
 * eight-octet big-endian payload length, then RFC 8785-compatible canonical JSON
 * UTF-8 bytes. A NUL in the domain would make the boundary ambiguous and is refused.
 */
export function framedDigest(domain, value) {
  if (typeof domain !== 'string' || domain.length === 0 || domain.includes('\0')) {
    throw new VerificationError(
      'SCHEMA_INVALID',
      'digest domain must be nonempty and contain no NUL',
    );
  }
  const domainBytes = Buffer.from(domain, 'ascii');
  if (domainBytes.toString('ascii') !== domain) {
    throw new VerificationError('SCHEMA_INVALID', 'digest domain must contain ASCII only');
  }
  const payload = canonicalBytes(value);
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(payload.length));
  return createHash('sha256')
    .update(domainBytes)
    .update(Buffer.from([0]))
    .update(length)
    .update(payload)
    .digest('hex');
}

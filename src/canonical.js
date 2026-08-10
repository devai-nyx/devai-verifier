import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

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

export function readJson(path, label) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    throw new VerificationError('INPUT_MISSING', `${label} is unreadable: ${error.message}`);
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new VerificationError('MALFORMED_JSON', `${label} is not valid JSON: ${error.message}`);
  }
}

export function assertObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new VerificationError('SCHEMA_INVALID', `${label} must be an object`);
  }
}

export function assertExactKeys(value, keys, label) {
  assertObject(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new VerificationError(
      'SCHEMA_INVALID',
      `${label} keys must be exactly ${expected.join(', ')}`,
    );
  }
}

export function assertString(value, label, pattern) {
  if (typeof value !== 'string' || (pattern !== undefined && !pattern.test(value))) {
    throw new VerificationError('SCHEMA_INVALID', `${label} is invalid`);
  }
}

export function assertUniqueStrings(values, label) {
  if (!Array.isArray(values) || values.some((value) => typeof value !== 'string')) {
    throw new VerificationError('SCHEMA_INVALID', `${label} must be a string array`);
  }
  if (new Set(values).size !== values.length) {
    throw new VerificationError('SCHEMA_INVALID', `${label} must contain unique values`);
  }
}

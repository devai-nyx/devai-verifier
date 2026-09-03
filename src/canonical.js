import { readFileSync } from 'node:fs';
import { VerificationError } from './canonical-json.js';

export {
  VerificationError,
  canonicalBytes,
  canonicalize,
  framedDigest,
  sha256Hex,
} from './canonical-json.js';

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

import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from 'node:fs';
import { isAbsolute, join, parse, relative, resolve } from 'node:path';
import { VerificationError } from './canonical-json.js';

const CONTROL = /[\u0000-\u001f\u007f]/u;
const DRIVE = /^[A-Za-z]:/u;

export function validatePortablePathV21(path, label = 'artifact path') {
  if (
    typeof path !== 'string' ||
    path.length === 0 ||
    path !== path.normalize('NFC') ||
    isAbsolute(path) ||
    DRIVE.test(path) ||
    path.startsWith('//') ||
    path.includes('\\') ||
    CONTROL.test(path)
  ) {
    throw new VerificationError('SCHEMA_INVALID', `${label} is not a canonical portable path`);
  }
  const segments = path.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new VerificationError('SCHEMA_INVALID', `${label} is not a canonical portable path`);
  }
  return path;
}

/**
 * Reads a root-relative regular file without following a symbolic link in the final
 * component. Every ancestor is lstat-checked first. Diagnostics deliberately contain
 * only the caller-provided logical label, never a native path or native error string.
 */
export function readRootRelativeRegularFile(root, path, label) {
  validatePortablePathV21(path, `${label} path`);
  const absoluteRoot = resolve(root);
  let cursor = absoluteRoot;
  const segments = path.split('/');
  for (let index = 0; index < segments.length; index += 1) {
    cursor = join(cursor, segments[index]);
    let stat;
    try {
      stat = lstatSync(cursor);
    } catch {
      throw new VerificationError('ARTIFACTS_MISSING', `${label} is unavailable`);
    }
    if (stat.isSymbolicLink()) {
      throw new VerificationError('ARTIFACT_SYMLINK_ESCAPE', `${label} traverses a symbolic link`);
    }
    if (index < segments.length - 1 && !stat.isDirectory()) {
      throw new VerificationError('ARTIFACT_INVALID', `${label} ancestor is not a directory`);
    }
    if (index === segments.length - 1 && !stat.isFile()) {
      throw new VerificationError('ARTIFACT_INVALID', `${label} is not a regular file`);
    }
  }

  let descriptor;
  try {
    descriptor = openSync(cursor, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    if (!fstatSync(descriptor).isFile()) {
      throw new VerificationError('ARTIFACT_INVALID', `${label} is not a regular file`);
    }
    return readFileSync(descriptor);
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    if (error?.code === 'ELOOP') {
      throw new VerificationError('ARTIFACT_SYMLINK_ESCAPE', `${label} traverses a symbolic link`);
    }
    throw new VerificationError('ARTIFACTS_MISSING', `${label} is unreadable`);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function readAbsoluteRegularFile(path, label) {
  // macOS exposes /var and /tmp as stable system aliases into /private. Normalize
  // those platform roots before enforcing the no-follow rule so user-controlled
  // descendants are still checked component by component.
  const requested = resolve(path);
  const absolute = requested.startsWith('/var/')
    ? `/private${requested}`
    : requested.startsWith('/tmp/')
      ? `/private${requested}`
      : requested;
  const root = parse(absolute).root;
  const fromRoot = relative(root, absolute).split('\\').join('/');
  return readRootRelativeRegularFile(root, fromRoot, label);
}

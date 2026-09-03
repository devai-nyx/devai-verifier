import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { isAbsolute, join, parse, relative, resolve } from 'node:path';
import { VerificationError, containsAsciiControl } from './canonical-json.js';

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
    containsAsciiControl(path)
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
/**
 * Opens a root-relative regular file without following a final symlink and
 * rejects ancestor swaps. Node does not expose openat(2), so the portable
 * implementation snapshots every path component, opens the final component with
 * O_NOFOLLOW, and proves that the opened descriptor and every ancestor still
 * have the snapshotted device/inode identity before reading. A swap can therefore
 * never cause unverified bytes to be accepted or copied.
 */
function openRootRelativeRegularFile(root, path, label) {
  validatePortablePathV21(path, `${label} path`);
  const absoluteRoot = resolve(root);
  const segments = path.split('/');
  const snapshots = [];
  let cursor = absoluteRoot;
  try {
    for (let index = -1; index < segments.length; index += 1) {
      if (index >= 0) cursor = join(cursor, segments[index]);
      const stat = lstatSync(cursor);
      if (stat.isSymbolicLink()) {
        throw new VerificationError(
          'ARTIFACT_SYMLINK_ESCAPE',
          `${label} traverses a symbolic link`,
        );
      }
      if (index < segments.length - 1 && !stat.isDirectory()) {
        throw new VerificationError('ARTIFACT_INVALID', `${label} ancestor is not a directory`);
      }
      if (index === segments.length - 1 && !stat.isFile()) {
        throw new VerificationError('ARTIFACT_INVALID', `${label} is not a regular file`);
      }
      snapshots.push({ path: cursor, dev: stat.dev, ino: stat.ino });
    }
    const descriptor = openSync(cursor, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(descriptor);
    const expected = snapshots.at(-1);
    if (!opened.isFile()) {
      closeSync(descriptor);
      throw new VerificationError('ARTIFACT_INVALID', `${label} is not a regular file`);
    }
    if (opened.dev !== expected.dev || opened.ino !== expected.ino) {
      closeSync(descriptor);
      throw new VerificationError('ARTIFACT_RACE_DETECTED', `${label} changed during safe access`);
    }
    for (const snapshot of snapshots) {
      const current = lstatSync(snapshot.path);
      if (
        current.isSymbolicLink() ||
        current.dev !== snapshot.dev ||
        current.ino !== snapshot.ino
      ) {
        closeSync(descriptor);
        throw new VerificationError(
          'ARTIFACT_RACE_DETECTED',
          `${label} changed during safe access`,
        );
      }
    }
    return descriptor;
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    if (error?.code === 'ELOOP') {
      throw new VerificationError('ARTIFACT_SYMLINK_ESCAPE', `${label} traverses a symbolic link`);
    }
    throw new VerificationError('ARTIFACTS_MISSING', `${label} is unavailable`);
  }
}

export function readRootRelativeRegularFile(root, path, label) {
  let descriptor;
  try {
    descriptor = openRootRelativeRegularFile(root, path, label);
    return readFileSync(descriptor);
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    throw new VerificationError('ARTIFACTS_MISSING', `${label} is unreadable`);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function copyRootRelativeRegularFile(root, path, destination, label) {
  const bytes = readRootRelativeRegularFile(root, path, label);
  try {
    writeFileSync(destination, bytes, { flag: 'wx' });
  } catch {
    throw new VerificationError('ARTIFACT_COPY_FAILED', `${label} could not be staged`);
  }
}

export function readAbsoluteRegularFile(path, label) {
  // macOS exposes /var and /tmp as stable system aliases into /private. Normalize
  // those platform roots before enforcing the no-follow rule so user-controlled
  // descendants are still checked component by component.
  const requested = resolve(path);
  const absolute =
    process.platform === 'darwin' && requested.startsWith('/var/')
      ? `/private${requested}`
      : process.platform === 'darwin' && requested.startsWith('/tmp/')
        ? `/private${requested}`
        : requested;
  const root = parse(absolute).root;
  const fromRoot = relative(root, absolute).split('\\').join('/');
  return readRootRelativeRegularFile(root, fromRoot, label);
}

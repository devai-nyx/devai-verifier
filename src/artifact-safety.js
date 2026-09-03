import { VerificationError } from './canonical.js';

const MAX_TEXT_ARTIFACT_BYTES = 32 * 1024 * 1024;

const CREDENTIAL_PATTERNS = [
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/u,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/u,
  /\bnpm_[A-Za-z0-9]{20,}\b/u,
  /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/u,
  /\b(?:https?|npm):\/\/[^\s/:]+:[^\s@/]+@/u,
];

// Every pattern is anchored on an absolute root that only exists on a particular
// workstation and is bounded so a hostile artifact cannot drive the scan quadratic.
// A portable relative path such as `Volumes/data/report.json` never carries the
// leading separator these patterns require, so it stays acceptable.
const HOST_PATH_PATTERNS = [
  /(?:^|[\s"'=:,(])\/(?:Users|home)\/[A-Za-z0-9._-]+(?:\/[^\s"']{0,4096})?/u,
  /(?:^|[\s"'=:,(])\/(?:private\/)?tmp\/[^\s"']{1,4096}/u,
  // macOS mounts external and secondary disks under /Volumes and gives each user a
  // per-boot scratch root under /var/folders; both leak the operator's workstation
  // exactly the way a home directory does.
  /(?:^|[\s"'=:,(])\/Volumes\/[A-Za-z0-9._-]{1,255}(?:\/[^\s"']{0,4096})?/u,
  /(?:^|[\s"'=:,(])\/(?:private\/)?var\/folders\/[A-Za-z0-9._+-]{1,255}(?:\/[^\s"']{0,4096})?/u,
  /\bfile:\/\/\/(?:Users|home|Volumes|(?:private\/)?(?:tmp|var\/folders))\/[^\s"']{1,4096}/u,
  /(?:^|[\s"'=:,(])[A-Za-z]:\\{1,2}Users\\{1,2}[^\s"']{1,4096}/u,
];

export function artifactMediaType(path) {
  if (path.endsWith('.json')) return 'application/json';
  if (path.endsWith('.txt') || path.endsWith('.log') || path.endsWith('.md')) {
    return 'text/plain';
  }
  if (path.endsWith('.csv')) return 'text/csv';
  if (path.endsWith('.xml')) return 'application/xml';
  return 'application/octet-stream';
}

function isTextMediaType(mediaType) {
  return (
    mediaType === 'application/json' ||
    mediaType === 'application/xml' ||
    mediaType.startsWith('text/')
  );
}

function decodeUtf8(bytes, path) {
  if (bytes.length > MAX_TEXT_ARTIFACT_BYTES) {
    throw new VerificationError(
      'ARTIFACT_INVALID',
      `artifact ${path} exceeds the bounded text inspection limit`,
    );
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new VerificationError('ARTIFACT_INVALID', `artifact ${path} is not valid UTF-8 text`);
  }
  if (Buffer.byteLength(text, 'utf8') !== bytes.length) {
    throw new VerificationError('ARTIFACT_INVALID', `artifact ${path} is not valid UTF-8 text`);
  }
  return text;
}

export function validateArtifactContent({ bytes, path, mediaType = artifactMediaType(path) }) {
  if (!isTextMediaType(mediaType)) return;
  const text = decodeUtf8(bytes, path);
  if (CREDENTIAL_PATTERNS.some((pattern) => pattern.test(text))) {
    throw new VerificationError(
      'ARTIFACT_CREDENTIAL_MATERIAL',
      `artifact ${path} contains credential-shaped material`,
    );
  }
  if (HOST_PATH_PATTERNS.some((pattern) => pattern.test(text))) {
    throw new VerificationError(
      'ARTIFACT_HOST_PATH',
      `artifact ${path} contains a workstation-specific absolute path`,
    );
  }
}

export { MAX_TEXT_ARTIFACT_BYTES };

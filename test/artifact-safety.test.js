import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  MAX_TEXT_ARTIFACT_BYTES,
  artifactMediaType,
  validateArtifactContent,
} from '../src/artifact-safety.js';

function expectCode(code, action) {
  assert.throws(action, (error) => error?.code === code);
}

describe('portable artifact content safety', () => {
  it('accepts portable canonical JSON and leaves binary artifacts uninterpreted', () => {
    validateArtifactContent({
      bytes: Buffer.from('{"projectRoot":".","proof":true}\n'),
      path: 'mutation/report.json',
    });
    validateArtifactContent({
      bytes: Buffer.from([0xff, 0x00, 0x01]),
      path: 'opaque.bin',
    });
    assert.equal(artifactMediaType('proof.json'), 'application/json');
    assert.equal(artifactMediaType('opaque.bin'), 'application/octet-stream');
  });

  it('rejects high-confidence credential material without echoing it', () => {
    const values = [
      `gho_${'a'.repeat(36)}`,
      `github_pat_${'b'.repeat(40)}`,
      `npm_${'c'.repeat(36)}`,
      `xoxb-${'1'.repeat(12)}-${'d'.repeat(24)}`,
      `AKIA${'A'.repeat(16)}`,
      `-----BEGIN ${'PRIVATE'} KEY-----`,
      'https://user:password@example.invalid/package',
    ];
    for (const value of values) {
      expectCode('ARTIFACT_CREDENTIAL_MATERIAL', () =>
        validateArtifactContent({
          bytes: Buffer.from(JSON.stringify({ value })),
          path: 'mutation/report.json',
        }),
      );
    }
  });

  it('rejects macOS, Linux, temporary, file URL, and Windows workstation paths', () => {
    const values = [
      '/Users/inspector/project/report.json',
      '/home/inspector/project/report.json',
      '/private/tmp/devai/report.json',
      '/Volumes/Thiamat/stech/devai-verifier/report.json',
      '/Volumes/Backup',
      '/var/folders/q7/9m0xk1_s0fs/T/devai-export/report.json',
      '/private/var/folders/q7/9m0xk1_s0fs/T/devai-export/report.json',
      'file:///Users/inspector/project/report.json',
      'file:///Volumes/Thiamat/stech/report.json',
      'file:///var/folders/q7/9m0xk1_s0fs/T/report.json',
      'C:\\Users\\inspector\\project\\report.json',
    ];
    for (const value of values) {
      const bytes = Buffer.from(JSON.stringify({ value }));
      assert.throws(
        () => validateArtifactContent({ bytes, path: 'mutation/report.json' }),
        (error) => {
          assert.equal(error.code, 'ARTIFACT_HOST_PATH');
          // The refusal names the declared artifact, never the matched workstation
          // path, so a fail-closed message cannot itself leak the operator's layout.
          assert.equal(
            error.message,
            'artifact mutation/report.json contains a workstation-specific absolute path',
          );
          assert.equal(error.message.includes(value), false);
          return true;
        },
      );
    }
  });

  it('accepts portable relative paths that merely share a workstation root name', () => {
    const values = [
      'Volumes/data/report.json',
      'packages/core/var/folders/report.json',
      'dist/Volumes/index.js',
      'var/folders/report.json',
      'src/home/user/index.ts',
    ];
    for (const value of values) {
      validateArtifactContent({
        bytes: Buffer.from(JSON.stringify({ value })),
        path: 'mutation/report.json',
      });
    }
  });

  it('rejects invalid UTF-8 and text artifacts beyond the bounded scan limit', () => {
    expectCode('ARTIFACT_INVALID', () =>
      validateArtifactContent({ bytes: Buffer.from([0xff]), path: 'report.json' }),
    );
    expectCode('ARTIFACT_INVALID', () =>
      validateArtifactContent({
        bytes: Buffer.alloc(MAX_TEXT_ARTIFACT_BYTES + 1, 0x61),
        path: 'report.json',
      }),
    );
  });
});

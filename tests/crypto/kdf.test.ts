import { describe, expect, it } from 'vitest';
import { argon2id } from 'hash-wasm';
import { pbkdf2Sync } from 'node:crypto';
import { fromBase64, toBase64, utf8 } from '../../src/crypto/bytes';
import { DEFAULT_ARGON2, DEFAULT_PBKDF2_ITERATIONS, deriveKeyBytes, newKdfParams, validateKdfParams } from '../../src/crypto/kdf';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

describe('PBKDF2-SHA-256', () => {
  it('matches an independent implementation (Node crypto.pbkdf2Sync)', async () => {
    const salt = utf8('saltSALTsaltSALT');
    const out = await deriveKeyBytes('password', { alg: 'pbkdf2-sha256', iterations: 4096, salt: toBase64(salt) });
    const expected = pbkdf2Sync('password', Buffer.from(salt), 4096, 32, 'sha256');
    expect(hex(out)).toBe(expected.toString('hex'));
  });

  it('defaults to 600 000 iterations and a fresh 16-byte salt', () => {
    const a = newKdfParams('pbkdf2-sha256');
    const b = newKdfParams('pbkdf2-sha256');
    expect(a).toMatchObject({ alg: 'pbkdf2-sha256', iterations: DEFAULT_PBKDF2_ITERATIONS });
    expect(fromBase64(a.salt)).toHaveLength(16);
    expect(a.salt).not.toBe(b.salt);
  });

  it('gives different keys for different salts and passwords', async () => {
    const p1 = { alg: 'pbkdf2-sha256' as const, iterations: 1000, salt: toBase64(new Uint8Array(16).fill(1)) };
    const p2 = { ...p1, salt: toBase64(new Uint8Array(16).fill(2)) };
    const a = hex(await deriveKeyBytes('pw', p1));
    expect(hex(await deriveKeyBytes('pw', p1))).toBe(a);
    expect(hex(await deriveKeyBytes('pw', p2))).not.toBe(a);
    expect(hex(await deriveKeyBytes('pw2', p1))).not.toBe(a);
  });
});

describe('Argon2id', () => {
  it('defaults to 64 MiB, 3 passes, parallelism 1', () => {
    const p = newKdfParams('argon2id');
    expect(p).toMatchObject({ alg: 'argon2id', memKiB: 64 * 1024, iterations: 3, parallelism: 1 });
    expect(DEFAULT_ARGON2.memKiB).toBe(65536);
  });

  it('agrees with hash-wasm called directly and depends on every parameter', async () => {
    const salt = new Uint8Array(16).fill(9);
    const base = { alg: 'argon2id' as const, memKiB: 256, iterations: 2, parallelism: 1, salt: toBase64(salt) };
    const ours = await deriveKeyBytes('correct horse', base);
    const direct = await argon2id({
      password: 'correct horse', salt, memorySize: 256, iterations: 2, parallelism: 1, hashLength: 32, outputType: 'binary',
    });
    expect(hex(ours)).toBe(hex(direct));
    expect(ours).toHaveLength(32);
    expect(hex(await deriveKeyBytes('correct horse', { ...base, iterations: 3 }))).not.toBe(hex(ours));
    expect(hex(await deriveKeyBytes('correct horse', { ...base, memKiB: 512 }))).not.toBe(hex(ours));
    expect(hex(await deriveKeyBytes('correct horsE', base))).not.toBe(hex(ours));
  });

  it('runs with the default 64 MiB parameters', async () => {
    const out = await deriveKeyBytes('pw', newKdfParams('argon2id'));
    expect(out).toHaveLength(32);
  });

  it('normalizes the password to NFC', async () => {
    const p = { alg: 'argon2id' as const, memKiB: 64, iterations: 1, parallelism: 1, salt: toBase64(new Uint8Array(16)) };
    const composed = 'café';
    const decomposed = 'café';
    expect(hex(await deriveKeyBytes(composed, p))).toBe(hex(await deriveKeyBytes(decomposed, p)));
  });

  it('rejects absurd parameters from a tampered keyring', () => {
    const salt = toBase64(new Uint8Array(16));
    expect(() => validateKdfParams({ alg: 'argon2id', memKiB: 1 << 30, iterations: 3, parallelism: 1, salt })).toThrow();
    expect(() => validateKdfParams({ alg: 'pbkdf2-sha256', iterations: 0, salt })).toThrow();
    expect(() => validateKdfParams({ alg: 'scrypt', salt })).toThrow();
  });
});

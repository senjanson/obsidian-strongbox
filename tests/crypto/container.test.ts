import { describe, expect, it } from 'vitest';
import { concatBytes, fromUtf8, randomBytes, utf8 } from '../../src/crypto/bytes';
import {
  DecryptError, HEADER_SIZE, MAGIC, TAG_BYTES, containerKeyId, decryptContainer, encryptContainer, isContainer, parseHeader,
} from '../../src/crypto/container';
import { testKeys } from '../helpers/keys';

async function expectDecryptError(p: Promise<unknown>, kind: string) {
  await expect(p).rejects.toBeInstanceOf(DecryptError);
  await p.catch((e: DecryptError) => expect(e.kind).toBe(kind));
}

describe('file container', () => {
  it('round-trips data of many sizes, including empty and exact chunk multiples', async () => {
    const keys = await testKeys();
    for (const size of [0, 1, 15, 16, 17, 31, 32, 33, 64, 1000]) {
      const data = randomBytes(size);
      const ct = await encryptContainer(data, keys, { chunkSize: 16 });
      expect(isContainer(ct)).toBe(true);
      expect(ct.length).toBe(HEADER_SIZE + size + Math.max(1, Math.ceil(size / 16)) * TAG_BYTES);
      expect(await decryptContainer(ct, keys)).toEqual(data);
    }
  });

  it('round-trips with the default 64 KiB chunks', async () => {
    const keys = await testKeys();
    const data = randomBytes(200_000);
    expect(await decryptContainer(await encryptContainer(data, keys), keys)).toEqual(data);
  });

  it('writes the header fields and a fresh salt each time', async () => {
    const keys = await testKeys(0xdeadbeef);
    const a = await encryptContainer(utf8('same'), keys, { chunkSize: 4096 });
    const b = await encryptContainer(utf8('same'), keys, { chunkSize: 4096 });
    expect(a.subarray(0, 8)).toEqual(MAGIC);
    const h = parseHeader(a);
    expect(h).toMatchObject({ version: 1, keyId: 0xdeadbeef, chunkSize: 4096 });
    expect(containerKeyId(a)).toBe(0xdeadbeef);
    expect(h.salt).not.toEqual(parseHeader(b).salt);
    expect(a).not.toEqual(b);
  });

  it('detects any flipped bit in header or body', async () => {
    const keys = await testKeys();
    const ct = await encryptContainer(utf8('hello tamper world'), keys, { chunkSize: 16 });
    for (const pos of [9, 20, 47, HEADER_SIZE + 1, ct.length - 1]) {
      const bad = ct.slice();
      bad[pos] ^= 0x01;
      await expect(decryptContainer(bad, keys)).rejects.toBeInstanceOf(DecryptError);
    }
  });

  it('detects truncation at a chunk boundary (dropped final chunk)', async () => {
    const keys = await testKeys();
    const ct = await encryptContainer(randomBytes(48), keys, { chunkSize: 16 });
    const stride = 16 + TAG_BYTES;
    const truncated = ct.slice(0, HEADER_SIZE + 2 * stride);
    await expectDecryptError(decryptContainer(truncated, keys), 'auth');
    await expect(decryptContainer(ct.slice(0, ct.length - 5), keys)).rejects.toBeInstanceOf(DecryptError);
    await expectDecryptError(decryptContainer(ct.slice(0, HEADER_SIZE), keys), 'format');
  });

  it('detects reordered chunks', async () => {
    const keys = await testKeys();
    const ct = await encryptContainer(randomBytes(48), keys, { chunkSize: 16 });
    const stride = 16 + TAG_BYTES;
    const header = ct.subarray(0, HEADER_SIZE);
    const c = (i: number) => ct.subarray(HEADER_SIZE + i * stride, HEADER_SIZE + (i + 1) * stride);
    const swapped = concatBytes(header, c(1), c(0), c(2));
    await expectDecryptError(decryptContainer(swapped, keys), 'auth');
  });

  it('refuses a wrong key and reports an unknown key id', async () => {
    const keys = await testKeys(1, 7);
    const other = await testKeys(1, 8);
    const missing = await testKeys(2, 7);
    const ct = await encryptContainer(utf8('secret'), keys);
    await expectDecryptError(decryptContainer(ct, other), 'auth');
    await expectDecryptError(decryptContainer(ct, missing), 'unknown-key');
  });

  it('keeps plaintext out of the ciphertext', async () => {
    const keys = await testKeys();
    const ct = await encryptContainer(utf8('a very recognisable sentence'), keys);
    expect(fromUtf8(ct)).not.toContain('recognisable');
  });

  it('rejects non-containers as format errors', async () => {
    const keys = await testKeys();
    await expectDecryptError(decryptContainer(utf8('plain text, nothing to see'), keys), 'format');
  });
});

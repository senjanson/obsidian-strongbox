import { describe, expect, it } from 'vitest';
import { newKdfParams } from '../../src/crypto/kdf';
import {
  DecryptError,
} from '../../src/crypto/container';
import {
  INLINE_BLOCK_RE, decryptInline, encryptInlineWithMaster, encryptInlineWithPassword, findInlineBlocks, inlineBlockMode, parseInlineBlock,
} from '../../src/crypto/inline';
import { FAST_ARGON, testKeys } from '../helpers/keys';

describe('inline blocks', () => {
  it('encrypts with the master key into a single-line code span that names the key id', async () => {
    const keys = await testKeys(42);
    const secret = 'my *bank* PIN is 1234\nsecond line with `code` and [[link]]';
    const token = await encryptInlineWithMaster(secret, keys);
    expect(token).toMatch(/^`strongbox:v1:k42:[A-Za-z0-9_-]+`$/);
    expect(token).not.toContain('\n');
    expect(token).not.toContain('1234');
    expect(inlineBlockMode(token)).toBe('master');
    expect(await decryptInline(token, { keys })).toBe(secret);
    // Without backticks too.
    expect(await decryptInline(token.slice(1, -1), { keys })).toBe(secret);
  });

  it('encrypts with its own password, carrying salt and KDF parameters (Argon2id and PBKDF2)', async () => {
    for (const kdf of [newKdfParams('argon2id', FAST_ARGON), newKdfParams('pbkdf2-sha256', { iterations: 1000 })]) {
      const token = await encryptInlineWithPassword('只给自己看的一句话', 'block pw', kdf);
      expect(inlineBlockMode(token)).toBe('password');
      const parsed = parseInlineBlock(token);
      expect(parsed.mode).toBe('password');
      if (parsed.mode === 'password') expect(parsed.kdf).toEqual(kdf);
      expect(await decryptInline(token, { password: 'block pw' })).toBe('只给自己看的一句话');
      await expect(decryptInline(token, { password: 'wrong' })).rejects.toBeInstanceOf(DecryptError);
      await expect(decryptInline(token, {})).rejects.toMatchObject({ kind: 'unknown-key' });
    }
  });

  it('binds the parameters: changing the key id or KDF settings breaks it', async () => {
    const keys = await testKeys(7);
    const token = await encryptInlineWithMaster('x', keys);
    const k8 = await testKeys(8, 7); // same key bytes, different id
    await expect(decryptInline(token.replace('k7:', 'k8:'), { keys: k8 })).rejects.toMatchObject({ kind: 'auth' });

    const kdf = newKdfParams('pbkdf2-sha256', { iterations: 1000 });
    const pw = await encryptInlineWithPassword('y', 'pw', kdf);
    await expect(decryptInline(pw.replace(':p1000:', ':p1001:'), { password: 'pw' })).rejects.toBeInstanceOf(DecryptError);
  });

  it('is found inside surrounding Markdown', async () => {
    const keys = await testKeys(3);
    const a = await encryptInlineWithMaster('one', keys);
    const b = await encryptInlineWithPassword('two', 'pw', newKdfParams('pbkdf2-sha256', { iterations: 1000 }));
    const doc = `# Title\n\nSome text ${a} and **bold** ${b}.\n- item \`ordinary code\`\n`;
    const found = findInlineBlocks(doc);
    expect(found.map((f) => f.token)).toEqual([a, b]);
    expect(doc.slice(found[0].start, found[0].end)).toBe(a);
    expect(new RegExp(INLINE_BLOCK_RE.source).test('`strongbox:v1:k1:`')).toBe(false);
  });

  it('reports malformed blocks as format errors', () => {
    expect(() => parseInlineBlock('`strongbox:v1:k1:AAAA`')).toThrow(DecryptError);
    expect(() => parseInlineBlock('`strongbox:v2:k1:AAAA`')).toThrow(DecryptError);
    expect(inlineBlockMode('`hello`')).toBeNull();
  });
});

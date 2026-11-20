import { describe, expect, it } from 'vitest';
import { utf8 } from '../../src/crypto/bytes';
import { decryptContainer, encryptContainer } from '../../src/crypto/container';
import { SHELL_FIRST_LINE, looksLikeShell, unwrapShell, unwrapShellBytes, wrapShell } from '../../src/crypto/text-shell';
import { detectForm, textLooksEncrypted } from '../../src/vault/codec';
import { testKeys } from '../helpers/keys';

describe('text shell', () => {
  it('starts with a readable warning line, then base64 lines of at most 76 chars', async () => {
    const keys = await testKeys();
    const ct = await encryptContainer(utf8('# Diary\n\nDear diary…'.repeat(50)), keys);
    const shell = wrapShell(ct);
    const lines = shell.split('\n');
    expect(lines[0]).toBe(SHELL_FIRST_LINE);
    expect(lines[0]).toContain('请勿手动编辑');
    expect(lines[0]).toContain('do not edit it by hand');
    for (const l of lines.slice(1)) expect(l.length).toBeLessThanOrEqual(76);
    expect(shell).not.toContain('Diary');
    const inner = unwrapShell(shell)!;
    expect(inner).toEqual(ct);
    expect(await decryptContainer(inner, keys)).toEqual(utf8('# Diary\n\nDear diary…'.repeat(50)));
  });

  it('survives CRLF line endings (e.g. after a Windows sync tool)', async () => {
    const keys = await testKeys();
    const ct = await encryptContainer(utf8('x'), keys);
    const crlf = wrapShell(ct).replace(/\n/g, '\r\n');
    expect(unwrapShell(crlf)).toEqual(ct);
  });

  it('treats a note that merely quotes the first line as plain text', () => {
    const note = SHELL_FIRST_LINE + '\nThis note documents the format; it is not encrypted.\n';
    expect(looksLikeShell(note)).toBe(true);
    expect(unwrapShell(note)).toBeNull();
    expect(textLooksEncrypted(note)).toBeNull();
    expect(detectForm(utf8(note))).toBeNull();
  });

  it('is recognised from bytes and from strings', async () => {
    const keys = await testKeys();
    const ct = await encryptContainer(utf8('hi'), keys);
    const shell = wrapShell(ct);
    expect(detectForm(utf8(shell))).toBe('text');
    expect(unwrapShellBytes(utf8(shell))).toEqual(ct);
    expect(textLooksEncrypted(shell)).toBe('text');
    expect(detectForm(ct)).toBe('binary');
    // A binary container read as UTF-8 text.
    expect(textLooksEncrypted(new TextDecoder().decode(ct))).toBe('binary');
  });
});

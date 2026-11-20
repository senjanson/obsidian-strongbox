import { beforeEach, describe, expect, it } from 'vitest';
import { fromUtf8, utf8 } from '../../src/crypto/bytes';
import { decryptContainer, encryptContainer } from '../../src/crypto/container';
import { MasterKeys } from '../../src/crypto/keyring';
import { SHELL_PREFIX, wrapShell } from '../../src/crypto/text-shell';
import { AdapterHook, LockedError } from '../../src/vault/adapter-hook';
import { FileCodec, containerOf, detectForm } from '../../src/vault/codec';
import { ProtectionPolicy } from '../../src/vault/rules';
import { FakeAdapter } from '../helpers/fake-adapter';
import { testKeys } from '../helpers/keys';

const SECRET = 'TOP-SECRET-CONTENT';

describe('adapter hook', () => {
  let adapter: FakeAdapter;
  let keys: MasterKeys | null;
  let policy: ProtectionPolicy;
  let hook: AdapterHook;
  let blocked: string[];
  let storedKeys: MasterKeys;

  beforeEach(async () => {
    adapter = new FakeAdapter();
    storedKeys = await testKeys(5);
    keys = storedKeys;
    blocked = [];
    policy = new ProtectionPolicy({
      configDir: '.obsidian',
      rules: [{ type: 'folder', path: 'Private' }],
      excludes: [],
      textExtensions: ['md', 'canvas', 'base'],
    });
    const codec = new FileCodec(() => keys, (p) => policy.isTextPath(p), 32);
    hook = new AdapterHook(adapter, {
      policy,
      codec,
      isUnlocked: () => keys !== null,
      onBlockedWrite: (p) => blocked.push(p),
    });
    hook.install();
  });

  const lock = () => { keys = null; };
  const unlock = () => { keys = storedKeys; };

  it('installs over the six methods and restores them exactly', () => {
    const before = new FakeAdapter();
    const protoRead = before.read;
    const ownWrite = async () => {};
    (before as any).write = ownWrite;
    const h = new AdapterHook(before, { policy, codec: new FileCodec(() => keys, () => true), isUnlocked: () => true });
    h.install();
    expect(before.read).not.toBe(protoRead);
    expect((before as any).write).not.toBe(ownWrite);
    h.uninstall();
    expect(Object.prototype.hasOwnProperty.call(before, 'read')).toBe(false);
    expect(before.read).toBe(protoRead);
    expect((before as any).write).toBe(ownWrite);
  });

  it('unlocked: writes to protected paths are encrypted on disk, reads give plaintext', async () => {
    await adapter.write('Private/diary.md', SECRET + '\n'.repeat(3) + SECRET);
    expect(adapter.containsPlaintext(SECRET)).toEqual([]);
    expect(adapter.text('Private/diary.md').startsWith(SHELL_PREFIX)).toBe(true);
    expect(await adapter.read('Private/diary.md')).toBe(SECRET + '\n'.repeat(3) + SECRET);

    const img = new Uint8Array([1, 2, 3, 4, 5, 250]);
    await adapter.writeBinary('Private/pic.png', img.buffer);
    expect(detectForm(adapter.bytes('Private/pic.png'))).toBe('binary');
    expect(new Uint8Array(await adapter.readBinary('Private/pic.png'))).toEqual(img);
    // A note read as binary decrypts as well.
    expect(fromUtf8(new Uint8Array(await adapter.readBinary('Private/diary.md')))).toContain(SECRET);
  });

  it('reads a binary-container text file even where the native read refuses non-UTF-8 (iOS)', async () => {
    // The iOS app throws instead of returning garbled text for bytes that are not UTF-8.
    class StrictAdapter extends FakeAdapter {
      async read(path: string): Promise<string> {
        return new TextDecoder('utf-8', { fatal: true }).decode(this.bytes(path));
      }
    }
    const strict = new StrictAdapter();
    const h = new AdapterHook(strict, {
      policy,
      codec: new FileCodec(() => keys, (p) => policy.isTextPath(p), 32),
      isUnlocked: () => keys !== null,
    });
    h.install();
    await strict.write('Private/list.txt', SECRET);
    expect(detectForm(strict.bytes('Private/list.txt'))).toBe('binary');
    expect(await strict.read('Private/list.txt')).toBe(SECRET);
    // Locked: the native error comes through unchanged.
    lock();
    await expect(strict.read('Private/list.txt')).rejects.toThrow();
    unlock();
    // A plain non-UTF-8 file keeps the native error too.
    await strict.writeBinary('Public/raw.bin', new Uint8Array([0xff, 0xfe, 0x00]).buffer);
    await expect(strict.read('Public/raw.bin')).rejects.toThrow();
  });

  it('leaves unprotected and excluded paths alone', async () => {
    await adapter.write('Public/a.md', SECRET);
    await adapter.write('.obsidian/app.json', '{}');
    expect(adapter.text('Public/a.md')).toBe(SECRET);
    expect(adapter.text('.obsidian/app.json')).toBe('{}');
  });

  it('keeps encrypting a file that is already encrypted, even outside the rules (moved out)', async () => {
    await adapter.write('Private/n.md', 'v1');
    const onDisk = adapter.bytes('Private/n.md');
    adapter.files.delete('Private/n.md');
    adapter.seed('Elsewhere/n.md', onDisk);
    expect(await adapter.read('Elsewhere/n.md')).toBe('v1');
    await adapter.write('Elsewhere/n.md', SECRET);
    expect(adapter.containsPlaintext(SECRET)).toEqual([]);
    expect(await adapter.read('Elsewhere/n.md')).toBe(SECRET);
  });

  it('detects an encrypted file it has not seen before by reading the disk', async () => {
    const ct = await encryptContainer(utf8('x'), storedKeys);
    adapter.seed('Loose/x.md', wrapShell(ct));
    await adapter.write('Loose/x.md', SECRET);
    expect(adapter.containsPlaintext(SECRET)).toEqual([]);
  });

  it('append and process keep the file encrypted', async () => {
    await adapter.write('Private/log.md', 'line1\n');
    await adapter.append('Private/log.md', SECRET + '\n');
    expect(adapter.containsPlaintext(SECRET)).toEqual([]);
    expect(await adapter.read('Private/log.md')).toBe('line1\n' + SECRET + '\n');
    const out = await adapter.process('Private/log.md', (s) => s.toUpperCase());
    expect(out).toBe('LINE1\n' + SECRET + '\n');
    expect(adapter.containsPlaintext('LINE1')).toEqual([]);
    expect(await adapter.read('Private/log.md')).toBe(out);
    // append to a new protected file
    await adapter.append('Private/new.md', SECRET);
    expect(adapter.containsPlaintext(SECRET)).toEqual([]);
  });

  it('locked: reads return the raw ciphertext', async () => {
    await adapter.write('Private/diary.md', SECRET);
    lock();
    const raw = await adapter.read('Private/diary.md');
    expect(raw.startsWith(SHELL_PREFIX)).toBe(true);
    expect(raw).not.toContain(SECRET);
  });

  it('locked: every kind of write to a protected path is refused and nothing reaches the disk', async () => {
    await adapter.write('Private/diary.md', 'old');
    const before = adapter.bytes('Private/diary.md');
    lock();
    adapter.writes = [];
    await expect(adapter.write('Private/diary.md', SECRET)).rejects.toBeInstanceOf(LockedError);
    await expect(adapter.write('Private/new.md', SECRET)).rejects.toBeInstanceOf(LockedError);
    await expect(adapter.writeBinary('Private/new.png', utf8(SECRET).buffer)).rejects.toBeInstanceOf(LockedError);
    await expect(adapter.append('Private/diary.md', SECRET)).rejects.toBeInstanceOf(LockedError);
    await expect(adapter.process('Private/diary.md', () => SECRET)).rejects.toBeInstanceOf(LockedError);
    expect(adapter.writes).toEqual([]);
    expect(adapter.containsPlaintext(SECRET)).toEqual([]);
    expect(adapter.bytes('Private/diary.md')).toEqual(before);
    expect(adapter.files.has('Private/new.md')).toBe(false);
    expect(blocked).toContain('Private/diary.md');
    expect(blocked).toContain('Private/new.md');
  });

  it('locked: writes over an already-encrypted file outside the rules are refused too', async () => {
    const ct = await encryptContainer(utf8('x'), storedKeys);
    adapter.seed('Loose/x.md', wrapShell(ct));
    lock();
    await expect(adapter.write('Loose/x.md', SECRET)).rejects.toBeInstanceOf(LockedError);
    expect(adapter.containsPlaintext(SECRET)).toEqual([]);
  });

  it('locked: ciphertext copied as-is (e.g. by a sync tool) may still be written', async () => {
    const ct = await encryptContainer(utf8(SECRET), storedKeys);
    lock();
    await adapter.write('Private/synced.md', wrapShell(ct));
    await adapter.writeBinary('Private/synced.png', ct.buffer);
    unlock();
    expect(await adapter.read('Private/synced.md')).toBe(SECRET);
    expect(fromUtf8(new Uint8Array(await adapter.readBinary('Private/synced.png')))).toBe(SECRET);
  });

  it('refuses hand-edited ciphertext (same file salt, different bytes) so the file is not destroyed', async () => {
    await adapter.write('Private/diary.md', SECRET);
    const shell = adapter.text('Private/diary.md');
    lock();
    const lines = shell.split('\n');
    const last = lines.length - 2; // final base64 line (the text ends with a newline)
    lines[last] = (lines[last][0] === 'A' ? 'B' : 'A') + lines[last].slice(1);
    await expect(adapter.write('Private/diary.md', lines.join('\n'))).rejects.toBeInstanceOf(LockedError);
    expect(adapter.text('Private/diary.md')).toBe(shell);
    // Writing back the identical ciphertext is harmless and allowed.
    await adapter.write('Private/diary.md', shell);
    unlock();
    expect(await adapter.read('Private/diary.md')).toBe(SECRET);
  });

  it('locked: unprotected paths still work normally', async () => {
    lock();
    await adapter.write('Public/a.md', 'hello');
    expect(await adapter.read('Public/a.md')).toBe('hello');
  });

  it('guards hidden-name placeholders while locked', async () => {
    const h2 = new AdapterHook(new FakeAdapter(), {
      policy,
      codec: new FileCodec(() => null, () => true),
      isUnlocked: () => false,
      isGuardedWhileLocked: (p) => p.includes('sbx-'),
    });
    h2.install();
    await expect(h2.write('Notes/sbx-0011223344556677/a.md', SECRET)).rejects.toBeInstanceOf(LockedError);
  });

  it('decrypt failures surface as errors instead of garbage', async () => {
    const otherKeys = await testKeys(5, 99);
    const ct = await encryptContainer(utf8(SECRET), otherKeys);
    adapter.seed('Private/foreign.md', wrapShell(ct));
    await expect(adapter.read('Private/foreign.md')).rejects.toMatchObject({ kind: 'auth' });
  });

  it('round-trips through the binary container when a note is stored in binary form', async () => {
    const ct = await encryptContainer(utf8('binary form note'), storedKeys);
    adapter.seed('Private/bin.md', ct);
    expect(await adapter.read('Private/bin.md')).toBe('binary form note');
    const raw = containerOf(adapter.bytes('Private/bin.md'))!;
    expect(fromUtf8(await decryptContainer(raw, storedKeys))).toBe('binary form note');
  });

  it('is a pass-through after uninstall', async () => {
    hook.uninstall();
    await adapter.write('Private/after.md', SECRET);
    expect(adapter.text('Private/after.md')).toBe(SECRET);
  });

  it('a user-excluded path that is already encrypted stays encrypted (no plaintext overwrite)', async () => {
    await adapter.write('Private/x.md', 'v1');
    policy.update({ excludes: ['Private'] });
    expect(await adapter.read('Private/x.md')).toBe('v1');
    await adapter.write('Private/x.md', SECRET);
    expect(adapter.containsPlaintext(SECRET)).toEqual([]);
    expect(await adapter.read('Private/x.md')).toBe(SECRET);
    lock();
    await expect(adapter.write('Private/x.md', 'LEAK')).rejects.toBeInstanceOf(LockedError);
    // New files there are not encrypted (that is what excluding means).
    unlock();
    await adapter.write('Private/plain.md', 'public');
    expect(adapter.text('Private/plain.md')).toBe('public');
  });
});

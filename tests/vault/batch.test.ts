import { beforeEach, describe, expect, it } from 'vitest';
import { fromUtf8, utf8 } from '../../src/crypto/bytes';
import { containerKeyId } from '../../src/crypto/container';
import { decryptInline, encryptInlineWithMaster } from '../../src/crypto/inline';
import { MasterKeys } from '../../src/crypto/keyring';
import { BatchEngine } from '../../src/vault/batch';
import { FileCodec, containerOf, detectForm } from '../../src/vault/codec';
import { decryptTransform, encryptTransform, rekeyTransform } from '../../src/vault/transforms';
import { CrashError, FakeAdapter } from '../helpers/fake-adapter';
import { testKeys } from '../helpers/keys';

const JOURNAL = '.obsidian/plugins/strongbox/batch-journal.log';
const TMP = '.obsidian/plugins/strongbox/tmp';
const isText = (p: string) => p.endsWith('.md');

function seedVault(a: FakeAdapter, n: number): string[] {
  const paths: string[] = [];
  for (let i = 0; i < n; i++) {
    const p = i % 3 === 0 ? `Vault/img${i}.png` : `Vault/note${i}.md`;
    a.seed(p, `content of file ${i} SECRET-${i}`);
    paths.push(p);
  }
  return paths;
}

describe('batch engine', () => {
  let adapter: FakeAdapter;
  let keys: MasterKeys;
  let codec: FileCodec;
  let engine: BatchEngine;

  beforeEach(async () => {
    adapter = new FakeAdapter();
    keys = await testKeys(1);
    codec = new FileCodec(() => keys, isText, 16);
    engine = new BatchEngine(adapter, JOURNAL, TMP);
  });

  it('encrypts every file, verifies, cleans up the journal and temp files', async () => {
    const paths = seedVault(adapter, 12);
    const progress: number[] = [];
    const res = await engine.start('encrypt', paths, encryptTransform(codec), {
      concurrency: 4,
      onProgress: (p) => progress.push(p.processed),
    });
    expect(res).toMatchObject({ total: 12, changed: 12, skipped: 0, failed: [], cancelled: false });
    expect(adapter.containsPlaintext('SECRET-')).toEqual([]);
    for (const p of paths) {
      expect(detectForm(adapter.bytes(p))).toBe(isText(p) ? 'text' : 'binary');
      expect(fromUtf8(await codec.decode(adapter.bytes(p)))).toMatch(/^content of file \d+/);
    }
    expect(await adapter.exists(JOURNAL)).toBe(false);
    expect([...adapter.files.keys()].filter((p) => p.startsWith(TMP))).toEqual([]);
    expect(progress.at(-1)).toBe(12);
  });

  it('removes a temp copy left by a crash after "done" was logged', async () => {
    const paths = seedVault(adapter, 3);
    // As if the previous run crashed between logging "done" for file 1 and removing its copy.
    await adapter.mkdir(TMP);
    await adapter.write(`${TMP}/1.tmp`, 'stale ciphertext');
    const res = await engine.start('encrypt', paths, encryptTransform(codec), { concurrency: 2 });
    expect(res).toMatchObject({ changed: 3, failed: [], cancelled: false });
    expect([...adapter.files.keys()].filter((p) => p.startsWith(TMP + '/'))).toEqual([]);
  });

  it('skips files that are already in the target state', async () => {
    const paths = seedVault(adapter, 4);
    await engine.start('encrypt', paths.slice(0, 2), encryptTransform(codec), { concurrency: 2 });
    const res = await engine.start('encrypt', paths, encryptTransform(codec), { concurrency: 2 });
    expect(res).toMatchObject({ changed: 2, skipped: 2 });
  });

  it('decrypts back to the original bytes', async () => {
    const paths = seedVault(adapter, 6);
    const before = new Map(paths.map((p) => [p, adapter.bytes(p).slice()]));
    await engine.start('encrypt', paths, encryptTransform(codec), { concurrency: 3 });
    const res = await engine.start('decrypt', paths, decryptTransform(codec), { concurrency: 3 });
    expect(res.changed).toBe(6);
    for (const p of paths) expect(adapter.bytes(p)).toEqual(before.get(p));
  });

  it('can be cancelled and resumed later', async () => {
    const paths = seedVault(adapter, 20);
    const ctl = new AbortController();
    const res = await engine.start('encrypt', paths, encryptTransform(codec), {
      concurrency: 1,
      signal: ctl.signal,
      onProgress: (p) => { if (p.processed === 5) ctl.abort(); },
    });
    expect(res.cancelled).toBe(true);
    expect(res.changed).toBe(5);
    const pending = await engine.pending();
    expect(pending).toMatchObject({ op: 'encrypt', total: 20, remaining: 15 });
    await expect(engine.start('encrypt', paths, encryptTransform(codec), { concurrency: 1 })).rejects.toThrow(/unfinished/);

    const resumed = await engine.resume(() => encryptTransform(codec), { concurrency: 4 });
    expect(resumed).toMatchObject({ changed: 15, cancelled: false, failed: [] });
    expect(adapter.containsPlaintext('SECRET-')).toEqual([]);
    expect(await engine.pending()).toBeNull();
  });

  it('recovers from a crash at every point of the write sequence', async () => {
    // Try crashing on each mutating call in turn; after resuming, every file
    // must hold exactly its original plaintext, encrypted.
    let crashes = 0;
    for (let crashAt = 0; crashAt < 40; crashAt++) {
      const a = new FakeAdapter();
      const paths = seedVault(a, 4);
      const originals = new Map(paths.map((p) => [p, fromUtf8(a.bytes(p))]));
      const e = new BatchEngine(a, JOURNAL, TMP);
      a.crashAfter = crashAt;
      let crashed = false;
      try {
        await e.start('encrypt', paths, encryptTransform(codec), { concurrency: 1 });
      } catch (err) {
        expect(err).toBeInstanceOf(CrashError);
        crashed = true;
      }
      // The engine may swallow the error of a single file; the process is dead all the same.
      crashed = crashed || a.dead;
      a.revive();
      if (crashed && (await e.pending())) {
        // A real crash also loses whatever was in flight; resume picks it up.
        await e.resume(() => encryptTransform(codec), { concurrency: 2 });
      } else if (crashed) {
        // Crashed before the journal existed: nothing was changed, start over.
        await e.start('encrypt', paths, encryptTransform(codec), { concurrency: 2 });
      }
      for (const p of paths) {
        const form = detectForm(a.bytes(p));
        expect(form, `crashAt=${crashAt} ${p}`).not.toBeNull();
        expect(fromUtf8(await codec.decode(a.bytes(p))), `crashAt=${crashAt}`).toBe(originals.get(p));
      }
      expect(await e.pending()).toBeNull();
      if (crashed) crashes++;
    }
    // journal write + 5 mutations per file × 4 files + journal removal = 22 crash points.
    expect(crashes).toBe(22);
  });

  it('finishes a file from its verified temporary copy when the original was torn', async () => {
    const paths = seedVault(adapter, 1);
    const p = paths[0];
    // Crash right after "temp" is logged: writes are tmp(1), log temp(2), original(3)…
    // Simulate a torn original instead of a crash.
    const origWriteBinary = adapter.writeBinary.bind(adapter);
    let calls = 0;
    adapter.writeBinary = async (path: string, data: ArrayBuffer) => {
      calls++;
      if (path === p) {
        await origWriteBinary(path, data.slice(0, 10)); // torn write
        throw new CrashError('torn');
      }
      return origWriteBinary(path, data);
    };
    const res = await engine.start('encrypt', paths, encryptTransform(codec), { concurrency: 1 });
    expect(res.failed).toHaveLength(1);
    adapter.writeBinary = origWriteBinary;
    expect(calls).toBeGreaterThan(0);
    const again = await engine.resume(() => encryptTransform(codec), { concurrency: 1 });
    expect(again?.changed).toBe(1);
    expect(fromUtf8(await codec.decode(adapter.bytes(p)))).toBe('content of file 0 SECRET-0');
  });

  it('re-keys containers and inline blocks onto the new key', async () => {
    const oldKeys = keys;
    const paths = seedVault(adapter, 6);
    const inline = await encryptInlineWithMaster('inline secret', oldKeys);
    adapter.seed('Public/plain.md', `public note with ${inline} inside`);
    await engine.start('encrypt', paths, encryptTransform(codec), { concurrency: 2 });

    const newKey = (await testKeys(2, 42)).get(2)!;
    const both = new MasterKeys(2, [[1, oldKeys.get(1)!], [2, newKey]]);
    keys = both;
    const all = [...paths, 'Public/plain.md'];
    const res = await engine.start('rekey', all, rekeyTransform(codec, () => keys, isText), { concurrency: 2 });
    expect(res.changed).toBe(7);
    for (const p of paths) expect(containerKeyId(containerOf(adapter.bytes(p))!)).toBe(2);

    const onlyNew = new MasterKeys(2, [[2, newKey]]);
    keys = onlyNew;
    for (const p of paths) expect(fromUtf8(await codec.decode(adapter.bytes(p)))).toMatch(/^content of file/);
    const plain = adapter.text('Public/plain.md');
    expect(plain.startsWith('public note with `strongbox:v1:k2:')).toBe(true);
    const token = plain.match(/`strongbox:[^`]+`/)![0];
    expect(await decryptInline(token, { keys: onlyNew })).toBe('inline secret');

    // A second run has nothing left to do.
    keys = both;
    const again = await engine.start('rekey', all, rekeyTransform(codec, () => keys, isText), { concurrency: 2 });
    expect(again.changed).toBe(0);
  });

  it('records failures and retries them on resume', async () => {
    const paths = seedVault(adapter, 3);
    let fail = true;
    const flaky = encryptTransform(codec);
    const res = await engine.start('encrypt', paths, async (p, c) => {
      if (fail && p === paths[1]) throw new Error('disk full');
      return flaky(p, c);
    }, { concurrency: 1 });
    expect(res.failed).toEqual([{ path: paths[1], error: 'disk full' }]);
    expect(await engine.pending()).toMatchObject({ remaining: 1 });
    fail = false;
    const again = await engine.resume(() => encryptTransform(codec), { concurrency: 1 });
    expect(again).toMatchObject({ changed: 1, failed: [] });
    expect(await engine.pending()).toBeNull();
  });

  it('discard() completes a half-replaced file from its temp copy before forgetting', async () => {
    const paths = seedVault(adapter, 2);
    // crash right after "temp" was logged for the first file:
    // mutations: journal write(1), tmp write(2), log temp(3), original write(4)
    adapter.crashAfter = 3;
    await expect(engine.start('encrypt', paths, encryptTransform(codec), { concurrency: 1 })).rejects.toBeInstanceOf(CrashError);
    adapter.revive();
    await engine.discard();
    expect(await engine.pending()).toBeNull();
    expect(detectForm(adapter.bytes(paths[0]))).not.toBeNull();
    expect(fromUtf8(await codec.decode(adapter.bytes(paths[0])))).toBe('content of file 0 SECRET-0');
  });

  /** An IO whose writes to one path are torn (half written, then an error) while `fail` is set. */
  function tornIO(a: FakeAdapter, target: string) {
    const ctl = { fail: false };
    const io: any = {
      read: (p: string) => a.read(p), readBinary: (p: string) => a.readBinary(p),
      write: (p: string, d: string) => a.write(p, d), append: (p: string, d: string) => a.append(p, d),
      exists: (p: string) => a.exists(p), remove: (p: string) => a.remove(p), mkdir: (p: string) => a.mkdir(p),
      writeBinary: async (p: string, d: ArrayBuffer) => {
        if (ctl.fail && p === target) {
          await a.writeBinary(p, d.slice(0, Math.floor(d.byteLength / 2)));
          throw new Error('ENOSPC torn write');
        }
        return a.writeBinary(p, d);
      },
    };
    return { io, ctl };
  }

  it('keeps the verified temp copy when finishing from it fails again, and recovers later', async () => {
    adapter.seed('a.png', 'X'.repeat(500) + 'SECRET');
    const { io, ctl } = tornIO(adapter, 'a.png');
    const e = new BatchEngine(io, JOURNAL, TMP);
    ctl.fail = true;
    expect((await e.start('encrypt', ['a.png'], encryptTransform(codec), { concurrency: 1 })).failed).toHaveLength(1);
    expect((await e.resume(() => encryptTransform(codec), { concurrency: 1 }))!.failed).toHaveLength(1);
    expect([...adapter.files.keys()].some((p) => p.startsWith(TMP))).toBe(true);
    ctl.fail = false;
    const r = await e.resume(() => encryptTransform(codec), { concurrency: 1 });
    expect(r).toMatchObject({ changed: 1, failed: [] });
    expect(fromUtf8(await codec.decode(adapter.bytes('a.png')))).toBe('X'.repeat(500) + 'SECRET');
  });

  it('discard() refuses to drop the temp copy when the original cannot be completed', async () => {
    adapter.seed('a.png', 'X'.repeat(500) + 'SECRET');
    const { io, ctl } = tornIO(adapter, 'a.png');
    const e = new BatchEngine(io, JOURNAL, TMP);
    ctl.fail = true;
    await e.start('encrypt', ['a.png'], encryptTransform(codec), { concurrency: 1 });
    await expect(e.discard()).rejects.toThrow(/ENOSPC/);
    expect(await e.pending()).not.toBeNull();
    ctl.fail = false;
    await e.discard();
    expect(fromUtf8(await codec.decode(adapter.bytes('a.png')))).toBe('X'.repeat(500) + 'SECRET');
  });

  it('does not overwrite a file that was edited while the job ran', async () => {
    adapter.seed('n.md', 'old text');
    const base = encryptTransform(codec);
    const res = await engine.start('encrypt', ['n.md'], async (p, cur) => {
      const r = await base(p, cur);
      adapter.seed('n.md', 'edited meanwhile'); // e.g. a save through the hook
      return r;
    }, { concurrency: 1 });
    expect(res.failed).toHaveLength(1);
    expect(adapter.text('n.md')).toBe('edited meanwhile');
  });
});

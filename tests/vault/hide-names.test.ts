import { beforeEach, describe, expect, it } from 'vitest';
import { MasterKeys } from '../../src/crypto/keyring';
import { NameHider, isHiddenName, pathHasHiddenSegment } from '../../src/vault/hide-names';
import { ProtectionPolicy } from '../../src/vault/rules';
import { CrashError, FakeAdapter } from '../helpers/fake-adapter';
import { testKeys } from '../helpers/keys';

const MANIFEST = '.obsidian/plugins/strongbox/names.sbx';
const JOURNAL = '.obsidian/plugins/strongbox/names-journal.log';

function snapshot(a: FakeAdapter): string[] {
  return [...a.files.keys()].filter((p) => !p.startsWith('.obsidian/')).sort();
}

function seed(a: FakeAdapter): void {
  a.seed('Private/Diary/2024-01-01.md', 'd1');
  a.seed('Private/Diary/2024-01-02.md', 'd2');
  a.seed('Private/Health/blood test.pdf', 'pdf');
  a.seed('Private/top.md', 'top');
  a.seed('Work/plan.md', 'plan');
  a.seed('Work/salary.md', 'amount');
  a.seed('.obsidian/app.json', '{}');
}

describe('hiding names', () => {
  let adapter: FakeAdapter;
  let keys: MasterKeys;
  let policy: ProtectionPolicy;
  let hider: NameHider;

  beforeEach(async () => {
    adapter = new FakeAdapter();
    seed(adapter);
    keys = await testKeys(3);
    policy = new ProtectionPolicy({
      configDir: '.obsidian',
      rules: [{ type: 'folder', path: 'Private' }, { type: 'file', path: 'Work/salary.md' }],
      excludes: [],
      textExtensions: ['md'],
    });
    hider = new NameHider(adapter, policy, { manifest: MANIFEST, journal: JOURNAL });
  });

  it('renames every protected file and folder to placeholders and back, contents untouched', async () => {
    const before = snapshot(adapter);
    const contents = new Map(before.map((p) => [p, adapter.text(p)]));
    const n = await hider.hide(keys);
    expect(n).toBe(8); // 5 files + Private, Diary, Health
    const hidden = snapshot(adapter);
    expect(hidden).toContain('Work/plan.md');
    for (const p of hidden.filter((x) => x !== 'Work/plan.md')) {
      expect(p, p).not.toMatch(/Diary|Health|blood|top|salary|Private|2024/);
      expect(pathHasHiddenSegment(p)).toBe(true);
    }
    expect(adapter.files.get('.obsidian/app.json')).toBeDefined();
    // The manifest is encrypted: no real names in it.
    expect(adapter.containsPlaintext('Diary')).toEqual([]);
    expect(adapter.containsPlaintext('salary')).toEqual([]);
    expect(await hider.isHidden()).toBe(true);

    const res = await hider.reveal(keys);
    expect(res).toEqual({ restored: 8, problems: [] });
    expect(snapshot(adapter)).toEqual(before);
    for (const p of before) expect(adapter.text(p)).toBe(contents.get(p));
    expect(await hider.isHidden()).toBe(false);
    expect(await adapter.exists(MANIFEST)).toBe(false);
  });

  it('does not rename a protected folder that contains an excluded path (only its other contents)', async () => {
    policy.update({ excludes: ['Private/Health'] });
    await hider.hide(keys);
    const hidden = snapshot(adapter);
    expect(hidden).toContain('Private/Health/blood test.pdf');
    expect(hidden.some((p) => p.startsWith('Private/sbx-'))).toBe(true);
    await hider.reveal(keys);
  });

  it('recovers from a crash at any point of hiding, then reveals everything', async () => {
    const before = snapshot(adapter);
    for (let crashAt = 0; crashAt < 30; crashAt++) {
      const a = new FakeAdapter();
      seed(a);
      const h = new NameHider(a, policy, { manifest: MANIFEST, journal: JOURNAL });
      a.crashAfter = crashAt;
      try {
        await h.hide(keys);
      } catch (e) {
        expect(e).toBeInstanceOf(CrashError);
      }
      a.revive();
      const res = await h.reveal(keys);
      expect(res.problems, `crashAt=${crashAt}`).toEqual([]);
      expect(snapshot(a), `crashAt=${crashAt}`).toEqual(before);
      expect(await h.isHidden()).toBe(false);
    }
  });

  it('recovers from a crash at any point of revealing', async () => {
    const before = snapshot(adapter);
    for (let crashAt = 0; crashAt < 20; crashAt++) {
      const a = new FakeAdapter();
      seed(a);
      const h = new NameHider(a, policy, { manifest: MANIFEST, journal: JOURNAL });
      await h.hide(keys);
      a.crashAfter = crashAt;
      try {
        await h.reveal(keys);
      } catch (e) {
        expect(e).toBeInstanceOf(CrashError);
      }
      a.revive();
      const res = await h.reveal(keys);
      expect(res.problems, `crashAt=${crashAt}`).toEqual([]);
      expect(snapshot(a), `crashAt=${crashAt}`).toEqual(before);
    }
  });

  it('uses the backup manifest when the main one is damaged', async () => {
    const before = snapshot(adapter);
    await hider.hide(keys);
    adapter.files.set(MANIFEST, new Uint8Array([1, 2, 3]));
    const res = await hider.reveal(keys);
    expect(res.problems).toEqual([]);
    expect(snapshot(adapter)).toEqual(before);
  });

  it('keeps the manifest and reports a conflict instead of guessing', async () => {
    await hider.hide(keys);
    adapter.seed('Work/salary.md', 'created while locked');
    const res = await hider.reveal(keys);
    expect(res.problems).toHaveLength(1);
    expect(await hider.isHidden()).toBe(true);
    const steps = await hider.describe(keys);
    expect(steps!.some((s) => s.from === 'Work/salary.md')).toBe(true);
  });

  it('refuses to open the manifest with the wrong key and keeps it', async () => {
    await hider.hide(keys);
    const res = await hider.reveal(await testKeys(3, 99));
    expect(res.problems).toHaveLength(1);
    expect(await hider.isHidden()).toBe(true);
    expect((await hider.reveal(keys)).problems).toEqual([]);
  });

  it('recognises placeholder names', () => {
    expect(isHiddenName('sbx-0123456789abcdef')).toBe(true);
    expect(isHiddenName('sbx-0123')).toBe(false);
    expect(pathHasHiddenSegment('a/sbx-0123456789abcdef/b.md')).toBe(true);
  });
});

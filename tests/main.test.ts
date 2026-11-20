import { beforeEach, describe, expect, it } from 'vitest';
import { Modal, Notice } from 'obsidian';
import StrongboxPlugin from '../src/main';
import { LockedError } from '../src/vault/adapter-hook';
import { detectForm } from '../src/vault/codec';
import { FakeAdapter } from './helpers/fake-adapter';

function fakeApp(adapter: FakeAdapter) {
  return {
    vault: {
      adapter,
      configDir: '.obsidian',
      on: () => ({}),
      getFiles: () => [],
      getAbstractFileByPath: () => null,
    },
    workspace: {
      onLayoutReady: (cb: () => void) => cb(),
      on: () => ({}),
      iterateAllLeaves: () => {},
      getLeavesOfType: () => [],
      getActiveFile: () => null,
    },
    metadataCache: { getFileCache: () => null, getFirstLinkpathDest: () => null },
  };
}

describe('plugin wiring (fake Obsidian)', () => {
  let adapter: FakeAdapter;
  let plugin: StrongboxPlugin;

  beforeEach(async () => {
    // The plugin only listens on the document; a bare object is enough here.
    (globalThis as any).document ??= { visibilityState: 'visible', querySelectorAll: () => [] };
    (globalThis as any).activeDocument ??= (globalThis as any).document;
    adapter = new FakeAdapter();
    adapter.seed('Private/diary.md', 'DEAR-DIARY plaintext');
    adapter.seed('Private/photo.png', 'PNG-BYTES');
    adapter.seed('Public/readme.md', 'hello');
    plugin = new StrongboxPlugin(fakeApp(adapter) as any, { id: 'strongbox', dir: '.obsidian/plugins/strongbox' } as any);
    await plugin.onload();
    // Fast KDF so the test does not spend seconds deriving keys.
    plugin.settings.kdfAlgorithm = 'pbkdf2-sha256';
    plugin.settings.pbkdf2Iterations = 1000;
  });

  it('registers the commands', () => {
    const ids = (plugin as any).commands.map((c: any) => c.id);
    for (const id of ['lock', 'unlock', 'encrypt-selection', 'decrypt-at-cursor', 'protect-current-file',
      'unprotect-current-file', 'protect-vault', 'unprotect-vault', 'change-password', 'rekey']) {
      expect(ids).toContain(id);
    }
  });

  it('sets up, encrypts a folder, locks (refusing writes), unlocks and reads plaintext', async () => {
    expect(plugin.isInitialized()).toBe(false);
    await (plugin as any).createKeyringWith('correct horse battery');
    expect(plugin.isUnlocked()).toBe(true);
    const keyring = JSON.parse(adapter.text('.obsidian/plugins/strongbox/keyring.json'));
    expect(keyring.format).toBe('strongbox-keyring');
    expect(adapter.text('.obsidian/plugins/strongbox/keyring.json')).not.toContain('correct horse');

    plugin.settings.rules = [{ type: 'folder', path: 'Private' }];
    await plugin.saveSettings();
    const files = await plugin.listFiles('Private');
    expect(files.sort()).toEqual(['Private/diary.md', 'Private/photo.png']);
    const res = await (plugin as any).runBatch('encrypt', files, (await import('../src/vault/transforms')).encryptTransform(plugin.codec));
    expect(res.changed).toBe(2);
    expect(adapter.containsPlaintext('DEAR-DIARY')).toEqual([]);
    expect(detectForm(adapter.bytes('Private/photo.png'))).toBe('binary');
    expect(await adapter.read('Private/diary.md')).toBe('DEAR-DIARY plaintext');

    await plugin.lock('manual');
    expect(plugin.isUnlocked()).toBe(false);
    await expect(adapter.write('Private/diary.md', 'LEAK')).rejects.toBeInstanceOf(LockedError);
    await expect(adapter.write('Private/new.md', 'LEAK')).rejects.toBeInstanceOf(LockedError);
    expect(adapter.containsPlaintext('LEAK')).toEqual([]);
    expect((await adapter.read('Private/diary.md')).startsWith('STRONGBOX-ENCRYPTED-FILE')).toBe(true);
    await adapter.write('Public/readme.md', 'still writable');

    expect(await (plugin as any).tryUnlock('wrong password')).toBe('wrong');
    expect(await (plugin as any).tryUnlock('correct horse battery')).toBe('ok');
    expect(await adapter.read('Private/diary.md')).toBe('DEAR-DIARY plaintext');
  });

  it('hides names on lock and restores them on unlock when the option is on', async () => {
    await (plugin as any).createKeyringWith('correct horse battery');
    plugin.settings.rules = [{ type: 'folder', path: 'Private' }];
    plugin.settings.hideNames = true;
    await plugin.saveSettings();
    await plugin.lock('manual');
    const visible = [...adapter.files.keys()].filter((p) => !p.startsWith('.obsidian'));
    expect(visible.some((p) => p.includes('diary'))).toBe(false);
    expect(visible).toContain('Public/readme.md');
    // While locked, nothing may be written under a placeholder.
    const placeholder = visible.find((p) => p.startsWith('sbx-'))!;
    await expect(adapter.write(placeholder.split('/')[0] + '/x.md', 'LEAK')).rejects.toBeInstanceOf(LockedError);
    expect(await (plugin as any).tryUnlock('correct horse battery')).toBe('ok');
    expect(adapter.files.has('Private/diary.md')).toBe(true);
    expect(await plugin.hider.isHidden()).toBe(false);
  });

  it('quick password change keeps files readable; re-key moves files to a new master key', async () => {
    await (plugin as any).createKeyringWith('first password');
    plugin.settings.rules = [{ type: 'vault', path: '' }];
    await plugin.saveSettings();
    const { encryptTransform } = await import('../src/vault/transforms');
    await (plugin as any).runBatch('encrypt', await plugin.listFiles(''), encryptTransform(plugin.codec));
    expect(adapter.containsPlaintext('hello')).toEqual([]);
    const oldId = plugin.keyring!.activeKeyId;
    // An encrypted file sitting in Obsidian's trash must be re-keyed too.
    adapter.seed('.trash/old.md', adapter.bytes('Public/readme.md'));

    const { changeKeyringPassword } = await import('../src/crypto/keyring');
    await plugin.saveKeyring(await changeKeyringPassword(plugin.keyring!, 'first password', 'second password', plugin.kdfForNewPassword()));
    await plugin.lock('manual');
    expect(await (plugin as any).tryUnlock('first password')).toBe('wrong');
    expect(await (plugin as any).tryUnlock('second password')).toBe('ok');
    expect(await adapter.read('Public/readme.md')).toBe('hello');

    // Full re-key, driving the same steps rekey() runs after its dialogs.
    const { addMasterKey } = await import('../src/crypto/keyring');
    const added = await addMasterKey(plugin.keyring!, 'second password');
    await plugin.saveKeyring(added.file);
    const keys = plugin.unlockedKeys!;
    keys.set(added.id, added.key);
    keys.activeKeyId = added.id;
    const res = await (plugin as any).runBatch('rekey', await plugin.listFiles('', { everything: true }), (plugin as any).transformFor('rekey'));
    await (plugin as any).finishRekeyIfComplete(res);
    expect(plugin.keyring!.keys.map((k) => k.id)).toEqual([added.id]);
    expect(plugin.keyring!.keys.some((k) => k.id === oldId)).toBe(false);
    await plugin.lock('manual');
    expect(await (plugin as any).tryUnlock('second password')).toBe('ok');
    expect(await adapter.read('Public/readme.md')).toBe('hello');
    expect(await adapter.read('Private/diary.md')).toBe('DEAR-DIARY plaintext');
    const { containerKeyId } = await import('../src/crypto/container');
    const { containerOf } = await import('../src/vault/codec');
    expect(containerKeyId(containerOf(adapter.bytes('.trash/old.md'))!)).toBe(added.id);
  });

  it('restores the adapter on unload, after a grace period that keeps closing editors encrypted', async () => {
    await (plugin as any).createKeyringWith('correct horse battery');
    plugin.settings.rules = [{ type: 'folder', path: 'Private' }];
    await plugin.saveSettings();
    plugin.unloadGraceMs = 20;
    plugin.onunload();
    // During the grace period a late save is still encrypted.
    await adapter.write('Private/late.md', 'LATE-SAVE');
    expect(adapter.containsPlaintext('LATE-SAVE')).toEqual([]);
    await new Promise((r) => setTimeout(r, 60));
    expect(plugin.isUnlocked()).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(adapter, 'read')).toBe(false);
    expect(Notice).toBeDefined();
    expect(Modal).toBeDefined();
  });
});

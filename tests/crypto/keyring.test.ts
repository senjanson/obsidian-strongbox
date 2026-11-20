import { describe, expect, it } from 'vitest';
import { utf8 } from '../../src/crypto/bytes';
import { decryptContainer, encryptContainer } from '../../src/crypto/container';
import { newKdfParams } from '../../src/crypto/kdf';
import {
  KeyringFormatError, WrongPasswordError, addMasterKey, changeKeyringPassword, createKeyring, parseKeyring,
  removeMasterKeys, serializeKeyring, unlockKeyring,
} from '../../src/crypto/keyring';
import { FAST_ARGON } from '../helpers/keys';

const fastArgon = () => newKdfParams('argon2id', FAST_ARGON);
const fastPbkdf2 = () => newKdfParams('pbkdf2-sha256', { iterations: 1000 });

describe('keyring', () => {
  it('creates a keyring that opens with the password and not otherwise', async () => {
    const { file, keys } = await createKeyring('hunter2!', fastArgon());
    const json = serializeKeyring(file);
    expect(json).not.toContain('hunter2');
    const parsed = parseKeyring(json);
    expect(parsed.keys).toHaveLength(1);
    expect(parsed.activeKeyId).toBe(keys.activeKeyId);
    expect(parsed.kdf.alg).toBe('argon2id');

    const reopened = await unlockKeyring(parsed, 'hunter2!');
    const ct = await encryptContainer(utf8('data'), keys);
    expect(await decryptContainer(ct, reopened)).toEqual(utf8('data'));
    await expect(unlockKeyring(parsed, 'hunter3!')).rejects.toBeInstanceOf(WrongPasswordError);
  });

  it('keeps master keys non-extractable', async () => {
    const { keys } = await createKeyring('pw', fastPbkdf2());
    const k = keys.get(keys.activeKeyId)!;
    expect(k.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', k)).rejects.toBeTruthy();
  });

  it('changes the password quickly without changing the master key', async () => {
    const { file, keys } = await createKeyring('old password', fastArgon());
    const ct = await encryptContainer(utf8('kept'), keys);
    const changed = await changeKeyringPassword(file, 'old password', 'new password', fastPbkdf2());
    expect(changed.kdf.alg).toBe('pbkdf2-sha256');
    expect(changed.keys[0].id).toBe(file.keys[0].id);
    expect(changed.keys[0].wrapped).not.toBe(file.keys[0].wrapped);
    await expect(unlockKeyring(changed, 'old password')).rejects.toBeInstanceOf(WrongPasswordError);
    const reopened = await unlockKeyring(changed, 'new password');
    expect(await decryptContainer(ct, reopened)).toEqual(utf8('kept'));
    await expect(changeKeyringPassword(file, 'wrong', 'x', fastPbkdf2())).rejects.toBeInstanceOf(WrongPasswordError);
  });

  it('holds old and new master keys side by side during a re-key, then drops the old one', async () => {
    const { file, keys } = await createKeyring('pw', fastArgon());
    const oldId = file.activeKeyId;
    const oldCt = await encryptContainer(utf8('old'), keys);
    await expect(addMasterKey(file, 'nope')).rejects.toBeInstanceOf(WrongPasswordError);
    const added = await addMasterKey(file, 'pw');
    expect(added.file.keys).toHaveLength(2);
    expect(added.file.activeKeyId).toBe(added.id);
    expect(added.id).not.toBe(oldId);

    const both = await unlockKeyring(parseKeyring(serializeKeyring(added.file)), 'pw');
    expect(both.ids()).toEqual([oldId, added.id].sort((a, b) => a - b));
    const newCt = await encryptContainer(utf8('new'), both);
    expect(await decryptContainer(oldCt, both)).toEqual(utf8('old'));
    expect(await decryptContainer(newCt, both)).toEqual(utf8('new'));

    const pruned = removeMasterKeys(added.file, [oldId, added.id]);
    expect(pruned.keys.map((k) => k.id)).toEqual([added.id]);
    const onlyNew = await unlockKeyring(pruned, 'pw');
    await expect(decryptContainer(oldCt, onlyNew)).rejects.toThrow();
    expect(await decryptContainer(newCt, onlyNew)).toEqual(utf8('new'));
  });

  it('rejects files that are not keyrings or were tampered with', async () => {
    expect(() => parseKeyring('{}')).toThrow(KeyringFormatError);
    expect(() => parseKeyring('not json')).toThrow(KeyringFormatError);
    const { file } = await createKeyring('pw', fastPbkdf2());
    const bad = { ...file, activeKeyId: 12345 };
    expect(() => parseKeyring(JSON.stringify(bad))).toThrow(KeyringFormatError);
    // Swapping the id of a wrapped key breaks its authentication (the id is bound).
    const swapped = { ...file, activeKeyId: 99, keys: [{ ...file.keys[0], id: 99 }] };
    await expect(unlockKeyring(parseKeyring(JSON.stringify(swapped)), 'pw')).rejects.toBeInstanceOf(WrongPasswordError);
  });
});

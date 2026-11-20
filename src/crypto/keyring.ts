/**
 * The keyring: one or more random 256-bit master keys, each wrapped with
 * AES-256-GCM under a key derived from the password. The password is never
 * stored; it is right exactly when the wraps open. Unwrapped master keys are
 * imported as non-extractable HKDF keys and the raw bytes are wiped.
 *
 * Several master keys exist side by side only while a full re-key is under
 * way (old files still use the old key until the batch rewrites them).
 */
import { Bytes, concatBytes, fromBase64, randomBytes, toBase64, utf8, wipe } from "./bytes";
import { KeyProvider } from "./container";
import { KdfParams, deriveAesKey, validateKdfParams } from "./kdf";

export const KEYRING_FORMAT = "strongbox-keyring";
export const KEYRING_VERSION = 1;
const MASTER_KEY_BYTES = 32;
const IV_BYTES = 12;

export interface WrappedKey {
  id: number;
  created: number;
  /** base64(iv || AES-GCM(master key)) */
  wrapped: string;
}

export interface KeyringFile {
  format: typeof KEYRING_FORMAT;
  version: number;
  kdf: KdfParams;
  /** The key new writes use. */
  activeKeyId: number;
  keys: WrappedKey[];
}

export class WrongPasswordError extends Error {
  constructor() {
    super("Wrong password");
    this.name = "WrongPasswordError";
  }
}

export class KeyringFormatError extends Error {}

/** Unlocked master keys, held as non-extractable CryptoKeys. */
export class MasterKeys implements KeyProvider {
  private readonly keys = new Map<number, CryptoKey>();

  constructor(public activeKeyId: number, entries: Iterable<[number, CryptoKey]> = []) {
    for (const [id, key] of entries) this.keys.set(id, key);
  }

  get(id: number): CryptoKey | undefined {
    return this.keys.get(id);
  }

  has(id: number): boolean {
    return this.keys.has(id);
  }

  ids(): number[] {
    return [...this.keys.keys()].sort((a, b) => a - b);
  }

  set(id: number, key: CryptoKey): void {
    this.keys.set(id, key);
  }

  delete(id: number): void {
    this.keys.delete(id);
  }

  /** Drops every reference (the CryptoKeys become garbage). */
  clear(): void {
    this.keys.clear();
  }
}

function wrapAad(id: number): Bytes {
  return utf8(`${KEYRING_FORMAT}/v${KEYRING_VERSION}/key/${id}`);
}

async function importMaster(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as Bytes, "HKDF", false, ["deriveKey", "deriveBits"]);
}

async function wrapKey(wrappingKey: CryptoKey, id: number, raw: Uint8Array): Promise<string> {
  const iv = randomBytes(IV_BYTES);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: wrapAad(id) },
    wrappingKey,
    raw as Bytes,
  );
  return toBase64(concatBytes(iv, new Uint8Array(ct)));
}

async function unwrapKey(wrappingKey: CryptoKey, entry: WrappedKey): Promise<Bytes> {
  const blob = fromBase64(entry.wrapped);
  if (blob.length !== IV_BYTES + MASTER_KEY_BYTES + 16) throw new KeyringFormatError("Bad wrapped key");
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: blob.slice(0, IV_BYTES), additionalData: wrapAad(entry.id) },
      wrappingKey,
      blob.slice(IV_BYTES),
    );
    return new Uint8Array(pt);
  } catch {
    throw new WrongPasswordError();
  }
}

export function parseKeyring(json: string): KeyringFile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new KeyringFormatError("Keyring is not valid JSON");
  }
  if (!isRecord(parsed) || parsed.format !== KEYRING_FORMAT) throw new KeyringFormatError("Not a Strongbox keyring");
  const o = parsed;
  if (o.version !== KEYRING_VERSION) throw new KeyringFormatError(`Unsupported keyring version ${String(o.version)}`);
  const kdf = validateKdfParams(o.kdf);
  if (!Array.isArray(o.keys) || o.keys.length === 0) throw new KeyringFormatError("Keyring has no keys");
  const keys: WrappedKey[] = (o.keys as unknown[]).map((k) => {
    if (!isRecord(k) || !isKeyId(k.id) || typeof k.wrapped !== "string") {
      throw new KeyringFormatError("Bad key entry");
    }
    return { id: k.id, created: Number(k.created) || 0, wrapped: k.wrapped };
  });
  if (new Set(keys.map((k) => k.id)).size !== keys.length) throw new KeyringFormatError("Duplicate key id");
  const activeKeyId = o.activeKeyId;
  if (!isKeyId(activeKeyId) || !keys.some((k) => k.id === activeKeyId)) throw new KeyringFormatError("Active key is missing");
  return { format: KEYRING_FORMAT, version: KEYRING_VERSION, kdf, activeKeyId, keys };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isKeyId(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 0xffffffff;
}

export function serializeKeyring(file: KeyringFile): string {
  return JSON.stringify(file, null, 2) + "\n";
}

/** Creates a keyring with one fresh master key. */
export async function createKeyring(
  password: string,
  kdf: KdfParams,
  now: number = Date.now(),
): Promise<{ file: KeyringFile; keys: MasterKeys }> {
  const wrappingKey = await deriveAesKey(password, kdf);
  const raw = randomBytes(MASTER_KEY_BYTES);
  // Random 32-bit ids, so keys from different keyrings rarely collide.
  const id = randomId(new Set());
  try {
    const wrapped = await wrapKey(wrappingKey, id, raw);
    const keys = new MasterKeys(id, [[id, await importMaster(raw)]]);
    return {
      file: { format: KEYRING_FORMAT, version: KEYRING_VERSION, kdf, activeKeyId: id, keys: [{ id, created: now, wrapped }] },
      keys,
    };
  } finally {
    wipe(raw);
  }
}

function randomId(taken: Set<number>): number {
  for (;;) {
    const b = randomBytes(4);
    const id = ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
    if (id !== 0 && !taken.has(id)) return id;
  }
}

/** Opens every key in the keyring. Throws WrongPasswordError on a bad password. */
export async function unlockKeyring(file: KeyringFile, password: string): Promise<MasterKeys> {
  const wrappingKey = await deriveAesKey(password, file.kdf);
  const keys = new MasterKeys(file.activeKeyId);
  for (const entry of file.keys) {
    const raw = await unwrapKey(wrappingKey, entry);
    try {
      keys.set(entry.id, await importMaster(raw));
    } finally {
      wipe(raw);
    }
  }
  return keys;
}

/**
 * Quick password change: re-wraps the same master keys under a key derived
 * from the new password (with new KDF parameters and salt). Files are not
 * touched.
 */
export async function changeKeyringPassword(
  file: KeyringFile,
  oldPassword: string,
  newPassword: string,
  newKdf: KdfParams,
): Promise<KeyringFile> {
  const oldWrap = await deriveAesKey(oldPassword, file.kdf);
  const newWrap = await deriveAesKey(newPassword, newKdf);
  const keys: WrappedKey[] = [];
  for (const entry of file.keys) {
    const raw = await unwrapKey(oldWrap, entry);
    try {
      keys.push({ id: entry.id, created: entry.created, wrapped: await wrapKey(newWrap, entry.id, raw) });
    } finally {
      wipe(raw);
    }
  }
  return { ...file, kdf: newKdf, keys };
}

/**
 * Adds a new master key (for a full re-key) and makes it the active one.
 * The password must open the existing keys.
 */
export async function addMasterKey(
  file: KeyringFile,
  password: string,
  now: number = Date.now(),
): Promise<{ file: KeyringFile; id: number; key: CryptoKey }> {
  const wrap = await deriveAesKey(password, file.kdf);
  // Proves the password before anything changes.
  wipe(await unwrapKey(wrap, file.keys[0]));
  const id = randomId(new Set(file.keys.map((k) => k.id)));
  const raw = randomBytes(MASTER_KEY_BYTES);
  try {
    const wrapped = await wrapKey(wrap, id, raw);
    const key = await importMaster(raw);
    return { file: { ...file, activeKeyId: id, keys: [...file.keys, { id, created: now, wrapped }] }, id, key };
  } finally {
    wipe(raw);
  }
}

/** Drops keys that no file uses any more. The active key is always kept. */
export function removeMasterKeys(file: KeyringFile, ids: number[]): KeyringFile {
  const drop = new Set(ids.filter((id) => id !== file.activeKeyId));
  return { ...file, keys: file.keys.filter((k) => !drop.has(k.id)) };
}

/** For the import check: a keyring JSON from a backup, validated. */
export function isKeyringJson(json: string): boolean {
  try {
    parseKeyring(json);
    return true;
  } catch {
    return false;
  }
}

import { MasterKeys } from '../../src/crypto/keyring';

/** A master key for tests, built without a password. */
export async function testKeys(id = 1, seed = 7): Promise<MasterKeys> {
  const raw = new Uint8Array(32).fill(seed);
  const key = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey', 'deriveBits']);
  return new MasterKeys(id, [[id, key]]);
}

/** Fast KDF parameters so tests do not spend seconds on Argon2id. */
export const FAST_ARGON = { memKiB: 64, iterations: 1, parallelism: 1 };

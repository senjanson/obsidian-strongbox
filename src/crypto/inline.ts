/**
 * Inline encrypted blocks for selected text.
 *
 * A block is an inline code span, so Markdown never rewrites what is inside
 * it (no emphasis, no escaping, no link parsing), and it fits on one line:
 *
 *   master key:  `strongbox:v1:k<keyId>:<data>`
 *   password:    `strongbox:v1:p:<kdf>:<salt>:<data>`
 *
 * <kdf> is `a<memKiB>.<iterations>.<parallelism>` for Argon2id or
 * `p<iterations>` for PBKDF2-SHA-256; <salt> and <data> are base64url.
 * With the master key, data = salt(16) || iv(12) || AES-GCM ciphertext and
 * the key is HKDF(master, salt, "strongbox/inline/v1"). With a password,
 * data = iv(12) || ciphertext and the key is the KDF output itself. The
 * additional data is everything before <data> ("strongbox:v1:...:"), so the
 * parameters cannot be swapped without breaking authentication.
 */
import { Bytes, concatBytes, fromBase64, fromBase64Url, fromUtf8, randomBytes, toBase64, toBase64Url, utf8, wipe } from "./bytes";
import { DecryptError, KeyProvider } from "./container";
import { KdfParams, deriveKeyBytes, validateKdfParams } from "./kdf";

export const INLINE_PREFIX = "strongbox:v1:";
const HKDF_INFO = utf8("strongbox/inline/v1");
const SALT_BYTES = 16;
const IV_BYTES = 12;

/** Matches a whole block including the backticks. Global: reset lastIndex before reuse. */
export const INLINE_BLOCK_RE = /`strongbox:v1:(k\d+|p:(?:a\d+\.\d+\.\d+|p\d+):[A-Za-z0-9_-]+):([A-Za-z0-9_-]+)`/g;

export type InlineBlock =
  | { mode: "master"; keyId: number; header: string; data: Bytes }
  | { mode: "password"; kdf: KdfParams; header: string; data: Bytes };

export function findInlineBlocks(text: string): { start: number; end: number; token: string }[] {
  const re = new RegExp(INLINE_BLOCK_RE.source, "g");
  const out: { start: number; end: number; token: string }[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) out.push({ start: m.index, end: m.index + m[0].length, token: m[0] });
  return out;
}

/** Parses a block (with or without its backticks). Throws DecryptError("format") when malformed. */
export function parseInlineBlock(token: string): InlineBlock {
  const inner = token.startsWith("`") && token.endsWith("`") ? token.slice(1, -1) : token;
  if (!inner.startsWith(INLINE_PREFIX)) throw new DecryptError("format", "Not a Strongbox block");
  const rest = inner.slice(INLINE_PREFIX.length);
  const lastColon = rest.lastIndexOf(":");
  if (lastColon < 0) throw new DecryptError("format", "Malformed block");
  const params = rest.slice(0, lastColon);
  const header = INLINE_PREFIX + params + ":";
  let data: Bytes;
  try {
    data = fromBase64Url(rest.slice(lastColon + 1));
  } catch {
    throw new DecryptError("format", "Malformed block data");
  }
  const km = /^k(\d+)$/.exec(params);
  if (km) {
    const keyId = Number(km[1]);
    if (!Number.isSafeInteger(keyId) || keyId > 0xffffffff) throw new DecryptError("format", "Bad key id");
    if (data.length < SALT_BYTES + IV_BYTES + 16) throw new DecryptError("format", "Block is truncated");
    return { mode: "master", keyId, header, data };
  }
  const pm = /^p:(a(\d+)\.(\d+)\.(\d+)|p(\d+)):([A-Za-z0-9_-]+)$/.exec(params);
  if (!pm) throw new DecryptError("format", "Malformed block parameters");
  let kdf: KdfParams;
  try {
    const salt = toBase64(fromBase64Url(pm[6]));
    kdf = pm[2] !== undefined
      ? validateKdfParams({ alg: "argon2id", memKiB: Number(pm[2]), iterations: Number(pm[3]), parallelism: Number(pm[4]), salt })
      : validateKdfParams({ alg: "pbkdf2-sha256", iterations: Number(pm[5]), salt });
  } catch {
    throw new DecryptError("format", "Bad block parameters");
  }
  if (data.length < IV_BYTES + 16) throw new DecryptError("format", "Block is truncated");
  return { mode: "password", kdf, header, data };
}

async function inlineKeyFromMaster(master: CryptoKey, salt: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: salt as Bytes, info: HKDF_INFO },
    master,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function keyFromPassword(password: string, kdf: KdfParams): Promise<CryptoKey> {
  const raw = await deriveKeyBytes(password, kdf);
  try {
    return await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  } finally {
    wipe(raw);
  }
}

function kdfSpec(kdf: KdfParams): string {
  // KdfParams keep the salt in standard base64; blocks use base64url.
  const salt = toBase64Url(fromBase64(kdf.salt));
  if (kdf.alg === "argon2id") return `p:a${kdf.memKiB}.${kdf.iterations}.${kdf.parallelism}:${salt}`;
  return `p:p${kdf.iterations}:${salt}`;
}

export async function encryptInlineWithMaster(plaintext: string, keys: KeyProvider): Promise<string> {
  const keyId = keys.activeKeyId;
  const master = keys.get(keyId);
  if (!master) throw new Error(`Master key ${keyId} is not available`);
  const header = `${INLINE_PREFIX}k${keyId}:`;
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = await inlineKeyFromMaster(master, salt);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(header) }, key, utf8(plaintext));
  return "`" + header + toBase64Url(concatBytes(salt, iv, new Uint8Array(ct))) + "`";
}

export async function encryptInlineWithPassword(plaintext: string, password: string, kdf: KdfParams): Promise<string> {
  const header = `${INLINE_PREFIX}${kdfSpec(kdf)}:`;
  const key = await keyFromPassword(password, kdf);
  const iv = randomBytes(IV_BYTES);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(header) }, key, utf8(plaintext));
  return "`" + header + toBase64Url(concatBytes(iv, new Uint8Array(ct))) + "`";
}

export async function decryptInline(
  token: string,
  secrets: { keys?: KeyProvider | null; password?: string },
): Promise<string> {
  const block = parseInlineBlock(token);
  let key: CryptoKey;
  let iv: Bytes;
  let ct: Bytes;
  if (block.mode === "master") {
    const master = secrets.keys?.get(block.keyId);
    if (!master) throw new DecryptError("unknown-key", `Master key ${block.keyId} is not available`);
    const salt = block.data.slice(0, SALT_BYTES);
    iv = block.data.slice(SALT_BYTES, SALT_BYTES + IV_BYTES);
    ct = block.data.slice(SALT_BYTES + IV_BYTES);
    key = await inlineKeyFromMaster(master, salt);
  } else {
    if (secrets.password === undefined) throw new DecryptError("unknown-key", "This block needs its own password");
    iv = block.data.slice(0, IV_BYTES);
    ct = block.data.slice(IV_BYTES);
    key = await keyFromPassword(secrets.password, block.kdf);
  }
  try {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: utf8(block.header) }, key, ct);
    return fromUtf8(new Uint8Array(pt));
  } catch {
    throw new DecryptError("auth", "Wrong key or password, or the block was modified");
  }
}

/** Which kind of secret a block needs, without decrypting it. */
export function inlineBlockMode(token: string): "master" | "password" | null {
  try {
    return parseInlineBlock(token).mode;
  } catch {
    return null;
  }
}

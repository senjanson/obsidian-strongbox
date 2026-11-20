/**
 * The Strongbox file container.
 *
 *   offset  size  field
 *   0       8     magic  89 53 42 4F 58 0D 0A 1A  ("\x89SBOX\r\n\x1a")
 *   8       1     format version (1)
 *   9       1     flags (reserved, 0)
 *   10      4     master key id, uint32 big-endian
 *   14      32    file salt, fresh random bytes on every write
 *   46      4     plaintext chunk size, uint32 big-endian
 *   50      ...   chunks
 *
 * Each chunk is AES-256-GCM(plaintext slice) with a 16-byte tag; every chunk
 * except the last holds exactly `chunkSize` plaintext bytes, the last holds
 * 0..chunkSize (an empty file is one empty chunk). The file key is
 * HKDF-SHA-256(master key, salt = file salt, info = "strongbox/file/v1").
 * The nonce is 4 zero bytes followed by the 64-bit chunk index; this is safe
 * because every write uses a new file salt, hence a new key. The additional
 * data of each chunk is header || uint64 index || final flag (1 byte), so
 * changing the header, dropping trailing chunks, or swapping chunks fails
 * authentication. The path is deliberately not bound: renaming a file must
 * not require rewriting it.
 */
import {
  Bytes,
  concatBytes,
  randomBytes,
  readUint32BE,
  startsWithBytes,
  uint64BE,
  writeUint32BE,
} from "./bytes";

export const MAGIC: Bytes = new Uint8Array([0x89, 0x53, 0x42, 0x4f, 0x58, 0x0d, 0x0a, 0x1a]);
export const CONTAINER_VERSION = 1;
export const HEADER_SIZE = 50;
export const FILE_SALT_BYTES = 32;
export const TAG_BYTES = 16;
export const DEFAULT_CHUNK_SIZE = 64 * 1024;
const MIN_CHUNK = 16;
const MAX_CHUNK = 16 * 1024 * 1024;
const HKDF_INFO = new TextEncoder().encode("strongbox/file/v1");

export type DecryptErrorKind = "format" | "unknown-key" | "auth";

export class DecryptError extends Error {
  constructor(public readonly kind: DecryptErrorKind, message: string) {
    super(message);
    this.name = "DecryptError";
  }
}

/** Something that can hand out master keys by id. */
export interface KeyProvider {
  /** Key used for new writes. */
  readonly activeKeyId: number;
  get(id: number): CryptoKey | undefined;
}

export interface ContainerHeader {
  version: number;
  keyId: number;
  salt: Bytes;
  chunkSize: number;
  raw: Bytes;
}

export function isContainer(data: Uint8Array): boolean {
  return startsWithBytes(data, MAGIC);
}

export function parseHeader(data: Uint8Array): ContainerHeader {
  if (!isContainer(data)) throw new DecryptError("format", "Not a Strongbox container");
  if (data.length < HEADER_SIZE + TAG_BYTES) throw new DecryptError("format", "Container is truncated");
  const version = data[8];
  if (version !== CONTAINER_VERSION) {
    throw new DecryptError("format", `Unsupported container version ${version}`);
  }
  const keyId = readUint32BE(data, 10);
  const salt = data.slice(14, 14 + FILE_SALT_BYTES);
  const chunkSize = readUint32BE(data, 46);
  if (chunkSize < MIN_CHUNK || chunkSize > MAX_CHUNK) {
    throw new DecryptError("format", "Bad chunk size");
  }
  return { version, keyId, salt, chunkSize, raw: data.slice(0, HEADER_SIZE) };
}

function buildHeader(keyId: number, salt: Uint8Array, chunkSize: number): Bytes {
  const header = new Uint8Array(HEADER_SIZE);
  header.set(MAGIC, 0);
  header[8] = CONTAINER_VERSION;
  header[9] = 0;
  writeUint32BE(header, 10, keyId);
  header.set(salt, 14);
  writeUint32BE(header, 46, chunkSize);
  return header;
}

export async function deriveFileKey(master: CryptoKey, salt: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: salt as Bytes, info: HKDF_INFO },
    master,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function nonceFor(index: number): Bytes {
  const nonce = new Uint8Array(12);
  nonce.set(uint64BE(index), 4);
  return nonce;
}

function aadFor(header: Uint8Array, index: number, final: boolean): Bytes {
  return concatBytes(header, uint64BE(index), new Uint8Array([final ? 1 : 0]));
}

export async function encryptContainer(
  plaintext: Uint8Array,
  keys: KeyProvider,
  options: { chunkSize?: number; keyId?: number } = {},
): Promise<Bytes> {
  const keyId = options.keyId ?? keys.activeKeyId;
  const master = keys.get(keyId);
  if (!master) throw new Error(`Master key ${keyId} is not available`);
  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE;
  if (chunkSize < MIN_CHUNK || chunkSize > MAX_CHUNK) throw new Error("Bad chunk size");
  const salt = randomBytes(FILE_SALT_BYTES);
  const header = buildHeader(keyId, salt, chunkSize);
  const fileKey = await deriveFileKey(master, salt);

  const count = Math.max(1, Math.ceil(plaintext.length / chunkSize));
  const out = new Uint8Array(HEADER_SIZE + plaintext.length + count * TAG_BYTES);
  out.set(header, 0);
  let offset = HEADER_SIZE;
  for (let i = 0; i < count; i++) {
    const slice = plaintext.subarray(i * chunkSize, Math.min(plaintext.length, (i + 1) * chunkSize));
    const final = i === count - 1;
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonceFor(i), additionalData: aadFor(header, i, final), tagLength: 128 },
      fileKey,
      slice as Bytes,
    );
    out.set(new Uint8Array(ct), offset);
    offset += ct.byteLength;
  }
  return out;
}

export async function decryptContainer(data: Uint8Array, keys: KeyProvider): Promise<Bytes> {
  const header = parseHeader(data);
  const master = keys.get(header.keyId);
  if (!master) throw new DecryptError("unknown-key", `Master key ${header.keyId} is not available`);
  const fileKey = await deriveFileKey(master, header.salt);

  const body = data.subarray(HEADER_SIZE);
  const stride = header.chunkSize + TAG_BYTES;
  const count = Math.ceil(body.length / stride);
  const lastLen = body.length - (count - 1) * stride;
  if (count < 1 || lastLen < TAG_BYTES) throw new DecryptError("format", "Container is truncated");

  const out = new Uint8Array(body.length - count * TAG_BYTES);
  let offset = 0;
  for (let i = 0; i < count; i++) {
    const chunk = body.subarray(i * stride, Math.min(body.length, (i + 1) * stride));
    const final = i === count - 1;
    let pt: ArrayBuffer;
    try {
      pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonceFor(i), additionalData: aadFor(header.raw, i, final), tagLength: 128 },
        fileKey,
        chunk as Bytes,
      );
    } catch {
      throw new DecryptError("auth", "Wrong key, or the file was modified or truncated");
    }
    out.set(new Uint8Array(pt), offset);
    offset += pt.byteLength;
  }
  return out;
}

/** Reads only the key id from a container header (no decryption). */
export function containerKeyId(data: Uint8Array): number {
  return parseHeader(data).keyId;
}

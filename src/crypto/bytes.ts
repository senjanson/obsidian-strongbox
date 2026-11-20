/**
 * Small byte helpers shared by the crypto core. Nothing here touches Node
 * built-ins: the same code runs in Obsidian's renderer, on mobile, and in
 * vitest (Node 20 has TextEncoder, atob/btoa and crypto.getRandomValues).
 */

/** A byte array backed by a plain ArrayBuffer (what Web Crypto accepts). */
export type Bytes = Uint8Array<ArrayBuffer>;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: false });
const strictDecoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(text: string): Bytes {
  return copyBytes(encoder.encode(text));
}

export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Decodes UTF-8, or returns null when the bytes are not valid UTF-8. */
export function fromUtf8Strict(bytes: Uint8Array): string | null {
  try {
    return strictDecoder.decode(bytes);
  } catch {
    return null;
  }
}

export function randomBytes(length: number): Bytes {
  const out = new Uint8Array(length);
  // getRandomValues refuses more than 65536 bytes per call.
  for (let i = 0; i < length; i += 65536) {
    crypto.getRandomValues(out.subarray(i, Math.min(length, i + 65536)));
  }
  return out;
}

export function concatBytes(...parts: Uint8Array[]): Bytes {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** A copy that owns its own ArrayBuffer (never a view into a larger one). */
export function copyBytes(src: Uint8Array): Bytes {
  const out = new Uint8Array(src.length);
  out.set(src);
  return out;
}

/** An exact ArrayBuffer for these bytes (Obsidian's binary APIs want one). */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength && bytes.buffer instanceof ArrayBuffer) {
    return bytes.buffer;
  }
  return copyBytes(bytes).buffer;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function startsWithBytes(data: Uint8Array, prefix: Uint8Array): boolean {
  if (data.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (data[i] !== prefix[i]) return false;
  return true;
}

/** Overwrites the bytes with zeros (best effort: JS may hold other copies). */
export function wipe(bytes: Uint8Array | null | undefined): void {
  if (bytes) bytes.fill(0);
}

// ---------------------------------------------------------------- base64

const CHUNK = 0x8000;

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + CHUNK)));
  }
  return btoa(binary);
}

/** Decodes standard base64; whitespace (line breaks) is ignored. Throws on bad input. */
export function fromBase64(text: string): Bytes {
  const clean = text.replace(/[\s]/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 === 1) {
    throw new Error("Invalid base64");
  }
  const binary = atob(clean);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(text: string): Bytes {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("Invalid base64url");
  let b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return fromBase64(b64);
}

// ---------------------------------------------------------------- integers

export function writeUint32BE(target: Uint8Array, offset: number, value: number): void {
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

export function readUint32BE(source: Uint8Array, offset: number): number {
  return (
    ((source[offset] << 24) >>> 0) +
    (source[offset + 1] << 16) +
    (source[offset + 2] << 8) +
    source[offset + 3]
  );
}

/** 8-byte big-endian encoding of a non-negative safe integer. */
export function uint64BE(value: number): Bytes {
  const out = new Uint8Array(8);
  const high = Math.floor(value / 0x100000000);
  const low = value >>> 0;
  writeUint32BE(out, 0, high);
  writeUint32BE(out, 4, low);
  return out;
}

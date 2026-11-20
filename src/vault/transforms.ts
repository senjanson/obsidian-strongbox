/**
 * The per-file transforms the batch engine runs. Each returns null when the
 * file is already in the target state, which is what makes resuming safe.
 */
import { Bytes, bytesEqual, fromUtf8Strict, utf8 } from "../crypto/bytes";
import { KeyProvider, containerKeyId } from "../crypto/container";
import { decryptInline, encryptInlineWithMaster, findInlineBlocks, parseInlineBlock } from "../crypto/inline";
import { FileTransform } from "./batch";
import { FileCodec, containerOf, detectForm } from "./codec";

export function encryptTransform(codec: FileCodec): FileTransform {
  return async (path, current) => {
    if (detectForm(current) !== null) return null;
    const payload = await codec.encode(path, current);
    return {
      output: payload.bytes,
      verify: async (written) => bytesEqual(await codec.decode(written), current),
    };
  };
}

export function decryptTransform(codec: FileCodec): FileTransform {
  return async (_path, current) => {
    if (detectForm(current) === null) return null;
    const plain = await codec.decode(current);
    return { output: plain, verify: async (written) => bytesEqual(written, plain) };
  };
}

/**
 * Re-key: moves file containers and master-key inline blocks onto the
 * active key. Plaintext files are only touched when they hold inline blocks
 * under an old key (and stay plaintext apart from those blocks).
 */
export function rekeyTransform(
  codec: FileCodec,
  keys: () => KeyProvider | null,
  isTextPath: (path: string) => boolean,
): FileTransform {
  return async (path, current) => {
    const k = keys();
    if (!k) throw new Error("Strongbox is locked");
    const container = containerOf(current);
    const wasEncrypted = container !== null;
    const plain = wasEncrypted ? await codec.decode(current) : current;

    let next: Bytes = plain;
    let inlineChanged = false;
    if (isTextPath(path)) {
      const text = fromUtf8Strict(plain);
      if (text !== null && text.includes("`strongbox:v1:k")) {
        const rewritten = await rekeyInlineBlocks(text, k);
        if (rewritten !== text) {
          next = utf8(rewritten);
          inlineChanged = true;
        }
      }
    }

    if (wasEncrypted) {
      if (containerKeyId(container) === k.activeKeyId && !inlineChanged) return null;
      const payload = await codec.encode(path, next);
      return { output: payload.bytes, verify: async (w) => bytesEqual(await codec.decode(w), next) };
    }
    if (!inlineChanged) return null;
    return { output: next, verify: async (w) => bytesEqual(w, next) };
  };
}

/** Re-encrypts master-key inline blocks that use a key other than the active one. */
export async function rekeyInlineBlocks(text: string, keys: KeyProvider): Promise<string> {
  const blocks = findInlineBlocks(text);
  if (blocks.length === 0) return text;
  let out = "";
  let last = 0;
  for (const b of blocks) {
    out += text.slice(last, b.start);
    let replacement = b.token;
    try {
      const parsed = parseInlineBlock(b.token);
      if (parsed.mode === "master" && parsed.keyId !== keys.activeKeyId && keys.get(parsed.keyId)) {
        const plain = await decryptInline(b.token, { keys });
        replacement = await encryptInlineWithMaster(plain, keys);
      }
    } catch {
      // Leave blocks we cannot open untouched.
    }
    out += replacement;
    last = b.end;
  }
  return out + text.slice(last);
}

/** Lists master-key ids still used by inline blocks in the text. */
export function inlineKeyIds(text: string): number[] {
  const ids = new Set<number>();
  for (const b of findInlineBlocks(text)) {
    try {
      const p = parseInlineBlock(b.token);
      if (p.mode === "master") ids.add(p.keyId);
    } catch {
      /* ignore */
    }
  }
  return [...ids];
}

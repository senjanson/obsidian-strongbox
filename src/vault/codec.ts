/**
 * Turns plaintext into what goes on disk for a path, and back. Note-like
 * files get the text shell, everything else the bare binary container; the
 * container inside is the same either way, and reading accepts both forms
 * whatever the extension.
 */
import { Bytes, fromUtf8, toArrayBuffer, utf8 } from "../crypto/bytes";
import { KeyProvider, decryptContainer, encryptContainer, isContainer } from "../crypto/container";
import { looksLikeShell, looksLikeShellBytes, unwrapShell, unwrapShellBytes, wrapShell } from "../crypto/text-shell";

export type DiskForm = "binary" | "text";

/** Which encrypted form the bytes are in, or null for ordinary content. */
export function detectForm(data: Uint8Array): DiskForm | null {
  if (isContainer(data)) return "binary";
  if (looksLikeShellBytes(data) && unwrapShellBytes(data)) return "text";
  return null;
}

/** The container inside on-disk bytes, or null if the bytes are not encrypted. */
export function containerOf(data: Uint8Array): Bytes | null {
  if (isContainer(data)) return data.buffer instanceof ArrayBuffer ? (data as Bytes) : new Uint8Array(data);
  return unwrapShellBytes(data);
}

/** Cheap check on a string read through adapter.read(). */
export function textLooksEncrypted(text: string): "text" | "binary" | null {
  if (looksLikeShell(text)) return unwrapShell(text) ? "text" : null;
  // A binary container read as UTF-8: 0x89 is not valid UTF-8, so it decodes
  // to U+FFFD, followed by "SBOX\r\n".
  if (text.startsWith("�SBOX\r\n")) return "binary";
  return null;
}

export interface EncodedPayload {
  form: DiskForm;
  /** What to hand to adapter.write (text form). */
  text?: string;
  /** What to hand to adapter.writeBinary (binary form). */
  binary?: ArrayBuffer;
  /** The exact bytes that end up on disk, for verification. */
  bytes: Bytes;
}

export class FileCodec {
  constructor(
    private readonly keys: () => KeyProvider | null,
    private readonly isTextPath: (path: string) => boolean,
    private readonly chunkSize?: number,
  ) {}

  private requireKeys(): KeyProvider {
    const k = this.keys();
    if (!k) throw new Error("Strongbox is locked");
    return k;
  }

  async encode(path: string, plaintext: Uint8Array, keyProvider?: KeyProvider): Promise<EncodedPayload> {
    const container = await encryptContainer(plaintext, keyProvider ?? this.requireKeys(), { chunkSize: this.chunkSize });
    if (this.isTextPath(path)) {
      const text = wrapShell(container);
      return { form: "text", text, bytes: utf8(text) };
    }
    return { form: "binary", binary: toArrayBuffer(container), bytes: container };
  }

  async encodeText(path: string, plaintext: string): Promise<EncodedPayload> {
    return this.encode(path, utf8(plaintext));
  }

  /** Decrypts on-disk bytes. Throws if they are not encrypted or do not open. */
  async decode(data: Uint8Array, keyProvider?: KeyProvider): Promise<Bytes> {
    const container = containerOf(data);
    if (!container) throw new Error("Not encrypted");
    return decryptContainer(container, keyProvider ?? this.requireKeys());
  }

  /** Decrypts a shell read through adapter.read(). */
  async decodeShellText(text: string, keyProvider?: KeyProvider): Promise<Bytes> {
    const container = unwrapShell(text);
    if (!container) throw new Error("Not encrypted");
    return decryptContainer(container, keyProvider ?? this.requireKeys());
  }

  async decodeToText(data: Uint8Array): Promise<string> {
    return fromUtf8(await this.decode(data));
  }
}

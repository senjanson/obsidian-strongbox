/**
 * Hooks the vault adapter's read and write methods so the disk only ever
 * holds ciphertext for protected files, while Obsidian (search, links,
 * graph, editors) sees plaintext once Strongbox is unlocked.
 *
 * - Unlocked: anything read that carries the Strongbox header is decrypted;
 *   anything written to a protected path, or over a file that is already
 *   encrypted, is encrypted first.
 * - Locked: reads return what is on disk; writes that would need encrypting
 *   are refused (LockedError), so plaintext can never land on disk.
 *
 * The hook only depends on the small RawAdapter interface, so tests drive it
 * with an in-memory adapter.
 */
import { Bytes, bytesEqual, fromUtf8, toArrayBuffer, utf8 } from "../crypto/bytes";
import { DecryptError, FILE_SALT_BYTES } from "../crypto/container";
import { FileCodec, containerOf, detectForm, textLooksEncrypted } from "./codec";
import { ProtectionPolicy, normPath } from "./rules";

export interface RawAdapter {
  read: (path: string) => Promise<string>;
  readBinary: (path: string) => Promise<ArrayBuffer>;
  write: (path: string, data: string, options?: unknown) => Promise<void>;
  writeBinary: (path: string, data: ArrayBuffer, options?: unknown) => Promise<void>;
  append: (path: string, data: string, options?: unknown) => Promise<void>;
  process?: (path: string, fn: (data: string) => string, options?: unknown) => Promise<string>;
  exists: (path: string, sensitive?: boolean) => Promise<boolean>;
}

/** The adapter seen as a bag of method slots, so they can be swapped and put back. */
type MethodSlots = Record<string, unknown>;

export const HOOKED_METHODS = ["read", "readBinary", "write", "writeBinary", "append", "process"] as const;
type HookedName = (typeof HOOKED_METHODS)[number];

export class LockedError extends Error {
  readonly code = "STRONGBOX_LOCKED";
  constructor(public readonly path: string) {
    super(`Strongbox is locked: unlock it before changing ${path}`);
    this.name = "LockedError";
  }
}

export interface HookDeps {
  policy: ProtectionPolicy;
  codec: FileCodec;
  isUnlocked(): boolean;
  /** A write was refused because Strongbox is locked. */
  onBlockedWrite?(path: string): void;
  /** An encrypted file could not be opened (wrong key, damage …). */
  onDecryptError?(path: string, error: unknown): void;
  /** Extra paths to refuse while locked (hidden-name placeholders). */
  isGuardedWhileLocked?(path: string): boolean;
}

interface Saved {
  own: boolean;
  value: unknown;
  wrapper: unknown;
}

export class AdapterHook {
  /** The adapter's own methods, bound; they bypass encryption entirely. */
  readonly raw: RawAdapter;
  private saved = new Map<HookedName, Saved>();
  private active = false;
  /** path → whether the file on disk is encrypted, as last seen. */
  private encrypted = new Map<string, boolean>();

  private readonly adapter: MethodSlots;

  constructor(adapter: RawAdapter, private readonly deps: HookDeps) {
    const a = adapter;
    this.adapter = adapter as unknown as MethodSlots;
    // Capture the original functions now: after install() the adapter's
    // slots hold our wrappers, and calling those from here would recurse.
    const { read, readBinary, write, writeBinary, append, process, exists } = a;
    this.raw = {
      read: (p) => read.call(a, p),
      readBinary: (p) => readBinary.call(a, p),
      write: (p, d, o) => write.call(a, p, d, o),
      writeBinary: (p, d, o) => writeBinary.call(a, p, d, o),
      append: (p, d, o) => append.call(a, p, d, o),
      process: typeof process === "function" ? (p, fn, o) => process.call(a, p, fn, o) : undefined,
      exists: (p, sensitive) => exists.call(a, p, sensitive),
    };
  }

  isInstalled(): boolean {
    return this.active;
  }

  install(): void {
    if (this.active) return;
    const impl: Record<HookedName, unknown> = {
      read: (p: string) => this.read(p),
      readBinary: (p: string) => this.readBinary(p),
      write: (p: string, d: string, o?: unknown) => this.write(p, d, o),
      writeBinary: (p: string, d: ArrayBuffer, o?: unknown) => this.writeBinary(p, d, o),
      append: (p: string, d: string, o?: unknown) => this.append(p, d, o),
      process: (p: string, fn: (d: string) => string, o?: unknown) => this.process(p, fn, o),
    };
    for (const name of HOOKED_METHODS) {
      if (name === "process" && typeof this.adapter.process !== "function") continue;
      const own = Object.prototype.hasOwnProperty.call(this.adapter, name);
      const wrapper = impl[name];
      this.saved.set(name, { own, value: this.adapter[name], wrapper });
      this.adapter[name] = wrapper;
    }
    this.active = true;
  }

  /** Puts the adapter's methods back exactly as they were. */
  uninstall(): void {
    if (!this.active) return;
    for (const [name, s] of this.saved) {
      if (this.adapter[name] !== s.wrapper) {
        // Someone wrapped us after we were installed; unwinding them would
        // break their hook. Our wrapper keeps working as a pass-through.
        continue;
      }
      if (s.own) this.adapter[name] = s.value;
      else delete this.adapter[name];
    }
    this.saved.clear();
    this.active = false;
  }

  /** Records what is on disk after someone else (the batch engine) changed it. */
  noteState(path: string, isEncrypted: boolean): void {
    this.encrypted.set(normPath(path), isEncrypted);
  }

  forget(path: string): void {
    const p = normPath(path);
    for (const key of [...this.encrypted.keys()]) {
      if (key === p || key.startsWith(p + "/")) this.encrypted.delete(key);
    }
  }

  knownEncrypted(path: string): boolean | undefined {
    return this.encrypted.get(normPath(path));
  }

  /**
   * Only the built-in exclusions (config folder, trash, dot paths, plugin
   * files) bypass the hook entirely. User-excluded paths still get the
   * "already encrypted on disk" treatment, so excluding a path never lets
   * plaintext overwrite a file that is encrypted.
   */
  private passThrough(path: string): boolean {
    return !this.active || this.deps.policy.isSystemExcluded(path);
  }

  /** Whether a write to this path has to be encrypted. */
  async mustEncrypt(rawPath: string): Promise<boolean> {
    const path = normPath(rawPath);
    if (this.deps.policy.isSystemExcluded(path)) return false;
    // isProtected() is false for user-excluded paths; the disk check below still applies to them.
    if (this.deps.policy.isProtected(path)) return true;
    if (!this.deps.isUnlocked() && this.deps.isGuardedWhileLocked?.(path)) return true;
    const known = this.encrypted.get(path);
    if (known !== undefined) return known;
    if (!(await this.raw.exists(path))) return false;
    const onDisk = new Uint8Array(await this.raw.readBinary(path));
    const enc = detectForm(onDisk) !== null;
    this.encrypted.set(path, enc);
    return enc;
  }

  /**
   * Ciphertext handed to write() is stored as is (sync tools copy raw
   * files). But every real encryption uses a fresh file salt, so ciphertext
   * with the same salt as the file on disk and different bytes can only be
   * the old ciphertext edited by hand (e.g. typing into the shell while
   * locked); storing it would destroy the file.
   */
  private async isEditedCiphertext(rawPath: string, incoming: Uint8Array): Promise<boolean> {
    if (!(await this.raw.exists(rawPath))) return false;
    const onDisk = new Uint8Array(await this.raw.readBinary(rawPath));
    if (bytesEqual(onDisk, incoming)) return false;
    const a = containerOf(onDisk);
    const b = containerOf(incoming);
    if (!a || !b) return false;
    return bytesEqual(a.subarray(14, 14 + FILE_SALT_BYTES), b.subarray(14, 14 + FILE_SALT_BYTES));
  }

  private blocked(path: string): never {
    this.deps.onBlockedWrite?.(path);
    throw new LockedError(path);
  }

  private decryptFailed(path: string, error: unknown): never {
    this.deps.onDecryptError?.(path, error);
    if (error instanceof DecryptError) throw error;
    throw error instanceof Error ? error : new Error(String(error));
  }

  // ------------------------------------------------------------ reads

  async read(rawPath: string): Promise<string> {
    if (this.passThrough(rawPath)) return this.raw.read(rawPath);
    const path = normPath(rawPath);
    let text: string;
    try {
      text = await this.raw.read(rawPath);
    } catch (e) {
      // A file kept as a binary container is not valid UTF-8. Desktop reads
      // it as garbled text, but the iOS app refuses to read it as text at
      // all, so look at the bytes before giving up.
      return this.readContainerAsText(rawPath, path, e);
    }
    const form = textLooksEncrypted(text);
    this.encrypted.set(path, form !== null);
    if (!form || !this.deps.isUnlocked()) return text;
    try {
      const plain =
        form === "text"
          ? await this.deps.codec.decodeShellText(text)
          : await this.deps.codec.decode(new Uint8Array(await this.raw.readBinary(rawPath)));
      return fromUtf8(plain);
    } catch (e) {
      this.decryptFailed(path, e);
    }
  }

  private async readContainerAsText(rawPath: string, path: string, readError: unknown): Promise<string> {
    let data: Uint8Array;
    try {
      data = new Uint8Array(await this.raw.readBinary(rawPath));
    } catch {
      throw readError;
    }
    if (detectForm(data) === null) throw readError;
    this.encrypted.set(path, true);
    if (!this.deps.isUnlocked()) throw readError;
    try {
      return fromUtf8(await this.deps.codec.decode(data));
    } catch (e) {
      this.decryptFailed(path, e);
    }
  }

  async readBinary(rawPath: string): Promise<ArrayBuffer> {
    if (this.passThrough(rawPath)) return this.raw.readBinary(rawPath);
    const path = normPath(rawPath);
    const buf = await this.raw.readBinary(rawPath);
    const data = new Uint8Array(buf);
    const form = detectForm(data);
    this.encrypted.set(path, form !== null);
    if (!form || !this.deps.isUnlocked()) return buf;
    try {
      return toArrayBuffer(await this.deps.codec.decode(data));
    } catch (e) {
      this.decryptFailed(path, e);
    }
  }

  // ------------------------------------------------------------ writes

  async write(rawPath: string, data: string, options?: unknown): Promise<void> {
    if (this.passThrough(rawPath)) return this.raw.write(rawPath, data, options);
    const path = normPath(rawPath);
    // Already ciphertext (e.g. a sync tool copying the raw file): store as is.
    if (typeof data === "string" && textLooksEncrypted(data) === "text") {
      if (await this.isEditedCiphertext(rawPath, utf8(data))) this.blocked(path);
      await this.raw.write(rawPath, data, options);
      this.encrypted.set(path, true);
      return;
    }
    if (!(await this.mustEncrypt(path))) {
      await this.raw.write(rawPath, data, options);
      this.encrypted.set(path, false);
      return;
    }
    if (!this.deps.isUnlocked()) this.blocked(path);
    await this.writeEncrypted(rawPath, path, utf8(data), options);
  }

  async writeBinary(rawPath: string, data: ArrayBuffer, options?: unknown): Promise<void> {
    if (this.passThrough(rawPath)) return this.raw.writeBinary(rawPath, data, options);
    const path = normPath(rawPath);
    const bytes = new Uint8Array(data);
    if (detectForm(bytes) !== null) {
      if (await this.isEditedCiphertext(rawPath, bytes)) this.blocked(path);
      await this.raw.writeBinary(rawPath, data, options);
      this.encrypted.set(path, true);
      return;
    }
    if (!(await this.mustEncrypt(path))) {
      await this.raw.writeBinary(rawPath, data, options);
      this.encrypted.set(path, false);
      return;
    }
    if (!this.deps.isUnlocked()) this.blocked(path);
    await this.writeEncrypted(rawPath, path, new Uint8Array(bytes), options);
  }

  private async writeEncrypted(rawPath: string, path: string, plain: Bytes, options?: unknown): Promise<void> {
    const payload = await this.deps.codec.encode(path, plain);
    if (payload.form === "text") await this.raw.write(rawPath, payload.text as string, options);
    else await this.raw.writeBinary(rawPath, payload.binary as ArrayBuffer, options);
    this.encrypted.set(path, true);
  }

  async append(rawPath: string, data: string, options?: unknown): Promise<void> {
    if (this.passThrough(rawPath)) return this.raw.append(rawPath, data, options);
    const path = normPath(rawPath);
    if (!(await this.mustEncrypt(path))) {
      await this.raw.append(rawPath, data, options);
      return;
    }
    if (!this.deps.isUnlocked()) this.blocked(path);
    const current = (await this.raw.exists(rawPath)) ? await this.read(rawPath) : "";
    await this.writeEncrypted(rawPath, path, utf8(current + data), options);
  }

  async process(rawPath: string, fn: (data: string) => string, options?: unknown): Promise<string> {
    const rawProcess = this.raw.process;
    if (this.passThrough(rawPath) && rawProcess) return rawProcess(rawPath, fn, options);
    const path = normPath(rawPath);
    if (rawProcess && !(await this.mustEncrypt(path))) {
      const out = await rawProcess(rawPath, fn, options);
      this.encrypted.set(path, false);
      return out;
    }
    if ((await this.mustEncrypt(path)) && !this.deps.isUnlocked()) this.blocked(path);
    const current = await this.read(rawPath);
    const next = fn(current);
    await this.write(rawPath, next, options);
    return next;
  }
}

/**
 * An in-memory stand-in for Obsidian's DataAdapter: enough of it for the
 * hook, the batch engine and name hiding. Paths are vault-relative.
 */
const enc = new TextEncoder();
const dec = new TextDecoder();

export class CrashError extends Error {}

export class FakeAdapter {
  files = new Map<string, Uint8Array>();
  folders = new Set<string>();
  /** Every path ever written through write/writeBinary/append, in order. */
  writes: string[] = [];
  /**
   * Simulated crash: after this many more mutating calls succeed, the next
   * one throws and the adapter "dies" (every call throws) until revive().
   */
  crashAfter: number | null = null;
  dead = false;

  private alive(): void {
    if (this.dead) throw new CrashError('process is dead');
  }

  private tick(): void {
    this.alive();
    if (this.crashAfter === null) return;
    this.crashAfter--;
    if (this.crashAfter < 0) {
      this.crashAfter = null;
      this.dead = true;
      throw new CrashError('simulated crash');
    }
  }

  revive(): void {
    this.dead = false;
    this.crashAfter = null;
  }

  private ensureParents(path: string): void {
    const parts = path.split('/');
    for (let i = 1; i < parts.length; i++) this.folders.add(parts.slice(0, i).join('/'));
  }

  seed(path: string, content: string | Uint8Array): void {
    this.ensureParents(path);
    this.files.set(path, typeof content === 'string' ? enc.encode(content) : new Uint8Array(content));
  }

  text(path: string): string {
    const b = this.files.get(path);
    if (!b) throw new Error(`no file ${path}`);
    return dec.decode(b);
  }

  bytes(path: string): Uint8Array {
    const b = this.files.get(path);
    if (!b) throw new Error(`no file ${path}`);
    return b;
  }

  async read(path: string): Promise<string> {
    this.alive();
    return this.text(path);
  }

  async readBinary(path: string): Promise<ArrayBuffer> {
    this.alive();
    const b = this.bytes(path);
    return b.slice().buffer;
  }

  async write(path: string, data: string): Promise<void> {
    this.tick();
    this.ensureParents(path);
    this.writes.push(path);
    this.files.set(path, enc.encode(data));
  }

  async writeBinary(path: string, data: ArrayBuffer): Promise<void> {
    this.tick();
    this.ensureParents(path);
    this.writes.push(path);
    this.files.set(path, new Uint8Array(data.slice(0)));
  }

  async append(path: string, data: string): Promise<void> {
    this.tick();
    this.ensureParents(path);
    this.writes.push(path);
    const prev = this.files.get(path) ?? new Uint8Array(0);
    const add = enc.encode(data);
    const out = new Uint8Array(prev.length + add.length);
    out.set(prev);
    out.set(add, prev.length);
    this.files.set(path, out);
  }

  async process(path: string, fn: (data: string) => string): Promise<string> {
    const next = fn(this.text(path));
    await this.write(path, next);
    return next;
  }

  async exists(path: string): Promise<boolean> {
    this.alive();
    return this.files.has(path) || this.folders.has(path);
  }

  async mkdir(path: string): Promise<void> {
    this.ensureParents(path + '/x');
  }

  async remove(path: string): Promise<void> {
    this.tick();
    this.files.delete(path);
  }

  async list(path: string): Promise<{ files: string[]; folders: string[] }> {
    // Obsidian calls the vault root "/".
    if (path === '/') path = '';
    const prefix = path ? path + '/' : '';
    const direct = (p: string) => p.startsWith(prefix) && !p.slice(prefix.length).includes('/');
    return {
      files: [...this.files.keys()].filter(direct).sort(),
      folders: [...this.folders].filter(direct).sort(),
    };
  }

  async rename(from: string, to: string): Promise<void> {
    if (this.files.has(to) || this.folders.has(to)) throw new Error('Destination file already exists!');
    this.tick();
    if (this.files.has(from)) {
      this.ensureParents(to);
      this.files.set(to, this.files.get(from)!);
      this.files.delete(from);
      return;
    }
    if (!this.folders.has(from)) throw new Error(`no such path ${from}`);
    const moveKey = (p: string) => (p === from ? to : to + p.slice(from.length));
    for (const f of [...this.files.keys()]) {
      if (f.startsWith(from + '/')) {
        this.files.set(moveKey(f), this.files.get(f)!);
        this.files.delete(f);
      }
    }
    for (const d of [...this.folders]) {
      if (d === from || d.startsWith(from + '/')) {
        this.folders.delete(d);
        this.folders.add(moveKey(d));
      }
    }
  }

  /** Every byte sequence stored, for "no plaintext on disk" checks. */
  containsPlaintext(needle: string): string[] {
    const n = enc.encode(needle);
    const hits: string[] = [];
    for (const [p, b] of this.files) {
      outer: for (let i = 0; i + n.length <= b.length; i++) {
        for (let j = 0; j < n.length; j++) if (b[i + j] !== n[j]) continue outer;
        hits.push(p);
        break;
      }
    }
    return hits;
  }
}

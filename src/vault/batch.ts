/**
 * The batch engine behind first-time encryption, removing protection and a
 * full re-key. For each file it:
 *
 *   1. reads the file and asks the transform for the new content (or a skip);
 *   2. writes the new content to a temporary file, reads it back and checks
 *      that it opens to the same plaintext;
 *   3. logs "temp" in the journal, overwrites the original, reads it back;
 *   4. logs "done" and deletes the temporary file.
 *
 * The journal is an append-only file of JSON lines. After a crash or a
 * cancel, `resume()` replays it: finished files are skipped, a file stuck at
 * "temp" is completed from its verified temporary copy, everything else is
 * processed again (transforms skip files already in the target state).
 */
import { Bytes, bytesEqual, toArrayBuffer } from "../crypto/bytes";

/** A failure after the verified temporary copy was logged: resume finishes from that copy. */
class AfterTempError extends Error {}

export type BatchOp = "encrypt" | "decrypt" | "rekey";

export interface BatchIO {
  read(path: string): Promise<string>;
  readBinary(path: string): Promise<ArrayBuffer>;
  write(path: string, data: string): Promise<void>;
  writeBinary(path: string, data: ArrayBuffer): Promise<void>;
  append(path: string, data: string): Promise<void>;
  exists(path: string): Promise<boolean>;
  remove(path: string): Promise<void>;
  mkdir(path: string): Promise<void>;
}

export interface TransformResult {
  output: Bytes;
  /** Checks bytes read back from disk; true when they hold the right plaintext. */
  verify(written: Bytes): Promise<boolean>;
}

/** Returns null when the file needs no change (already in the target state). */
export type FileTransform = (path: string, current: Bytes) => Promise<TransformResult | null>;

export interface BatchProgress {
  total: number;
  processed: number;
  changed: number;
  skipped: number;
  failed: number;
  current?: string;
}

export interface BatchResult {
  op: BatchOp;
  total: number;
  changed: number;
  skipped: number;
  failed: { path: string; error: string }[];
  cancelled: boolean;
  meta: Record<string, unknown>;
}

export interface BatchRunOptions {
  concurrency: number;
  signal?: AbortSignal;
  onProgress?(p: BatchProgress): void;
  /** Called after a file's on-disk state changed. */
  onFileWritten?(path: string, op: BatchOp): void;
}

export interface JournalInfo {
  op: BatchOp;
  created: number;
  meta: Record<string, unknown>;
  total: number;
  remaining: number;
}

type FileState = "pending" | "temp" | "done" | "skip" | "fail";

const FILE_STATES: readonly string[] = ["pending", "temp", "done", "skip", "fail"];
const isFileState = (v: unknown): v is FileState => typeof v === "string" && FILE_STATES.includes(v);
const isBatchOp = (v: unknown): v is BatchOp => v === "encrypt" || v === "decrypt" || v === "rekey";
const isIndex = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0;

interface LoadedJournal {
  op: BatchOp;
  created: number;
  meta: Record<string, unknown>;
  paths: string[];
  states: FileState[];
  errors: Map<number, string>;
}

export class BatchEngine {
  private appendChain: Promise<void> = Promise.resolve();

  constructor(
    private readonly io: BatchIO,
    private readonly journalPath: string,
    private readonly tmpDir: string,
  ) {}

  /** Describes an unfinished batch, or null. */
  async pending(): Promise<JournalInfo | null> {
    const j = await this.load();
    if (!j) return null;
    const remaining = j.states.filter((s) => s !== "done" && s !== "skip").length;
    return { op: j.op, created: j.created, meta: j.meta, total: j.paths.length, remaining };
  }

  /** Starts a new batch. Refuses while another one is unfinished. */
  async start(
    op: BatchOp,
    paths: string[],
    transform: FileTransform,
    options: BatchRunOptions,
    meta: Record<string, unknown> = {},
  ): Promise<BatchResult> {
    if (await this.io.exists(this.journalPath)) {
      throw new Error("Another batch is unfinished; resume or discard it first");
    }
    const unique = [...new Set(paths)];
    const lines = [JSON.stringify({ h: 1, op, created: Date.now(), meta })];
    unique.forEach((p, i) => lines.push(JSON.stringify({ f: p, i })));
    await this.ensureDir(this.tmpDir);
    await this.io.write(this.journalPath, lines.join("\n") + "\n");
    const journal: LoadedJournal = {
      op,
      created: Date.now(),
      meta,
      paths: unique,
      states: unique.map((): FileState => "pending"),
      errors: new Map(),
    };
    return this.run(journal, transform, options);
  }

  /** Continues the unfinished batch with the transform for its operation. */
  async resume(
    transformFor: (op: BatchOp, meta: Record<string, unknown>) => FileTransform,
    options: BatchRunOptions,
  ): Promise<BatchResult | null> {
    const j = await this.load();
    if (!j) return null;
    await this.ensureDir(this.tmpDir);
    // Failed files get another go.
    j.states = j.states.map((s) => (s === "fail" ? "pending" : s));
    return this.run(j, transformFor(j.op, j.meta), options);
  }

  /**
   * Forgets the unfinished batch (temporary files are removed too). A file
   * left half-replaced is first completed from its verified copy; if that
   * fails, nothing is removed and the error is thrown, so the copy survives.
   */
  async discard(): Promise<void> {
    const j = await this.load();
    if (j) {
      for (let i = 0; i < j.paths.length; i++) {
        if (j.states[i] === "temp") await this.finishFromTemp(i, j.paths[i]);
      }
      for (let i = 0; i < j.paths.length; i++) await this.removeIfExists(this.tmpPath(i));
    }
    await this.removeIfExists(this.journalPath);
  }

  private tmpPath(index: number): string {
    return `${this.tmpDir}/${index}.tmp`;
  }

  private async ensureDir(dir: string): Promise<void> {
    if (!(await this.io.exists(dir))) await this.io.mkdir(dir);
  }

  private async removeIfExists(path: string): Promise<void> {
    if (await this.io.exists(path)) await this.io.remove(path);
  }

  private log(entry: Record<string, unknown>): Promise<void> {
    const line = JSON.stringify(entry) + "\n";
    // A failed append must not poison every later one.
    this.appendChain = this.appendChain.catch(() => undefined).then(() => this.io.append(this.journalPath, line));
    return this.appendChain;
  }

  private async load(): Promise<LoadedJournal | null> {
    if (!(await this.io.exists(this.journalPath))) return null;
    const text = await this.io.read(this.journalPath);
    const lines = text.split("\n");
    let header: { op: BatchOp; created: number; meta: Record<string, unknown> } | null = null;
    const paths: string[] = [];
    const states: FileState[] = [];
    const errors = new Map<number, string>();
    for (const line of lines) {
      if (!line.trim()) continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        continue; // a torn last line after a crash
      }
      if (typeof parsed !== "object" || parsed === null) continue;
      const o = parsed as Record<string, unknown>;
      const i = o.i;
      if (o.h === 1 && header === null) {
        if (!isBatchOp(o.op)) return null;
        const meta = o.meta;
        header = {
          op: o.op,
          created: typeof o.created === "number" ? o.created : 0,
          meta: typeof meta === "object" && meta !== null ? (meta as Record<string, unknown>) : {},
        };
      } else if (typeof o.f === "string" && isIndex(i)) {
        paths[i] = o.f;
        states[i] = "pending";
      } else if (isFileState(o.s) && isIndex(i) && i < paths.length) {
        states[i] = o.s;
        if (o.s === "fail") errors.set(i, typeof o.e === "string" ? o.e : "");
      }
    }
    if (!header) return null;
    for (let i = 0; i < paths.length; i++) {
      if (paths[i] === undefined) {
        paths[i] = "";
        states[i] = "skip";
      }
    }
    return { op: header.op, created: header.created, meta: header.meta, paths, states, errors };
  }

  private async finishFromTemp(index: number, path: string): Promise<boolean> {
    const tmp = this.tmpPath(index);
    if (!(await this.io.exists(tmp))) return false;
    const data = new Uint8Array(await this.io.readBinary(tmp));
    await this.io.writeBinary(path, toArrayBuffer(data));
    const back = new Uint8Array(await this.io.readBinary(path));
    if (!bytesEqual(back, data)) throw new Error("Read-back mismatch while finishing from the temporary copy");
    return true;
  }

  private async run(j: LoadedJournal, transform: FileTransform, options: BatchRunOptions): Promise<BatchResult> {
    this.appendChain = Promise.resolve();
    const progress: BatchProgress = { total: j.paths.length, processed: 0, changed: 0, skipped: 0, failed: 0 };
    const failed: { path: string; error: string }[] = [];
    const queue: number[] = [];
    j.states.forEach((s, i) => {
      if (s === "done" || s === "skip") progress.processed++;
      else queue.push(i);
    });
    options.onProgress?.({ ...progress });

    let cancelled = false;
    const worker = async () => {
      for (;;) {
        if (options.signal?.aborted) {
          cancelled = true;
          return;
        }
        const i = queue.shift();
        if (i === undefined) return;
        const path = j.paths[i];
        progress.current = path;
        try {
          const outcome = await this.processOne(i, path, j.states[i], transform);
          j.states[i] = outcome;
          if (outcome === "done") {
            progress.changed++;
            options.onFileWritten?.(path, j.op);
          } else progress.skipped++;
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          failed.push({ path, error: msg });
          progress.failed++;
          if (e instanceof AfterTempError) {
            // Leave the journal at "temp": the verified copy is the truth now.
            j.states[i] = "temp";
          } else {
            j.states[i] = "fail";
            await this.log({ s: "fail", i, e: msg });
          }
        }
        progress.processed++;
        options.onProgress?.({ ...progress });
      }
    };
    const n = Math.max(1, Math.min(options.concurrency, queue.length || 1));
    await Promise.all(Array.from({ length: n }, () => worker()));
    await this.appendChain;

    const unfinished = j.states.some((s) => s !== "done" && s !== "skip");
    if (!unfinished) {
      // A crash between logging "done" and removing the temp copy leaves the
      // copy behind; nothing would ever look at it again.
      for (let i = 0; i < j.paths.length; i++) await this.removeIfExists(this.tmpPath(i));
      await this.removeIfExists(this.journalPath);
    }
    return {
      op: j.op,
      total: j.paths.length,
      changed: progress.changed,
      skipped: progress.skipped,
      failed,
      cancelled: cancelled && unfinished,
      meta: j.meta,
    };
  }

  private async processOne(i: number, path: string, state: FileState, transform: FileTransform): Promise<FileState> {
    const tmp = this.tmpPath(i);
    if (state === "temp") {
      // We crashed after the verified temporary copy was logged. Finish the
      // replacement from it rather than re-reading a possibly torn original.
      // If that fails again, stay at "temp" (AfterTempError): the original
      // must never be re-read and judged while the copy is the only truth.
      let finished: boolean;
      try {
        finished = await this.finishFromTemp(i, path);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        throw new AfterTempError(`${msg}; the verified temporary copy is kept for the next resume`);
      }
      if (finished) {
        await this.log({ s: "done", i });
        await this.removeIfExists(tmp);
        return "done";
      }
      // No temporary copy: the original was replaced and the copy removed
      // before "done" was logged. Fall through; the transform will skip it.
    }
    if (!path || !(await this.io.exists(path))) {
      await this.log({ s: "skip", i });
      return "skip";
    }
    const current = new Uint8Array(await this.io.readBinary(path));
    const result = await transform(path, current);
    if (!result) {
      await this.log({ s: "skip", i });
      await this.removeIfExists(tmp);
      return "skip";
    }
    const output = result.output;
    await this.io.writeBinary(tmp, toArrayBuffer(output));
    const tmpBack = new Uint8Array(await this.io.readBinary(tmp));
    if (!bytesEqual(tmpBack, output) || !(await result.verify(tmpBack))) {
      await this.removeIfExists(tmp);
      throw new Error("Verification of the temporary copy failed; the original was not touched");
    }
    // Someone changed the file while we worked on it (an edit through the
    // hook): do not replace it with stale content. Resume will retry.
    const again = new Uint8Array(await this.io.readBinary(path));
    if (!bytesEqual(again, current)) {
      await this.removeIfExists(tmp);
      throw new Error("The file changed while the job was running; it was left as it is and will be retried");
    }
    await this.log({ s: "temp", i });
    try {
      await this.io.writeBinary(path, toArrayBuffer(output));
      const back = new Uint8Array(await this.io.readBinary(path));
      if (!bytesEqual(back, output)) throw new Error("Read-back mismatch after replacing the original");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new AfterTempError(`${msg}; resume finishes it from the verified temporary copy`);
    }
    await this.log({ s: "done", i });
    await this.removeIfExists(tmp);
    return "done";
  }
}

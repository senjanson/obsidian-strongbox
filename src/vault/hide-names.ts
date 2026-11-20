/**
 * Hiding file names and folder structure (experimental, off by default).
 *
 * On lock every protected file and folder is renamed to a random
 * placeholder (`sbx-` + 16 hex digits, no extension); the list of renames is
 * encrypted with the master key and saved as the manifest. On unlock the
 * renames are undone in reverse order. Contents are never rewritten.
 *
 * Crash safety:
 * - The manifest (and a backup copy) is written and read back before the
 *   first rename, so the mapping exists on disk before any name is lost.
 * - A plain journal logs each rename by its index only (no names). It is
 *   informative; recovery itself relies on what exists on disk: step i is
 *   hidden when its placeholder exists and its real path does not. Because
 *   renames run children-first on hide and parents-first on reveal, those
 *   paths are always valid at the moment a step is checked.
 * - The manifest is removed only after every step has been undone; if
 *   anything is off (a placeholder went missing, the real name was taken
 *   meanwhile), it stays, and the problems are reported.
 */
import { Bytes, fromUtf8, randomBytes, toArrayBuffer, utf8 } from "../crypto/bytes";
import { KeyProvider, decryptContainer, encryptContainer } from "../crypto/container";
import { ProtectionPolicy, normPath } from "./rules";

export interface HideIO {
  list(path: string): Promise<{ files: string[]; folders: string[] }>;
  rename(from: string, to: string): Promise<void>;
  exists(path: string): Promise<boolean>;
  read(path: string): Promise<string>;
  readBinary(path: string): Promise<ArrayBuffer>;
  write(path: string, data: string): Promise<void>;
  writeBinary(path: string, data: ArrayBuffer): Promise<void>;
  append(path: string, data: string): Promise<void>;
  remove(path: string): Promise<void>;
}

export interface HideStep {
  from: string;
  to: string;
  folder: boolean;
}

interface Manifest {
  format: "strongbox-names";
  version: 1;
  id: string;
  created: number;
  steps: HideStep[];
}

export const HIDDEN_NAME_RE = /^sbx-[0-9a-f]{16}$/;

export function isHiddenName(name: string): boolean {
  return HIDDEN_NAME_RE.test(name);
}

/** True when any segment of the path is a placeholder name. */
export function pathHasHiddenSegment(path: string): boolean {
  return normPath(path).split("/").some(isHiddenName);
}

function randomName(): string {
  return "sbx-" + Array.from(randomBytes(8), (b) => b.toString(16).padStart(2, "0")).join("");
}

function parentOf(path: string): string {
  const i = path.lastIndexOf("/");
  return i < 0 ? "" : path.slice(0, i);
}

function join(dir: string, name: string): string {
  return dir ? `${dir}/${name}` : name;
}

export interface RevealResult {
  restored: number;
  problems: string[];
}

export class NameHider {
  constructor(
    private readonly io: HideIO,
    private readonly policy: ProtectionPolicy,
    private readonly paths: { manifest: string; journal: string },
  ) {}

  private get backupPath(): string {
    return this.paths.manifest + ".bak";
  }

  /** True while names are hidden (or a hide/reveal was interrupted). */
  async isHidden(): Promise<boolean> {
    return (await this.io.exists(this.paths.manifest)) || (await this.io.exists(this.backupPath));
  }

  /** The renames that hiding would perform now, children before parents. */
  async plan(): Promise<HideStep[]> {
    const steps: HideStep[] = [];
    const taken = new Set<string>();
    const fresh = (dir: string): string => {
      for (;;) {
        const p = join(dir, randomName());
        if (!taken.has(p)) {
          taken.add(p);
          return p;
        }
      }
    };
    const walk = async (folder: string): Promise<void> => {
      const { files, folders } = await this.io.list(folder);
      for (const sub of folders.map(normPath)) {
        if (this.policy.isExcluded(sub) || isHiddenName(sub.slice(sub.lastIndexOf("/") + 1))) continue;
        await walk(sub);
        if (this.policy.isFolderProtected(sub) && !this.policy.containsExcluded(sub)) {
          steps.push({ from: sub, to: fresh(parentOf(sub)), folder: true });
        }
      }
      for (const f of files.map(normPath)) {
        if (isHiddenName(f.slice(f.lastIndexOf("/") + 1))) continue;
        if (this.policy.isProtected(f)) steps.push({ from: f, to: fresh(parentOf(f)), folder: false });
      }
    };
    await walk("");
    // Files of a folder must be renamed before the folder itself; walk()
    // pushes a sub-folder's step right after its own contents, but files of
    // the parent come later, which is fine (they are siblings, not children).
    return steps;
  }

  private async readManifest(keys: KeyProvider): Promise<Manifest | null> {
    for (const p of [this.paths.manifest, this.backupPath]) {
      if (!(await this.io.exists(p))) continue;
      try {
        const plain = await decryptContainer(new Uint8Array(await this.io.readBinary(p)), keys);
        const m = JSON.parse(fromUtf8(plain)) as Manifest;
        if (m.format === "strongbox-names" && Array.isArray(m.steps)) return m;
      } catch {
        /* try the backup */
      }
    }
    return null;
  }

  private async writeVerified(path: string, data: Bytes, keys: KeyProvider, json: string): Promise<void> {
    await this.io.writeBinary(path, toArrayBuffer(data));
    const back = await decryptContainer(new Uint8Array(await this.io.readBinary(path)), keys);
    if (fromUtf8(back) !== json) throw new Error("Name manifest did not read back correctly");
  }

  private async journalLines(): Promise<string[]> {
    if (!(await this.io.exists(this.paths.journal))) return [];
    return (await this.io.read(this.paths.journal)).split("\n").filter(Boolean);
  }

  /**
   * Hides protected names. Returns the number of renames. Does nothing when
   * names are already hidden (an earlier reveal has to finish first).
   */
  async hide(keys: KeyProvider, onStep?: (done: number, total: number) => void): Promise<number> {
    if (await this.isHidden()) return 0;
    const steps = await this.plan();
    if (steps.length === 0) return 0;
    const id = Array.from(randomBytes(8), (b) => b.toString(16).padStart(2, "0")).join("");
    const manifest: Manifest = { format: "strongbox-names", version: 1, id, created: Date.now(), steps };
    const json = JSON.stringify(manifest);
    const sealed = await encryptContainer(utf8(json), keys);
    await this.io.write(this.paths.journal, JSON.stringify({ id, phase: "hide", steps: steps.length }) + "\n");
    await this.writeVerified(this.paths.manifest, sealed, keys, json);
    await this.writeVerified(this.backupPath, sealed, keys, json);
    await this.io.append(this.paths.journal, "ready\n");

    let done = 0;
    for (let i = 0; i < steps.length; i++) {
      const s = steps[i];
      if (!(await this.io.exists(s.from)) || (await this.io.exists(s.to))) {
        await this.io.append(this.paths.journal, `x ${i}\n`);
        continue;
      }
      await this.io.rename(s.from, s.to);
      await this.io.append(this.paths.journal, `h ${i}\n`);
      done++;
      onStep?.(done, steps.length);
    }
    return done;
  }

  /**
   * Restores real names from the manifest. Safe to call repeatedly and
   * after a crash at any point of hide() or reveal().
   */
  async reveal(keys: KeyProvider, onStep?: (done: number, total: number) => void): Promise<RevealResult> {
    if (!(await this.isHidden())) return { restored: 0, problems: [] };
    const manifest = await this.readManifest(keys);
    if (!manifest) {
      const lines = await this.journalLines();
      if (!lines.includes("ready")) {
        // We crashed while writing the manifest, before any rename: nothing is hidden.
        await this.cleanup();
        return { restored: 0, problems: [] };
      }
      return { restored: 0, problems: ["The name manifest cannot be opened with the current keys; it was kept untouched."] };
    }
    const lines = await this.journalLines();
    // Steps hide() skipped because the file was already gone.
    const skipped = new Set(lines.filter((l) => l.startsWith("x ")).map((l) => Number(l.slice(2))));
    await this.io.append(this.paths.journal, `reveal\n`);
    const problems: string[] = [];
    let restored = 0;
    for (let i = manifest.steps.length - 1; i >= 0; i--) {
      const s = manifest.steps[i];
      if (skipped.has(i)) continue;
      const hiddenExists = await this.io.exists(s.to);
      const realExists = await this.io.exists(s.from);
      if (hiddenExists && !realExists) {
        await this.io.rename(s.to, s.from);
        await this.io.append(this.paths.journal, `r ${i}\n`);
        restored++;
        onStep?.(restored, manifest.steps.length);
      } else if (hiddenExists && realExists) {
        problems.push(`Both "${s.from}" and its placeholder "${s.to}" exist; left as they are.`);
      }
      // Neither hidden nor real missing → never hidden or already restored.
      // Real missing too → the placeholder vanished (moved or deleted meanwhile).
      else if (!hiddenExists && !realExists) {
        problems.push(`"${s.from}" (placeholder "${s.to}") is missing.`);
      }
    }
    if (problems.length === 0) await this.cleanup();
    return { restored, problems };
  }

  /** The saved mapping (for showing it to the user when something went wrong). */
  async describe(keys: KeyProvider): Promise<HideStep[] | null> {
    const m = await this.readManifest(keys);
    return m ? m.steps : null;
  }

  /** Deletes the manifest and journal even though problems remain. */
  async forget(): Promise<void> {
    await this.cleanup();
  }

  private async cleanup(): Promise<void> {
    for (const p of [this.paths.manifest, this.backupPath, this.paths.journal]) {
      if (await this.io.exists(p)) await this.io.remove(p);
    }
  }
}

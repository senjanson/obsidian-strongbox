/**
 * Which paths Strongbox protects. A rule names a file, a folder (and
 * everything below it) or the whole vault. Some paths are never protected:
 * the config folder (which holds the plugin itself and its keyring), the
 * trash, and whatever the user excluded.
 */

export type RuleType = "file" | "folder" | "vault";

export interface ProtectionRule {
  type: RuleType;
  /** Vault-relative path without leading or trailing slashes; "" for the vault. */
  path: string;
}

export interface PolicyOptions {
  configDir: string;
  rules: ProtectionRule[];
  excludes: string[];
  textExtensions: string[];
  /** Plugin-internal files (keyring, journals …), always excluded. */
  extraExcludes?: string[];
}

/** Normalizes a vault path the way Obsidian does (forward slashes, no leading/trailing slash). */
export function normPath(path: string): string {
  let p = path.replace(/\\/g, "/").replace(/\/{2,}/g, "/");
  p = p.replace(/^\.\/+/, "").replace(/^\/+/, "").replace(/\/+$/, "");
  return p === "." ? "" : p;
}

/** True when `path` is `base` itself or lies inside it. "" contains everything. */
export function isWithin(path: string, base: string): boolean {
  if (base === "") return true;
  return path === base || path.startsWith(base + "/");
}

export function extensionOf(path: string): string {
  const name = path.slice(path.lastIndexOf("/") + 1);
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot + 1).toLowerCase() : "";
}

export class ProtectionPolicy {
  private configDir: string;
  private rules: ProtectionRule[] = [];
  private excludes: string[] = [];
  private extraExcludes: string[] = [];
  private textExt = new Set<string>();

  constructor(options: PolicyOptions) {
    this.configDir = normPath(options.configDir);
    this.update(options);
  }

  update(options: Partial<PolicyOptions>): void {
    if (options.configDir !== undefined) this.configDir = normPath(options.configDir);
    if (options.rules) {
      this.rules = options.rules.map((r) => ({ type: r.type, path: r.type === "vault" ? "" : normPath(r.path) }));
    }
    if (options.excludes) this.excludes = options.excludes.map(normPath).filter((p) => p !== "");
    if (options.extraExcludes) this.extraExcludes = options.extraExcludes.map(normPath).filter((p) => p !== "");
    if (options.textExtensions) {
      this.textExt = new Set(options.textExtensions.map((e) => e.replace(/^\./, "").toLowerCase()).filter(Boolean));
    }
  }

  getRules(): ProtectionRule[] {
    return this.rules.map((r) => ({ ...r }));
  }

  /** Paths Strongbox never encrypts, whatever the rules say. */
  isExcluded(rawPath: string): boolean {
    const path = normPath(rawPath);
    if (this.isSystemExcluded(path)) return true;
    return this.excludes.some((e) => isWithin(path, e));
  }

  /** The built-in exclusions only (config folder, trash, dot paths, OS litter), not the user's list. */
  isSystemExcluded(rawPath: string): boolean {
    const path = normPath(rawPath);
    if (path === "") return true;
    if (isWithin(path, this.configDir)) return true;
    if (isWithin(path, ".trash")) return true;
    if (this.extraExcludes.some((e) => isWithin(path, e))) return true;
    // Dot folders and files (.git, .github …) are not part of the vault in
    // Obsidian's eyes; encrypting them would break the tools that own them.
    if (path.split("/").some((seg) => seg.startsWith("."))) return true;
    const name = path.slice(path.lastIndexOf("/") + 1);
    // Key file backups ("Save copy in vault", or a download moved into the
    // vault): encrypting one with the key it backs up would make it useless.
    if (isKeyringBackupName(name)) return true;
    // OS litter.
    return name === ".DS_Store" || name === "Thumbs.db" || name === "desktop.ini";
  }

  /** The rule that covers the path, if any (most specific first). */
  ruleFor(rawPath: string): ProtectionRule | null {
    const path = normPath(rawPath);
    if (this.isExcluded(path)) return null;
    let best: ProtectionRule | null = null;
    let bestScore = -1;
    for (const r of this.rules) {
      const hit = r.type === "file" ? path === r.path : isWithin(path, r.path);
      if (!hit) continue;
      const score = r.type === "vault" ? 0 : r.path.length + (r.type === "file" ? 1 : 0);
      if (score > bestScore) {
        best = r;
        bestScore = score;
      }
    }
    return best;
  }

  isProtected(path: string): boolean {
    return this.ruleFor(path) !== null;
  }

  /** True when a folder rule or the vault rule covers this folder. */
  isFolderProtected(rawPath: string): boolean {
    const path = normPath(rawPath);
    if (this.isExcluded(path) && path !== "") return false;
    return this.rules.some((r) => r.type !== "file" && isWithin(path, r.path));
  }

  /** True when some excluded path lies inside this folder. */
  containsExcluded(rawFolder: string): boolean {
    const folder = normPath(rawFolder);
    const all = [this.configDir, ".trash", ...this.extraExcludes, ...this.excludes];
    return all.some((e) => e !== folder && isWithin(e, folder));
  }

  isTextPath(path: string): boolean {
    return this.textExt.has(extensionOf(path));
  }

  hasRule(type: RuleType, rawPath: string): boolean {
    const path = type === "vault" ? "" : normPath(rawPath);
    return this.rules.some((r) => r.type === type && r.path === path);
  }
}

/** Adds a rule unless an identical one exists; returns the new list. */
export function addRule(rules: ProtectionRule[], rule: ProtectionRule): ProtectionRule[] {
  const path = rule.type === "vault" ? "" : normPath(rule.path);
  if (rules.some((r) => r.type === rule.type && normPath(r.path) === path)) return rules;
  return [...rules, { type: rule.type, path }];
}

export function removeRule(rules: ProtectionRule[], rule: ProtectionRule): ProtectionRule[] {
  const path = rule.type === "vault" ? "" : normPath(rule.path);
  return rules.filter((r) => !(r.type === rule.type && normPath(r.path) === path));
}

/** Rewrites rules after a file or folder was renamed inside the vault. */
export function renameInRules(rules: ProtectionRule[], oldPath: string, newPath: string): ProtectionRule[] {
  const from = normPath(oldPath);
  const to = normPath(newPath);
  let changed = false;
  const out = rules.map((r) => {
    if (r.type === "vault") return r;
    if (r.path === from || r.path.startsWith(from + "/")) {
      changed = true;
      return { ...r, path: to + r.path.slice(from.length) };
    }
    return r;
  });
  return changed ? out : rules;
}

/** File names Strongbox gives key file backups (in the vault or downloaded). */
export function isKeyringBackupName(name: string): boolean {
  return /^Strongbox keyring backup .*\.json$/.test(name) || /^strongbox-keyring-.*\.json$/.test(name);
}

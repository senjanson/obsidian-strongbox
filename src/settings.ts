import { KdfAlgorithm } from "./crypto/kdf";
import { ProtectionRule } from "./vault/rules";

export interface StrongboxSettings {
  /** What is protected. Paths are stored in plain text in data.json. */
  rules: ProtectionRule[];
  /** Paths never encrypted (folders cover everything inside them). */
  excludes: string[];
  /** Extensions stored with the readable text shell instead of the binary container. */
  textExtensions: string[];
  /** KDF used the next time a password is set. */
  kdfAlgorithm: KdfAlgorithm;
  argon2MemoryMiB: number;
  argon2Iterations: number;
  argon2Parallelism: number;
  pbkdf2Iterations: number;
  /** Lock after this many minutes without input; 0 = never. */
  idleMinutes: number;
  /** Mobile: lock when the app was in the background this long; 0 = at once, -1 = never. */
  backgroundLockSeconds: number;
  showStatusBar: boolean;
  /** Experimental: rename protected files and folders to placeholders while locked. */
  hideNames: boolean;
  /** "Also encrypt attachments" is ticked by default in the file menu dialog. */
  includeAttachmentsByDefault: boolean;
}

export const DEFAULT_SETTINGS: StrongboxSettings = {
  rules: [],
  excludes: [],
  textExtensions: ["md", "canvas", "base"],
  kdfAlgorithm: "argon2id",
  argon2MemoryMiB: 64,
  argon2Iterations: 3,
  argon2Parallelism: 1,
  pbkdf2Iterations: 600_000,
  idleMinutes: 10,
  backgroundLockSeconds: 60,
  showStatusBar: true,
  hideNames: false,
  includeAttachmentsByDefault: true,
};

export function mergeSettings(stored: unknown): StrongboxSettings {
  const s = { ...DEFAULT_SETTINGS, ...((stored as Partial<StrongboxSettings>) ?? {}) };
  s.rules = Array.isArray(s.rules)
    ? s.rules.filter((r) => r && (r.type === "file" || r.type === "folder" || r.type === "vault") && typeof r.path === "string")
    : [];
  s.excludes = Array.isArray(s.excludes) ? s.excludes.filter((e) => typeof e === "string") : [];
  s.textExtensions = Array.isArray(s.textExtensions) ? s.textExtensions.filter((e) => typeof e === "string") : DEFAULT_SETTINGS.textExtensions;
  if (s.kdfAlgorithm !== "argon2id" && s.kdfAlgorithm !== "pbkdf2-sha256") s.kdfAlgorithm = "argon2id";
  return s;
}

/**
 * Password-based key derivation: Argon2id (via hash-wasm, whose WebAssembly
 * is inlined as base64 in the bundle, so nothing is fetched) or
 * PBKDF2-HMAC-SHA-256 (Web Crypto). Either one yields 32 bytes.
 */
import { argon2id } from "hash-wasm";
import { Bytes, copyBytes, fromBase64, randomBytes, toBase64, utf8, wipe } from "./bytes";

export type KdfAlgorithm = "argon2id" | "pbkdf2-sha256";

export interface Argon2idParams {
  alg: "argon2id";
  /** Memory in KiB. */
  memKiB: number;
  iterations: number;
  parallelism: number;
  /** base64 */
  salt: string;
}

export interface Pbkdf2Params {
  alg: "pbkdf2-sha256";
  iterations: number;
  /** base64 */
  salt: string;
}

export type KdfParams = Argon2idParams | Pbkdf2Params;

export const DEFAULT_ARGON2 = { memKiB: 64 * 1024, iterations: 3, parallelism: 1 } as const;
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;
export const KDF_SALT_BYTES = 16;
export const DERIVED_KEY_BYTES = 32;

/** Limits that keep a tampered or hand-edited file from hanging the app. */
const LIMITS = {
  argonMemMinKiB: 8,
  argonMemMaxKiB: 1024 * 1024,
  argonIterMax: 64,
  argonParMax: 16,
  pbkdf2Min: 1,
  pbkdf2Max: 50_000_000,
};

export class KdfParamsError extends Error {}

/** New parameters with a fresh random salt. */
export function newKdfParams(
  alg: KdfAlgorithm,
  options: { memKiB?: number; iterations?: number; parallelism?: number } = {},
): KdfParams {
  const salt = toBase64(randomBytes(KDF_SALT_BYTES));
  if (alg === "argon2id") {
    return {
      alg,
      memKiB: options.memKiB ?? DEFAULT_ARGON2.memKiB,
      iterations: options.iterations ?? DEFAULT_ARGON2.iterations,
      parallelism: options.parallelism ?? DEFAULT_ARGON2.parallelism,
      salt,
    };
  }
  return { alg, iterations: options.iterations ?? DEFAULT_PBKDF2_ITERATIONS, salt };
}

export function validateKdfParams(p: unknown): KdfParams {
  const o = p as Record<string, unknown> | null;
  if (!o || typeof o !== "object") throw new KdfParamsError("Missing KDF parameters");
  const int = (v: unknown, min: number, max: number, name: string): number => {
    if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) {
      throw new KdfParamsError(`Bad KDF parameter ${name}`);
    }
    return v;
  };
  if (typeof o.salt !== "string") throw new KdfParamsError("Bad KDF salt");
  const salt = fromBase64(o.salt);
  if (salt.length < 8) throw new KdfParamsError("KDF salt too short");
  if (o.alg === "argon2id") {
    return {
      alg: "argon2id",
      memKiB: int(o.memKiB, LIMITS.argonMemMinKiB, LIMITS.argonMemMaxKiB, "memKiB"),
      iterations: int(o.iterations, 1, LIMITS.argonIterMax, "iterations"),
      parallelism: int(o.parallelism, 1, LIMITS.argonParMax, "parallelism"),
      salt: o.salt,
    };
  }
  if (o.alg === "pbkdf2-sha256") {
    return {
      alg: "pbkdf2-sha256",
      iterations: int(o.iterations, LIMITS.pbkdf2Min, LIMITS.pbkdf2Max, "iterations"),
      salt: o.salt,
    };
  }
  throw new KdfParamsError("Unknown KDF algorithm");
}

/** Passwords are compared as NFC so the same password typed on two OSes matches. */
export function normalizePassword(password: string): Bytes {
  return utf8(password.normalize("NFC"));
}

/** Runs the KDF and returns 32 raw bytes. Callers should wipe() them when done. */
export async function deriveKeyBytes(password: string, params: KdfParams): Promise<Bytes> {
  const checked = validateKdfParams(params);
  const salt = fromBase64(checked.salt);
  const pw = normalizePassword(password);
  try {
    if (checked.alg === "argon2id") {
      const out = await argon2id({
        password: pw,
        salt,
        parallelism: checked.parallelism,
        iterations: checked.iterations,
        memorySize: checked.memKiB,
        hashLength: DERIVED_KEY_BYTES,
        outputType: "binary",
      });
      return copyBytes(out);
    }
    const base = await crypto.subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: checked.iterations },
      base,
      DERIVED_KEY_BYTES * 8,
    );
    return new Uint8Array(bits);
  } finally {
    wipe(pw);
  }
}

/** Derives a non-extractable AES-256-GCM key from the password. */
export async function deriveAesKey(password: string, params: KdfParams): Promise<CryptoKey> {
  const raw = await deriveKeyBytes(password, params);
  try {
    return await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  } finally {
    wipe(raw);
  }
}

/** A short, stable description of the parameters (without the salt). */
export function describeKdf(params: KdfParams): string {
  if (params.alg === "argon2id") {
    return `Argon2id (${Math.round(params.memKiB / 1024)} MiB, ${params.iterations} passes, parallelism ${params.parallelism})`;
  }
  return `PBKDF2-SHA-256 (${params.iterations.toLocaleString("en-US")} iterations)`;
}

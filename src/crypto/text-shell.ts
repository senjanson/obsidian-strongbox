/**
 * The text shell used for note-like files (md, canvas, base …): a first line
 * a person can read, then the binary container in base64, 76 characters a
 * line. Opening the file in any editor shows the warning instead of noise,
 * and sync tools that treat these files as text keep working.
 */
import { Bytes, fromBase64, fromUtf8Strict, startsWithBytes, toBase64, utf8 } from "./bytes";
import { isContainer } from "./container";

/** Every shell starts with exactly this; detection keys on it. */
export const SHELL_PREFIX = "STRONGBOX-ENCRYPTED-FILE v1 ·";
export const SHELL_FIRST_LINE =
  `${SHELL_PREFIX} 此文件已被 Strongbox 加密，请勿手动编辑。This file is encrypted by Strongbox; do not edit it by hand.`;
const SHELL_PREFIX_BYTES = utf8(SHELL_PREFIX);
const LINE = 76;

export function wrapShell(container: Uint8Array): string {
  const b64 = toBase64(container);
  const lines: string[] = [SHELL_FIRST_LINE];
  for (let i = 0; i < b64.length; i += LINE) lines.push(b64.slice(i, i + LINE));
  return lines.join("\n") + "\n";
}

export function looksLikeShell(text: string): boolean {
  return text.startsWith(SHELL_PREFIX);
}

export function looksLikeShellBytes(data: Uint8Array): boolean {
  return startsWithBytes(data, SHELL_PREFIX_BYTES);
}

/**
 * Pulls the container out of a shell. Returns null when the text is not a
 * well-formed shell (for example a note that merely quotes the first line),
 * so callers can treat it as ordinary text.
 */
export function unwrapShell(text: string): Bytes | null {
  if (!looksLikeShell(text)) return null;
  const nl = text.indexOf("\n");
  if (nl < 0) return null;
  const body = text.slice(nl + 1);
  if (!/^[A-Za-z0-9+/=\r\n]+$/.test(body)) return null;
  let data: Bytes;
  try {
    data = fromBase64(body);
  } catch {
    return null;
  }
  return isContainer(data) ? data : null;
}

export function unwrapShellBytes(data: Uint8Array): Bytes | null {
  if (!looksLikeShellBytes(data)) return null;
  const text = fromUtf8Strict(data);
  return text === null ? null : unwrapShell(text);
}

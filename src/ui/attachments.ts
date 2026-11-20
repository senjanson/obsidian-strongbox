/**
 * Encrypted attachments in notes.
 *
 * Obsidian shows images, audio, video and PDFs by pointing the element at a
 * resource URL (getResourcePath) that the app serves straight from disk,
 * bypassing the adapter hook — so an encrypted attachment would show as
 * broken. This watches the DOM (reading view and Live Preview alike) for
 * such elements and, while unlocked, swaps their URL for a Blob URL of the
 * decrypted bytes. On lock every Blob URL is revoked and the original URL
 * put back.
 *
 * NOT VERIFIED IN A REAL OBSIDIAN (desktop or mobile): resource URL formats
 * differ per platform and Obsidian version, and PDFs open in Obsidian's own
 * viewer, which may not follow this path. The code is deliberately
 * conservative: it only touches elements whose URL exactly matches the
 * resource URL of a file it knows to be encrypted.
 */
import { App, TFile } from "obsidian";

const MIME: Record<string, string> = {
  png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", svg: "image/svg+xml",
  bmp: "image/bmp", avif: "image/avif", ico: "image/x-icon",
  mp3: "audio/mpeg", wav: "audio/wav", m4a: "audio/mp4", ogg: "audio/ogg", flac: "audio/flac", webm: "video/webm", "3gp": "video/3gpp",
  mp4: "video/mp4", mov: "video/quicktime", mkv: "video/x-matroska", ogv: "video/ogg",
  pdf: "application/pdf",
};

const ORIG_ATTR = "data-strongbox-src";
const SELECTOR = "img, video, audio, source, embed, iframe, object";

export interface AttachmentHost {
  isUnlocked(): boolean;
  /** Whether the file at this path is (or should be) encrypted on disk. */
  isEncryptedPath(path: string): boolean;
}

export class AttachmentRenderer {
  /** One observer per window document (main window and popouts). */
  private observers = new Map<Document, MutationObserver>();
  /** vault path → Blob URL */
  private blobs = new Map<string, string>();
  /** resource URL without query → vault path */
  private index = new Map<string, string>();
  private indexDirty = true;
  private touched = new Set<HTMLElement>();

  constructor(private readonly app: App, private readonly host: AttachmentHost) {}

  /** Starts watching the main window; popouts are added with watch(). */
  start(): void {
    this.watch(activeDocument);
  }

  /** Watches one window's document for media that point at encrypted files. */
  watch(doc: Document): void {
    if (this.observers.has(doc) || typeof MutationObserver === "undefined") return;
    const observer = new MutationObserver((records) => {
      if (!this.host.isUnlocked()) return;
      for (const r of records) {
        if (r.type === "attributes" && r.target.instanceOf(HTMLElement)) this.consider(r.target);
        for (const n of Array.from(r.addedNodes)) {
          if (!n.instanceOf(HTMLElement)) continue;
          if (n.matches(SELECTOR)) this.consider(n);
          n.querySelectorAll(SELECTOR).forEach((el) => this.consider(el as HTMLElement));
        }
      }
    });
    observer.observe(doc.body, { subtree: true, childList: true, attributes: true, attributeFilter: ["src", "data"] });
    this.observers.set(doc, observer);
    if (this.host.isUnlocked()) this.scan(doc);
  }

  /** A popout window closed. */
  unwatch(doc: Document): void {
    this.observers.get(doc)?.disconnect();
    this.observers.delete(doc);
  }

  stop(): void {
    for (const observer of this.observers.values()) observer.disconnect();
    this.observers.clear();
    this.revokeAll();
  }

  /** The set of encrypted files changed. */
  invalidate(path?: string): void {
    this.indexDirty = true;
    if (path) {
      const url = this.blobs.get(path);
      if (url) URL.revokeObjectURL(url);
      this.blobs.delete(path);
    }
  }

  /** After unlocking: fix up whatever is already on screen. */
  rescan(): void {
    if (!this.host.isUnlocked()) return;
    for (const doc of this.observers.keys()) this.scan(doc);
  }

  private scan(doc: Document): void {
    doc.querySelectorAll(SELECTOR).forEach((el) => this.consider(el as HTMLElement));
  }

  /** On lock: put every original URL back and revoke all Blob URLs. */
  revokeAll(): void {
    for (const el of this.touched) {
      const orig = el.getAttribute(ORIG_ATTR);
      if (orig !== null) {
        el.removeAttribute(ORIG_ATTR);
        if (el.tagName === "OBJECT") el.setAttribute("data", orig);
        else el.setAttribute("src", orig);
      }
    }
    this.touched.clear();
    for (const url of this.blobs.values()) URL.revokeObjectURL(url);
    this.blobs.clear();
  }

  private rebuildIndex(): void {
    this.index.clear();
    for (const file of this.app.vault.getFiles()) {
      if (!this.host.isEncryptedPath(file.path)) continue;
      try {
        const url = this.app.vault.getResourcePath(file);
        this.index.set(resourceKey(url), file.path);
      } catch {
        /* ignore */
      }
    }
    this.indexDirty = false;
  }

  private pathFor(url: string): string | null {
    if (this.indexDirty) this.rebuildIndex();
    return this.index.get(resourceKey(url)) ?? null;
  }

  private consider(el: HTMLElement): void {
    if (el.hasAttribute(ORIG_ATTR)) return;
    const attr = el.tagName === "OBJECT" ? "data" : "src";
    const src = el.getAttribute(attr);
    if (!src || src.startsWith("blob:") || src.startsWith("data:")) return;
    const path = this.pathFor(src);
    if (!path) return;
    void this.swap(el, attr, src, path);
  }

  private async swap(el: HTMLElement, attr: string, src: string, path: string): Promise<void> {
    try {
      const url = await this.blobUrl(path);
      if (!url || !this.host.isUnlocked() || el.getAttribute(attr) !== src) return;
      el.setAttribute(ORIG_ATTR, src);
      this.touched.add(el);
      el.setAttribute(attr, url);
      if (el.tagName === "SOURCE") (el.parentElement as HTMLMediaElement | null)?.load?.();
    } catch (e) {
      console.warn("Strongbox: could not show encrypted attachment", path, e);
    }
  }

  private async blobUrl(path: string): Promise<string | null> {
    const cached = this.blobs.get(path);
    if (cached) return cached;
    const file = this.app.vault.getAbstractFileByPath(path);
    if (!(file instanceof TFile)) return null;
    // Goes through the adapter hook, so this is the decrypted content.
    const data = await this.app.vault.readBinary(file);
    if (!this.host.isUnlocked()) return null;
    const url = URL.createObjectURL(new Blob([data], { type: MIME[file.extension.toLowerCase()] ?? "application/octet-stream" }));
    this.blobs.set(path, url);
    return url;
  }
}

/**
 * Comparable form of a resource URL: no query string, percent-escapes
 * decoded and Unicode in NFC, so the DOM's spelling of a non-ASCII path
 * (escaped or not, NFC or NFD as some platforms store it) still matches
 * getResourcePath().
 */
export function resourceKey(url: string): string {
  const q = url.indexOf("?");
  let s = q < 0 ? url : url.slice(0, q);
  try {
    s = decodeURI(s);
  } catch {
    /* malformed escape: compare as is */
  }
  return s.normalize("NFC");
}

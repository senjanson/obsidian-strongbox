/**
 * Lock badges in the file explorer. Obsidian has no public API for this, so
 * it reads the explorer view's `fileItems` map (private, but stable for
 * years) and toggles a CSS class; if the internals change it silently does
 * nothing. Not verified in a real Obsidian.
 */
import { App, TFolder, debounce } from "obsidian";

export interface BadgeHost {
  isProtectedFile(path: string): boolean;
  isProtectedFolder(path: string): boolean;
}

export const BADGE_CLASS = "strongbox-protected";

export class ExplorerBadges {
  readonly refreshSoon = debounce(() => this.refresh(), 300, true);

  constructor(private readonly app: App, private readonly host: BadgeHost) {}

  refresh(): void {
    for (const leaf of this.app.workspace.getLeavesOfType("file-explorer")) {
      const items = (leaf.view as unknown as { fileItems?: Record<string, { el?: HTMLElement; selfEl?: HTMLElement; file?: unknown } | undefined> }).fileItems;
      if (!items) continue;
      for (const [path, item] of Object.entries(items)) {
        if (!item) continue;
        const el = item.selfEl ?? item.el;
        if (!el) continue;
        const isFolder = item.file instanceof TFolder;
        const on = isFolder ? this.host.isProtectedFolder(path) : this.host.isProtectedFile(path);
        el.toggleClass(BADGE_CLASS, on);
      }
    }
  }

  clear(): void {
    for (const leaf of this.app.workspace.getLeavesOfType("file-explorer")) {
      leaf.view.containerEl.querySelectorAll("." + BADGE_CLASS).forEach((el) => el.removeClass(BADGE_CLASS));
    }
  }
}

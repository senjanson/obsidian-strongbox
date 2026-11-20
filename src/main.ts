import {
  Editor,
  MarkdownView,
  Menu,
  Notice,
  Platform,
  Plugin,
  TAbstractFile,
  TFile,
  TFolder,
  TextFileView,
  WorkspaceLeaf,
  setIcon,
} from "obsidian";
import { fromUtf8 } from "./crypto/bytes";
import { containerKeyId } from "./crypto/container";
import {
  decryptInline,
  encryptInlineWithMaster,
  encryptInlineWithPassword,
  findInlineBlocks,
  inlineBlockMode,
} from "./crypto/inline";
import { KdfParams, newKdfParams } from "./crypto/kdf";
import {
  KeyringFile,
  MasterKeys,
  WrongPasswordError,
  addMasterKey,
  changeKeyringPassword,
  createKeyring,
  parseKeyring,
  removeMasterKeys,
  serializeKeyring,
  unlockKeyring,
} from "./crypto/keyring";
import { t } from "./i18n";
import { DEFAULT_SETTINGS, StrongboxSettings, mergeSettings } from "./settings";
import { AttachmentRenderer } from "./ui/attachments";
import { ExplorerBadges } from "./ui/explorer-badges";
import { inlineEditorExtension, inlinePostProcessor } from "./ui/inline-render";
import {
  InlineViewModal,
  ProgressModal,
  UnlockModal,
  UnlockOutcome,
  askProtectFile,
  chooseInlineMode,
  confirmDialog,
  promptPassword,
} from "./ui/modals";
import { MIN_PASSWORD_LENGTH, SetupWizard } from "./ui/setup-wizard";
import { StrongboxSettingTab } from "./ui/settings-tab";
import { AdapterHook } from "./vault/adapter-hook";
import { BatchEngine, BatchIO, BatchOp, BatchResult, FileTransform } from "./vault/batch";
import { FileCodec, containerOf, detectForm } from "./vault/codec";
import { HideIO, NameHider, pathHasHiddenSegment } from "./vault/hide-names";
import { ProtectionPolicy, ProtectionRule, addRule, isWithin, normPath, removeRule, renameInRules } from "./vault/rules";
import { decryptTransform, encryptTransform, rekeyTransform } from "./vault/transforms";

type VaultIO = BatchIO & HideIO;

/** Body class that hides the workspace while a mobile app is in the background. */
const PRIVACY_COVER = "strongbox-privacy-cover";

/** The file a workspace leaf shows, if it shows one. */
function fileOfLeaf(leaf: WorkspaceLeaf): TFile | null {
  const file = (leaf.view as unknown as { file?: unknown }).file;
  return file instanceof TFile ? file : null;
}

export default class StrongboxPlugin extends Plugin {
  settings: StrongboxSettings = { ...DEFAULT_SETTINGS };
  policy: ProtectionPolicy;
  codec: FileCodec;
  hook: AdapterHook;
  io: VaultIO;
  batch: BatchEngine;
  hider: NameHider;
  attachments: AttachmentRenderer;
  badges: ExplorerBadges;

  keyring: KeyringFile | null = null;
  private keys: MasterKeys | null = null;
  /** A batch or a lock/unlock transition is running. */
  private busy = false;
  private lastActivity = Date.now();
  private hiddenAt: number | null = null;
  private unlockPrompt: UnlockModal | null = null;
  private setupWizard: SetupWizard | null = null;
  private statusEl: HTMLElement | null = null;
  private ribbonEl: HTMLElement | null = null;
  private lastBlockedNotice = 0;
  /** Plaintext files that turned up inside protected areas (copied or moved in). */
  private toEnforce = new Set<string>();
  private settingTab: StrongboxSettingTab | null = null;

  // ------------------------------------------------------------ paths

  /** `<configDir>/plugins/strongbox`: keyring, journals and temporary files live here. */
  get pluginDir(): string {
    return `${this.app.vault.configDir}/plugins/${this.manifest.id}`;
  }
  get keyringPath(): string {
    return `${this.pluginDir}/keyring.json`;
  }
  private get journalPath(): string {
    return `${this.pluginDir}/batch-journal.log`;
  }
  private get tmpDir(): string {
    return `${this.pluginDir}/tmp`;
  }

  // ------------------------------------------------------------ lifecycle

  async onload(): Promise<void> {
    this.settings = mergeSettings(await this.loadData());
    this.policy = new ProtectionPolicy({
      configDir: this.app.vault.configDir,
      rules: this.settings.rules,
      excludes: this.settings.excludes,
      textExtensions: this.settings.textExtensions,
      // Inside the config folder anyway; listed so they stay excluded even if that changes.
      extraExcludes: [this.keyringPath, this.journalPath, this.tmpDir, `${this.pluginDir}/names.sbx`, `${this.pluginDir}/names-journal.log`],
    });
    this.codec = new FileCodec(() => this.keys, (p) => this.policy.isTextPath(p));
    this.hook = new AdapterHook(this.app.vault.adapter, {
      policy: this.policy,
      codec: this.codec,
      isUnlocked: () => this.keys !== null,
      onBlockedWrite: (p) => this.onBlockedWrite(p),
      onDecryptError: (p, e) => console.error("Strongbox: cannot decrypt", p, e),
      // Placeholder names only ever come from name hiding; never let plaintext land under them.
      isGuardedWhileLocked: (p) => pathHasHiddenSegment(p),
    });
    this.hook.install();

    const adapter = this.app.vault.adapter;
    const raw = this.hook.raw;
    this.io = {
      read: (p) => raw.read(p),
      readBinary: (p) => raw.readBinary(p),
      write: (p, d) => raw.write(p, d),
      writeBinary: (p, d) => raw.writeBinary(p, d),
      append: (p, d) => raw.append(p, d),
      exists: (p) => raw.exists(p),
      remove: (p) => adapter.remove(p),
      mkdir: (p) => adapter.mkdir(p),
      // Obsidian lists the vault root as "/".
      list: (p) => adapter.list(p === "" ? "/" : p),
      rename: (f, to) => adapter.rename(f, to),
    };
    this.batch = new BatchEngine(this.io, this.journalPath, this.tmpDir);
    this.hider = new NameHider(this.io, this.policy, {
      manifest: `${this.pluginDir}/names.sbx`,
      journal: `${this.pluginDir}/names-journal.log`,
    });
    this.keyring = await this.loadKeyring();

    this.attachments = new AttachmentRenderer(this.app, {
      isUnlocked: () => this.keys !== null,
      isEncryptedPath: (p) => this.isEncryptedPath(p),
    });
    this.badges = new ExplorerBadges(this.app, {
      isProtectedFile: (p) => this.isEncryptedPath(p),
      isProtectedFolder: (p) => this.policy.isFolderProtected(p),
    });

    this.registerUi();
    this.registerEvents();

    this.settingTab = new StrongboxSettingTab(this.app, this);
    this.addSettingTab(this.settingTab);

    this.app.workspace.onLayoutReady(() => void this.afterLayoutReady());
  }

  /** How long the hook outlives the plugin so closing editors can save encrypted. */
  unloadGraceMs = 3000;

  onunload(): void {
    // Obsidian does not await onunload. Editors showing protected files still
    // hold plaintext and save asynchronously when closed; if the hook were
    // removed first, that save would write plaintext to disk. So: save and
    // close those tabs now, keep the hook (and keys) for a short grace
    // period so the saves are encrypted, then drop the keys and unhook.
    activeDocument?.body?.removeClass?.(PRIVACY_COVER);
    InlineViewModal.closeAll();
    this.attachments?.stop();
    this.badges?.clear();
    const leaves: WorkspaceLeaf[] = [];
    try {
      this.app.workspace.iterateAllLeaves((leaf) => {
        const file = fileOfLeaf(leaf);
        if (file && this.isEncryptedPath(file.path)) leaves.push(leaf);
      });
    } catch {
      /* workspace already torn down */
    }
    const saves = leaves.map(async (leaf) => {
      try {
        if (leaf.view instanceof TextFileView) await leaf.view.save();
      } catch (e) {
        console.warn("Strongbox: could not save before unloading", e);
      }
      leaf.detach();
    });
    const keys = this.keys;
    const hook = this.hook;
    const finish = () => {
      keys?.clear();
      if (this.keys === keys) this.keys = null;
      hook?.uninstall();
    };
    void Promise.all(saves).then(() => window.setTimeout(finish, this.unloadGraceMs));
  }

  private async afterLayoutReady(): Promise<void> {
    this.attachments.start();
    this.badges.refresh();
    // Only now: 'create' fires for every file while the vault loads.
    this.registerEvent(this.app.vault.on("create", (f) => this.onCreate(f)));
    if (!this.keyring) {
      new Notice(t("notice.notSetUp"), 8000);
    }
    const pending = await this.batch.pending();
    if (pending) new Notice(t("notice.pendingBatch", { op: this.opLabel(pending.op), n: pending.remaining }), 10000);
    if (await this.hider.isHidden()) new Notice(t("notice.namesHidden"), 6000);
  }

  // ------------------------------------------------------------ state

  isUnlocked(): boolean {
    return this.keys !== null;
  }

  isInitialized(): boolean {
    return this.keyring !== null;
  }

  isBusy(): boolean {
    return this.busy;
  }

  /** Protected by a rule, or encrypted on disk as far as we have seen. */
  isEncryptedPath(path: string): boolean {
    return this.policy.isProtected(path) || this.hook.knownEncrypted(path) === true;
  }

  kdfForNewPassword(): KdfParams {
    const s = this.settings;
    return s.kdfAlgorithm === "argon2id"
      ? newKdfParams("argon2id", { memKiB: s.argon2MemoryMiB * 1024, iterations: s.argon2Iterations, parallelism: s.argon2Parallelism })
      : newKdfParams("pbkdf2-sha256", { iterations: s.pbkdf2Iterations });
  }

  kdfLabel(): string {
    return this.describeKdf(this.kdfForNewPassword());
  }

  currentKdfLabel(): string | null {
    return this.keyring ? this.describeKdf(this.keyring.kdf) : null;
  }

  /** KDF parameters in the UI language. */
  describeKdf(params: KdfParams): string {
    if (params.alg === "argon2id") {
      return t("kdf.argon2id", { mem: Math.round(params.memKiB / 1024), passes: params.iterations, par: params.parallelism });
    }
    return t("kdf.pbkdf2", { n: params.iterations.toLocaleString("en-US") });
  }

  async saveSettings(): Promise<void> {
    this.policy.update({ rules: this.settings.rules, excludes: this.settings.excludes, textExtensions: this.settings.textExtensions });
    await this.saveData(this.settings);
    this.attachments.invalidate();
    this.badges.refreshSoon();
  }

  private opLabel(op: BatchOp): string {
    return op === "encrypt" ? t("op.encrypt") : op === "decrypt" ? t("op.decrypt") : t("op.rekey");
  }

  // ------------------------------------------------------------ keyring storage

  private async loadKeyring(): Promise<KeyringFile | null> {
    for (const p of [this.keyringPath, this.keyringPath + ".new"]) {
      try {
        if (await this.io.exists(p)) return parseKeyring(await this.io.read(p));
      } catch (e) {
        console.error("Strongbox: unreadable keyring at", p, e);
      }
    }
    return null;
  }

  /** Writes the keyring so that a crash leaves either the old or the new one readable. */
  async saveKeyring(file: KeyringFile): Promise<void> {
    const json = serializeKeyring(file);
    const tmp = this.keyringPath + ".new";
    if (!(await this.io.exists(this.pluginDir))) await this.io.mkdir(this.pluginDir);
    await this.io.write(tmp, json);
    parseKeyring(await this.io.read(tmp));
    await this.io.write(this.keyringPath, json);
    if ((await this.io.read(this.keyringPath)) !== json) throw new Error("Keyring did not read back correctly");
    await this.io.remove(tmp);
    this.keyring = file;
  }

  keyringJson(): string | null {
    return this.keyring ? serializeKeyring(this.keyring) : null;
  }

  /** Replaces the keyring with a backup. Locks first. */
  async importKeyringJson(json: string): Promise<boolean> {
    let parsed: KeyringFile;
    try {
      parsed = parseKeyring(json);
    } catch (e) {
      new Notice(t("keyring.importInvalid", { error: String((e as Error).message) }));
      return false;
    }
    if (this.keyring) {
      const ok = await confirmDialog(this.app, {
        title: t("keyring.importTitle"),
        body: [t("keyring.importReplace"), t("keyring.importReplace2")],
        confirm: t("keyring.importConfirm"),
        danger: true,
      });
      if (!ok) return false;
      await this.lock("manual");
      if (this.isUnlocked()) return false;
    }
    await this.saveKeyring(parsed);
    new Notice(t("keyring.imported"));
    this.refreshStatus();
    return true;
  }

  // ------------------------------------------------------------ unlock / lock

  /** Makes sure Strongbox is set up and unlocked, asking the user if needed. */
  async ensureUnlocked(reason?: string): Promise<boolean> {
    if (this.keys) return true;
    if (!this.keyring) {
      const created = await this.openSetup();
      if (!created) return false;
      // Importing a backup in the wizard leaves Strongbox locked.
      return this.keys !== null || this.promptUnlock(reason);
    }
    return this.promptUnlock(reason);
  }

  async promptUnlock(reason?: string): Promise<boolean> {
    if (this.keys) return true;
    if (!this.keyring) return this.ensureUnlocked(reason);
    if (this.unlockPrompt) return this.unlockPrompt.result;
    const modal = new UnlockModal(this.app, (pw) => this.tryUnlock(pw), reason);
    this.unlockPrompt = modal;
    modal.open();
    try {
      return await modal.result;
    } finally {
      this.unlockPrompt = null;
    }
  }

  async openSetup(): Promise<boolean> {
    // Opening a protected file and running "Unlock" can both ask for setup; show one wizard.
    if (this.setupWizard) return this.setupWizard.result;
    const wizard = new SetupWizard(this.app, {
      kdfLabel: () => this.kdfLabel(),
      create: (pw) => this.createKeyringWith(pw),
      renderBackup: (el) => this.settingTab?.renderBackupButtons(el),
      importKeyring: () => this.pickAndImportKeyring(),
      fileRecoveryEnabled: () => this.fileRecoveryEnabled(),
    });
    this.setupWizard = wizard;
    wizard.open();
    try {
      return await wizard.result;
    } finally {
      this.setupWizard = null;
    }
  }

  private async createKeyringWith(password: string): Promise<void> {
    if (this.keyring) throw new Error(t("setup.alreadySetUp"));
    const { file, keys } = await createKeyring(password, this.kdfForNewPassword());
    await this.saveKeyring(file);
    await this.becomeUnlocked(keys);
  }

  /** Used by the unlock dialog. */
  private async tryUnlock(password: string): Promise<UnlockOutcome> {
    const keyring = (await this.loadKeyring()) ?? this.keyring;
    if (!keyring) return { error: t("unlock.noKeyring") };
    try {
      const keys = await unlockKeyring(keyring, password);
      this.keyring = keyring;
      await this.becomeUnlocked(keys);
      return "ok";
    } catch (e) {
      if (e instanceof WrongPasswordError) return "wrong";
      console.error("Strongbox: unlock failed", e);
      return { error: String((e as Error)?.message ?? e) };
    }
  }

  private async becomeUnlocked(keys: MasterKeys): Promise<void> {
    this.keys = keys;
    this.lastActivity = Date.now();
    this.busy = true;
    try {
      if (await this.hider.isHidden()) {
        const res = await this.hider.reveal(keys);
        if (res.problems.length) {
          new Notice(t("names.problems", { n: res.problems.length }), 15000);
          console.warn("Strongbox: name restore problems", res.problems);
        }
      }
    } catch (e) {
      console.error("Strongbox: restoring names failed", e);
      new Notice(t("names.revealFailed", { error: String((e as Error)?.message ?? e) }), 15000);
    } finally {
      this.busy = false;
    }
    // A dialog opened earlier (e.g. by a blocked save) would otherwise stay open with a stale reason.
    this.unlockPrompt?.unlockedElsewhere();
    // Reads made while locked cached the ciphertext shells.
    this.purgeContentCache();
    this.rerunSearches();
    this.refreshStatus();
    this.attachments.invalidate();
    this.attachments.rescan();
    await this.reloadProtectedLeaves();
    void this.flushEnforce();
    const pending = await this.batch.pending();
    if (pending) {
      const go = await confirmDialog(this.app, {
        title: t("batch.resumeTitle"),
        body: t("batch.resumeBody", { op: this.opLabel(pending.op), n: pending.remaining, total: pending.total }),
        confirm: t("batch.resume"),
      });
      if (go) await this.resumeBatch();
    }
  }

  /**
   * Locks: closes protected tabs and inline viewers, hides names when that
   * is on, revokes Blob URLs and drops the keys.
   */
  async lock(reason: "manual" | "idle" | "background"): Promise<void> {
    if (!this.keys) return;
    if (this.busy) {
      if (reason === "manual") new Notice(t("notice.busyNoLock"));
      return;
    }
    this.busy = true;
    try {
      InlineViewModal.closeAll();
      // Saves pending edits (still encrypted, we are unlocked) before closing.
      await this.closeProtectedLeaves();
      this.attachments.revokeAll();
      // Obsidian keeps file contents in memory for cachedRead() (search reads
      // it too); without this, plaintext stays searchable after locking.
      this.purgeContentCache();
      if (this.settings.hideNames) {
        try {
          await this.hider.hide(this.keys);
        } catch (e) {
          console.error("Strongbox: hiding names failed", e);
          new Notice(t("names.hideFailed", { error: String((e as Error)?.message ?? e) }), 15000);
        }
      }
    } finally {
      this.keys?.clear();
      this.keys = null;
      this.busy = false;
    }
    this.purgeContentCache();
    this.rerunSearches();
    this.refreshStatus();
    new Notice(reason === "manual" ? t("notice.locked") : t("notice.autoLocked"));
  }

  async toggleLock(): Promise<void> {
    if (this.keys) await this.lock("manual");
    else await this.ensureUnlocked();
  }

  /**
   * Drops Obsidian's in-memory copy of protected files' contents (the cache
   * behind vault.cachedRead, filled by every vault.read). TFile.cache(null)
   * is not public API; if it is missing nothing happens.
   */
  private purgeContentCache(): void {
    for (const file of this.app.vault.getFiles()) {
      if (!this.isEncryptedPath(file.path)) continue;
      try {
        (file as unknown as { cache?: (value: null) => void }).cache?.(null);
      } catch {
        /* not available in this Obsidian version */
      }
    }
  }

  /** Re-runs open searches so results built from plaintext disappear. */
  private rerunSearches(): void {
    for (const leaf of this.app.workspace.getLeavesOfType("search")) {
      try {
        const view = leaf.view as unknown as { searchQuery?: unknown; startSearch?: () => void };
        // With an unchanged query Obsidian only re-checks the previous
        // matches ("narrowing"); forget the old query so every file is searched.
        if ("searchQuery" in view) view.searchQuery = null;
        view.startSearch?.();
      } catch {
        /* private API */
      }
    }
  }

  private async closeProtectedLeaves(): Promise<void> {
    const leaves: WorkspaceLeaf[] = [];
    this.app.workspace.iterateAllLeaves((leaf) => {
      const file = fileOfLeaf(leaf);
      if (file && this.isEncryptedPath(file.path)) leaves.push(leaf);
    });
    for (const leaf of leaves) {
      if (leaf.view instanceof TextFileView) {
        try {
          await leaf.view.save();
        } catch (e) {
          console.warn("Strongbox: could not save before locking", e);
        }
      }
      leaf.detach();
    }
  }

  /** Re-opens tabs that showed ciphertext while locked, so they read plaintext now. */
  private async reloadProtectedLeaves(): Promise<void> {
    const leaves: WorkspaceLeaf[] = [];
    this.app.workspace.iterateAllLeaves((leaf) => {
      const file = fileOfLeaf(leaf);
      if (file && this.isEncryptedPath(file.path)) leaves.push(leaf);
    });
    for (const leaf of leaves) {
      try {
        const state = leaf.getViewState();
        await leaf.setViewState({ type: "empty" });
        await leaf.setViewState(state);
      } catch (e) {
        console.warn("Strongbox: could not reload tab", e);
      }
    }
  }

  private onBlockedWrite(path: string): void {
    const now = Date.now();
    if (now - this.lastBlockedNotice > 3000) {
      this.lastBlockedNotice = now;
      new Notice(t("notice.blockedWrite", { path }), 8000);
      void this.promptUnlock(t("unlock.reasonWrite", { path }));
    }
  }

  // ------------------------------------------------------------ UI registration

  private registerUi(): void {
    this.ribbonEl = this.addRibbonIcon("lock", t("ribbon.toggle"), () => void this.toggleLock());
    this.statusEl = this.addStatusBarItem();
    this.statusEl.addClass("strongbox-status", "mod-clickable");
    this.registerDomEvent(this.statusEl, "click", () => void this.toggleLock());
    this.refreshStatus();

    this.addCommand({ id: "lock", name: t("cmd.lock"), callback: () => void this.lock("manual") });
    this.addCommand({ id: "unlock", name: t("cmd.unlock"), callback: () => void this.ensureUnlocked() });
    this.addCommand({
      id: "encrypt-selection",
      name: t("cmd.encryptSelection"),
      editorCallback: (editor) => void this.encryptSelection(editor),
    });
    this.addCommand({
      id: "decrypt-at-cursor",
      name: t("cmd.decryptAtCursor"),
      editorCallback: (editor, ctx) => void this.decryptAtCursor(editor, ctx.file?.path ?? ""),
    });
    this.addCommand({
      id: "protect-current-file",
      name: t("cmd.protectFile"),
      checkCallback: (checking) => {
        const file = this.app.workspace.getActiveFile();
        if (!file || this.policy.isExcluded(file.path)) return false;
        if (!checking) void this.protectFile(file);
        return true;
      },
    });
    this.addCommand({
      id: "unprotect-current-file",
      name: t("cmd.unprotectFile"),
      checkCallback: (checking) => {
        const file = this.app.workspace.getActiveFile();
        if (!file || !this.isEncryptedPath(file.path)) return false;
        if (!checking) void this.unprotectFile(file);
        return true;
      },
    });
    this.addCommand({ id: "protect-vault", name: t("cmd.protectVault"), callback: () => void this.protectVault() });
    this.addCommand({ id: "unprotect-vault", name: t("cmd.unprotectVault"), callback: () => void this.unprotectVault() });
    this.addCommand({ id: "change-password", name: t("cmd.changePassword"), callback: () => void this.changePassword() });
    this.addCommand({ id: "rekey", name: t("cmd.rekey"), callback: () => void this.rekey() });
    this.addCommand({ id: "resume-batch", name: t("cmd.resumeBatch"), callback: () => void this.resumeBatch() });

    this.registerEvent(this.app.workspace.on("file-menu", (menu, file) => this.fileMenu(menu, file)));
    this.registerEvent(this.app.workspace.on("editor-menu", (menu, editor, info) => this.editorMenu(menu, editor, info.file?.path ?? "")));

    const host = {
      openInline: (token: string, restore: (plain: string) => Promise<void>) => this.openInline(token, restore),
      replaceInFile: (path: string, token: string, plain: string) => this.replaceInFile(path, token, plain),
    };
    this.registerMarkdownPostProcessor(inlinePostProcessor(host));
    this.registerEditorExtension(inlineEditorExtension(host));
  }

  refreshStatus(): void {
    const unlocked = this.isUnlocked();
    if (this.ribbonEl) {
      setIcon(this.ribbonEl, unlocked ? "unlock" : "lock");
      this.ribbonEl.setAttribute("aria-label", unlocked ? t("ribbon.lock") : t("ribbon.unlock"));
    }
    if (this.statusEl) {
      this.statusEl.toggleClass("strongbox-hidden", !this.settings.showStatusBar || Platform.isMobile);
      this.statusEl.empty();
      const icon = this.statusEl.createSpan({ cls: "strongbox-status-icon" });
      setIcon(icon, unlocked ? "unlock" : "lock");
      this.statusEl.createSpan({ text: unlocked ? t("status.unlocked") : this.keyring ? t("status.locked") : t("status.notSetUp") });
      this.statusEl.setAttribute("aria-label", unlocked ? t("ribbon.lock") : t("ribbon.unlock"));
    }
    this.badges?.refreshSoon();
    this.settingTab?.refreshIfOpen();
  }

  private registerEvents(): void {
    const activity = () => (this.lastActivity = Date.now());
    const watchActivity = (doc: Document) => {
      for (const type of ["keydown", "mousedown", "touchstart", "wheel"] as const) {
        this.registerDomEvent(doc, type, activity, { passive: true, capture: true });
      }
    };
    watchActivity(activeDocument);
    // Popout windows: count activity there too, and show encrypted media in them.
    this.registerEvent(
      this.app.workspace.on("window-open", (_win, win) => {
        watchActivity(win.document);
        this.attachments.watch(win.document);
      }),
    );
    this.registerEvent(this.app.workspace.on("window-close", (_win, win) => this.attachments.unwatch(win.document)));
    this.registerInterval(
      window.setInterval(() => {
        const minutes = this.settings.idleMinutes;
        if (this.keys && minutes > 0 && Date.now() - this.lastActivity > minutes * 60_000) void this.lock("idle");
      }, 15_000),
    );
    this.registerDomEvent(activeDocument, "visibilitychange", () => {
      if (!Platform.isMobile) return;
      // Best effort against the app-switcher snapshot: hide the workspace
      // synchronously while in the background (locking itself is async).
      activeDocument.body.toggleClass(PRIVACY_COVER, activeDocument.visibilityState === "hidden" && !!this.keys);
      if (!this.keys) return;
      const limit = this.settings.backgroundLockSeconds;
      if (limit < 0) return;
      if (activeDocument.visibilityState === "hidden") {
        this.hiddenAt = Date.now();
        if (limit === 0) void this.lock("background");
      } else if (this.hiddenAt !== null) {
        const away = Date.now() - this.hiddenAt;
        this.hiddenAt = null;
        if (away >= limit * 1000) void this.lock("background");
      }
    });

    this.registerEvent(
      this.app.workspace.on("file-open", (file) => {
        if (file && !this.keys && this.isEncryptedPath(file.path)) {
          void this.promptUnlock(t("unlock.reasonOpen", { name: file.name }));
        }
      }),
    );
    this.registerEvent(this.app.vault.on("rename", (file, oldPath) => void this.onRename(file, oldPath)));
    this.registerEvent(
      this.app.vault.on("delete", (file) => {
        this.hook.forget(file.path);
        this.attachments.invalidate(file.path);
      }),
    );
    this.registerEvent(this.app.vault.on("modify", (file) => this.attachments.invalidate(file.path)));
    this.registerEvent(this.app.workspace.on("layout-change", () => this.badges.refreshSoon()));
  }

  private async onRename(file: TAbstractFile, oldPath: string): Promise<void> {
    const wasEncrypted = this.hook.knownEncrypted(oldPath);
    this.hook.forget(oldPath);
    if (wasEncrypted !== undefined && file instanceof TFile) this.hook.noteState(file.path, wasEncrypted);
    this.attachments.invalidate(oldPath);
    // Our own placeholder renames (hiding names): rules must keep the real
    // paths. Checked by name, not by timing, because the vault may report
    // these renames after hide()/reveal() has returned.
    if (pathHasHiddenSegment(oldPath) || pathHasHiddenSegment(file.path)) return;
    const rules = renameInRules(this.settings.rules, oldPath, file.path);
    if (rules !== this.settings.rules) {
      this.settings.rules = rules;
      await this.saveSettings();
    }
    this.queueEnforce(file);
  }

  private onCreate(file: TAbstractFile): void {
    this.badges.refreshSoon();
    this.attachments.invalidate();
    if (!pathHasHiddenSegment(file.path)) this.queueEnforce(file);
  }

  /** Plaintext that arrived in a protected place by copy, move or sync gets encrypted. */
  private queueEnforce(file: TAbstractFile): void {
    const paths: string[] = [];
    if (file instanceof TFile) paths.push(file.path);
    else if (file instanceof TFolder) {
      const walk = (f: TAbstractFile) => {
        if (f instanceof TFile) paths.push(f.path);
        else if (f instanceof TFolder) f.children.forEach(walk);
      };
      walk(file);
    }
    for (const p of paths) if (this.policy.isProtected(p)) this.toEnforce.add(p);
    if (this.toEnforce.size) window.setTimeout(() => void this.flushEnforce(), 1000);
  }

  private async flushEnforce(): Promise<void> {
    if (!this.keys || this.busy || this.toEnforce.size === 0) return;
    const paths = [...this.toEnforce];
    this.toEnforce.clear();
    let count = 0;
    for (const path of paths) {
      try {
        if (!this.policy.isProtected(path) || !(await this.io.exists(path))) continue;
        const data = new Uint8Array(await this.io.readBinary(path));
        if (detectForm(data) !== null) {
          this.hook.noteState(path, true);
          continue;
        }
        if (!this.keys) {
          this.toEnforce.add(path);
          continue;
        }
        const payload = await this.codec.encode(path, data);
        const check = await this.codec.decode(payload.bytes);
        if (check.length !== data.length) throw new Error("verification failed");
        if (payload.form === "text") await this.io.write(path, payload.text as string);
        else await this.io.writeBinary(path, payload.binary as ArrayBuffer);
        this.hook.noteState(path, true);
        count++;
      } catch (e) {
        console.error("Strongbox: could not encrypt", path, e);
      }
    }
    if (count) new Notice(t("notice.enforced", { n: count }));
  }

  // ------------------------------------------------------------ menus

  private fileMenu(menu: Menu, file: TAbstractFile): void {
    if (this.policy.isExcluded(file.path)) return;
    if (file instanceof TFile) {
      if (this.isEncryptedPath(file.path)) {
        menu.addItem((i) => i.setTitle(t("menu.unprotectFile")).setIcon("unlock").onClick(() => void this.unprotectFile(file)));
      } else {
        menu.addItem((i) => i.setTitle(t("menu.protectFile")).setIcon("lock").onClick(() => void this.protectFile(file)));
      }
    } else if (file instanceof TFolder && !file.isRoot()) {
      if (this.policy.hasRule("folder", file.path)) {
        menu.addItem((i) => i.setTitle(t("menu.unprotectFolder")).setIcon("unlock").onClick(() => void this.unprotectFolder(file.path)));
      } else if (this.policy.isFolderProtected(file.path)) {
        menu.addItem((i) => i.setTitle(t("menu.folderCovered")).setIcon("lock").setDisabled(true));
      } else {
        menu.addItem((i) => i.setTitle(t("menu.protectFolder")).setIcon("lock").onClick(() => void this.protectFolder(file.path)));
      }
    }
  }

  private editorMenu(menu: Menu, editor: Editor, path: string): void {
    if (editor.getSelection()) {
      menu.addItem((i) => i.setTitle(t("cmd.encryptSelection")).setIcon("lock").onClick(() => void this.encryptSelection(editor)));
    }
    if (this.blockAtCursor(editor)) {
      menu.addItem((i) => i.setTitle(t("menu.viewBlock")).setIcon("eye").onClick(() => void this.viewBlockAtCursor(editor)));
      menu.addItem((i) => i.setTitle(t("cmd.decryptAtCursor")).setIcon("unlock").onClick(() => void this.decryptAtCursor(editor, path)));
    }
  }

  // ------------------------------------------------------------ selected text

  private async encryptSelection(editor: Editor): Promise<void> {
    const text = editor.getSelection();
    if (!text) {
      new Notice(t("inline.nothingSelected"));
      return;
    }
    if (findInlineBlocks(text).length) {
      new Notice(t("inline.alreadyEncrypted"));
      return;
    }
    const from = editor.getCursor("from");
    const to = editor.getCursor("to");
    const choice = await chooseInlineMode(this.app);
    if (!choice) return;
    let token: string;
    try {
      if (choice.mode === "master") {
        if (!(await this.ensureUnlocked())) return;
        token = await encryptInlineWithMaster(text, this.keys as MasterKeys);
      } else {
        token = await encryptInlineWithPassword(text, choice.password, this.kdfForNewPassword());
      }
    } catch (e) {
      new Notice(t("inline.encryptFailed", { error: String((e as Error)?.message ?? e) }));
      return;
    }
    if (editor.getRange(from, to) !== text) {
      new Notice(t("inline.selectionChanged"));
      return;
    }
    editor.replaceRange(token, from, to);
  }

  private blockAtCursor(editor: Editor): { token: string; line: number; start: number; end: number } | null {
    const cur = editor.getCursor();
    const line = editor.getLine(cur.line);
    for (const b of findInlineBlocks(line)) {
      if (cur.ch >= b.start && cur.ch <= b.end) return { token: b.token, line: cur.line, start: b.start, end: b.end };
    }
    return null;
  }

  private async decryptBlock(token: string, password?: string): Promise<string> {
    if (inlineBlockMode(token) === "master") {
      if (!(await this.ensureUnlocked())) throw new Error(t("notice.stillLocked"));
      return decryptInline(token, { keys: this.keys });
    }
    return decryptInline(token, { password });
  }

  private async decryptAtCursor(editor: Editor, _path: string): Promise<void> {
    const block = this.blockAtCursor(editor);
    if (!block) {
      new Notice(t("inline.noBlock"));
      return;
    }
    let password: string | undefined;
    if (inlineBlockMode(block.token) === "password") {
      const pw = await promptPassword(this.app, { title: t("inline.blockPassword") });
      if (pw === null) return;
      password = pw;
    }
    try {
      const plain = await this.decryptBlock(block.token, password);
      const current = editor.getRange({ line: block.line, ch: block.start }, { line: block.line, ch: block.end });
      if (current !== block.token) throw new Error(t("inline.blockGone"));
      editor.replaceRange(plain, { line: block.line, ch: block.start }, { line: block.line, ch: block.end });
    } catch (e) {
      new Notice(t("inline.decryptFailed") + " " + String((e as Error)?.message ?? ""));
    }
  }

  private async viewBlockAtCursor(editor: Editor): Promise<void> {
    const block = this.blockAtCursor(editor);
    if (!block) return;
    this.openInline(block.token, async (plain) => {
      const current = editor.getRange({ line: block.line, ch: block.start }, { line: block.line, ch: block.end });
      if (current !== block.token) throw new Error(t("inline.blockGone"));
      editor.replaceRange(plain, { line: block.line, ch: block.start }, { line: block.line, ch: block.end });
    });
  }

  openInline(token: string, restore: (plain: string) => Promise<void>): void {
    const needsPassword = inlineBlockMode(token) === "password";
    new InlineViewModal(this.app, {
      needsPassword,
      decrypt: (pw) => this.decryptBlock(token, pw),
      restore: async (plain) => {
        try {
          await restore(plain);
        } catch (e) {
          new Notice(String((e as Error)?.message ?? e));
        }
      },
    }).open();
  }

  private async replaceInFile(path: string, token: string, plain: string): Promise<void> {
    const file = this.app.vault.getAbstractFileByPath(path);
    if (!(file instanceof TFile)) throw new Error(t("inline.blockGone"));
    // Prefer the open editor so unsaved edits are kept.
    let done = false;
    this.app.workspace.iterateAllLeaves((leaf) => {
      if (done) return;
      const view = leaf.view;
      if (view instanceof MarkdownView && view.file?.path === path) {
        const text = view.editor.getValue();
        const at = text.indexOf(token);
        if (at >= 0) {
          const from = view.editor.offsetToPos(at);
          const to = view.editor.offsetToPos(at + token.length);
          view.editor.replaceRange(plain, from, to);
          done = true;
        }
      }
    });
    if (done) return;
    let found = false;
    await this.app.vault.process(file, (data) => {
      const at = data.indexOf(token);
      if (at < 0) return data;
      found = true;
      return data.slice(0, at) + plain + data.slice(at + token.length);
    });
    if (!found) throw new Error(t("inline.blockGone"));
  }

  // ------------------------------------------------------------ files, folders, vault

  /**
   * All files below a folder ("" = vault), read from disk, minus excluded
   * ones. `everything` (used by re-key) also walks user-excluded paths and
   * the trash, which may hold encrypted files or inline blocks too.
   */
  async listFiles(folder: string, opts: { everything?: boolean } = {}): Promise<string[]> {
    const out: string[] = [];
    const skip = (p: string) => {
      if (!opts.everything) return this.policy.isExcluded(p);
      if (isWithin(p, ".trash")) return p.split("/").slice(1).some((seg) => seg.startsWith("."));
      return this.policy.isSystemExcluded(p);
    };
    const walk = async (dir: string) => {
      const { files, folders } = await this.io.list(dir);
      for (const f of files.map(normPath)) if (!skip(f)) out.push(f);
      for (const d of folders.map(normPath)) if (!skip(d)) await walk(d);
    };
    await walk(normPath(folder));
    return out;
  }

  /** Non-note files a note embeds or links to. */
  attachmentsOf(file: TFile): TFile[] {
    const cache = this.app.metadataCache.getFileCache(file);
    const refs = [...(cache?.embeds ?? []), ...(cache?.links ?? [])];
    const found = new Map<string, TFile>();
    for (const r of refs) {
      const target = this.app.metadataCache.getFirstLinkpathDest(r.link.split("#")[0].split("|")[0], file.path);
      if (target && target.path !== file.path && !this.policy.isTextPath(target.path) && !this.policy.isExcluded(target.path)) {
        found.set(target.path, target);
      }
    }
    return [...found.values()];
  }

  async protectFile(file: TFile): Promise<void> {
    if (this.policy.isExcluded(file.path)) {
      new Notice(t("notice.excluded", { path: file.path }));
      return;
    }
    const attachments = this.attachmentsOf(file);
    if (!(await this.readyForBatch())) return;
    const answer = await askProtectFile(this.app, file.name, attachments.length, this.settings.includeAttachmentsByDefault);
    if (!answer) return;
    if (!(await this.ensureUnlocked())) return;
    const paths = [file.path, ...(answer.withAttachments ? attachments.map((a) => a.path) : [])];
    let rules = this.settings.rules;
    for (const p of paths) if (!this.policy.isProtected(p)) rules = addRule(rules, { type: "file", path: p });
    this.settings.rules = rules;
    await this.saveSettings();
    await this.runBatch("encrypt", paths, encryptTransform(this.codec));
  }

  async unprotectFile(file: TFile): Promise<void> {
    const rule = this.policy.ruleFor(file.path);
    if (rule && rule.type !== "file") {
      new Notice(t("notice.coveredByRule", { rule: this.describeRule(rule) }), 8000);
      return;
    }
    if (!(await this.readyForBatch())) return;
    const ok = await confirmDialog(this.app, {
      title: t("file.unprotectTitle"),
      body: t("file.unprotectBody", { name: file.name }),
      confirm: t("file.unprotect"),
    });
    if (!ok || !(await this.ensureUnlocked())) return;
    if (rule) {
      this.settings.rules = removeRule(this.settings.rules, rule);
      await this.saveSettings();
    }
    await this.runBatch("decrypt", [file.path], decryptTransform(this.codec));
  }

  async protectFolder(path: string): Promise<void> {
    if (!(await this.readyForBatch())) return;
    const ok = await confirmDialog(this.app, {
      title: t("folder.protectTitle"),
      body: [t("folder.protectBody", { path }), t("folder.protectBody2")],
      confirm: t("folder.protect"),
    });
    if (!ok || !(await this.ensureUnlocked())) return;
    this.settings.rules = addRule(this.settings.rules, { type: "folder", path });
    await this.saveSettings();
    await this.runBatch("encrypt", await this.listFiles(path), encryptTransform(this.codec));
  }

  async unprotectFolder(path: string): Promise<void> {
    if (!(await this.readyForBatch())) return;
    const ok = await confirmDialog(this.app, {
      title: t("folder.unprotectTitle"),
      body: t("folder.unprotectBody", { path }),
      confirm: t("folder.unprotect"),
    });
    if (!ok || !(await this.ensureUnlocked())) return;
    // Drop the folder rule and every file rule inside it.
    this.settings.rules = this.settings.rules.filter((r) => !(r.type !== "vault" && isWithin(normPath(r.path), normPath(path))));
    await this.saveSettings();
    const files = (await this.listFiles(path)).filter((p) => !this.policy.isProtected(p));
    await this.runBatch("decrypt", files, decryptTransform(this.codec));
  }

  async protectVault(): Promise<void> {
    if (this.policy.hasRule("vault", "")) {
      new Notice(t("vault.alreadyProtected"));
      return;
    }
    if (!(await this.readyForBatch())) return;
    const ok = await confirmDialog(this.app, {
      title: t("vault.protectTitle"),
      body: [t("vault.protectBody"), t("vault.protectBody2", { config: this.app.vault.configDir }), t("vault.protectBody3")],
      confirm: t("vault.protect"),
      checkbox: t("vault.protectCheckbox"),
    });
    if (!ok || !(await this.ensureUnlocked())) return;
    this.settings.rules = addRule(this.settings.rules, { type: "vault", path: "" });
    await this.saveSettings();
    await this.runBatch("encrypt", await this.listFiles(""), encryptTransform(this.codec));
  }

  async unprotectVault(): Promise<void> {
    if (!(await this.readyForBatch())) return;
    const ok = await confirmDialog(this.app, {
      title: t("vault.unprotectTitle"),
      body: t("vault.unprotectBody"),
      confirm: t("vault.unprotect"),
      danger: true,
    });
    if (!ok || !(await this.ensureUnlocked())) return;
    this.settings.rules = [];
    await this.saveSettings();
    await this.runBatch("decrypt", await this.listFiles(""), decryptTransform(this.codec));
  }

  /** Removes one rule from the settings list (and decrypts what it covered). */
  async removeRuleAndDecrypt(rule: ProtectionRule): Promise<void> {
    if (rule.type === "vault") return this.unprotectVault();
    if (rule.type === "folder") return this.unprotectFolder(rule.path);
    const file = this.app.vault.getAbstractFileByPath(rule.path);
    if (file instanceof TFile) return this.unprotectFile(file);
    this.settings.rules = removeRule(this.settings.rules, rule);
    await this.saveSettings();
  }

  describeRule(rule: ProtectionRule): string {
    if (rule.type === "vault") return t("rule.vault");
    return rule.type === "folder" ? t("rule.folder", { path: rule.path }) : t("rule.file", { path: rule.path });
  }

  // ------------------------------------------------------------ batches

  private concurrency(): number {
    return Platform.isMobile ? 2 : 4;
  }

  private transformFor(op: BatchOp): FileTransform {
    if (op === "encrypt") return encryptTransform(this.codec);
    if (op === "decrypt") return decryptTransform(this.codec);
    return rekeyTransform(this.codec, () => this.keys, (p) => this.policy.isTextPath(p));
  }

  /** No other job running and no unfinished one waiting. Checked before rules change. */
  private async readyForBatch(): Promise<boolean> {
    if (this.busy) {
      new Notice(t("notice.busy"));
      return false;
    }
    if (await this.batch.pending()) {
      new Notice(t("notice.pendingFirst"), 8000);
      return false;
    }
    return true;
  }

  private async runBatch(
    op: BatchOp,
    paths: string[],
    transform: FileTransform,
    meta: Record<string, unknown> = {},
  ): Promise<BatchResult | null> {
    if (this.busy) {
      new Notice(t("notice.busy"));
      return null;
    }
    if (await this.batch.pending()) {
      new Notice(t("notice.pendingFirst"), 8000);
      return null;
    }
    return this.withProgress(op, (options) => this.batch.start(op, paths, transform, options, meta));
  }

  async resumeBatch(): Promise<void> {
    const pending = await this.batch.pending();
    if (!pending) {
      new Notice(t("batch.nothingPending"));
      return;
    }
    if (this.busy) {
      new Notice(t("notice.busy"));
      return;
    }
    if (!(await this.ensureUnlocked())) return;
    const res = await this.withProgress(pending.op, (options) => this.batch.resume((op) => this.transformFor(op), options));
    if (res && res.op === "rekey") await this.finishRekeyIfComplete(res);
  }

  async discardBatch(): Promise<void> {
    const pending = await this.batch.pending();
    if (!pending) return;
    const ok = await confirmDialog(this.app, {
      title: t("batch.discardTitle"),
      body: t("batch.discardBody", { op: this.opLabel(pending.op), n: pending.remaining }),
      confirm: t("batch.discard"),
      danger: true,
    });
    if (!ok) return;
    await this.batch.discard();
    new Notice(t("batch.discarded"));
    this.settingTab?.refreshIfOpen();
  }

  private async withProgress(
    op: BatchOp,
    run: (options: Parameters<BatchEngine["start"]>[3]) => Promise<BatchResult | null>,
  ): Promise<BatchResult | null> {
    const modal = new ProgressModal(this.app, t("progress.title", { op: this.opLabel(op) }));
    modal.open();
    this.busy = true;
    let result: BatchResult | null = null;
    try {
      result = await run({
        concurrency: this.concurrency(),
        signal: modal.controller.signal,
        onProgress: (p) => modal.update(p),
        onFileWritten: (path, kind) => {
          this.hook.noteState(path, kind !== "decrypt");
          this.attachments.invalidate(path);
        },
      });
    } catch (e) {
      new Notice(t("batch.error", { error: String((e as Error)?.message ?? e) }), 10000);
      console.error("Strongbox: batch failed", e);
    } finally {
      this.busy = false;
      modal.close();
      this.lastActivity = Date.now();
    }
    if (result) {
      if (result.cancelled) new Notice(t("batch.cancelled", { changed: result.changed }), 10000);
      else if (result.failed.length) {
        new Notice(t("batch.someFailed", { n: result.failed.length, first: result.failed[0].path, error: result.failed[0].error }), 15000);
        console.warn("Strongbox: failed files", result.failed);
      } else new Notice(t("batch.done", { op: this.opLabel(result.op), changed: result.changed, skipped: result.skipped }));
    }
    this.badges.refreshSoon();
    this.settingTab?.refreshIfOpen();
    return result;
  }

  // ------------------------------------------------------------ passwords and keys

  async changePassword(): Promise<void> {
    if (!this.keyring) {
      await this.openSetup();
      return;
    }
    const oldPw = await promptPassword(this.app, { title: t("password.changeTitle"), desc: t("password.changeOld") });
    if (oldPw === null) return;
    const newPw = await promptPassword(this.app, {
      title: t("password.changeTitle"),
      desc: t("password.changeNew", { kdf: this.kdfLabel() }),
      confirm: true,
      warning: t("setup.warnNoRecovery"),
      minLength: MIN_PASSWORD_LENGTH,
    });
    if (newPw === null) return;
    try {
      const updated = await changeKeyringPassword(this.keyring, oldPw, newPw, this.kdfForNewPassword());
      await this.saveKeyring(updated);
      new Notice(t("password.changed"), 8000);
    } catch (e) {
      new Notice(e instanceof WrongPasswordError ? t("unlock.wrong") : String((e as Error)?.message ?? e));
    }
    this.settingTab?.refreshIfOpen();
  }

  /** Full re-key: new master key, every encrypted file rewritten, old key removed. */
  async rekey(): Promise<void> {
    if (!this.keyring) return;
    if (!(await this.readyForBatch())) return;
    if (await this.hider.isHidden()) {
      new Notice(t("names.mustRevealFirst"), 8000);
      return;
    }
    const ok = await confirmDialog(this.app, {
      title: t("rekey.title"),
      body: [t("rekey.body"), t("rekey.body2")],
      confirm: t("rekey.start"),
    });
    if (!ok || !(await this.ensureUnlocked())) return;
    const pw = await promptPassword(this.app, { title: t("rekey.title"), desc: t("rekey.password") });
    if (pw === null) return;
    let added;
    try {
      added = await addMasterKey(this.keyring, pw);
    } catch (e) {
      new Notice(e instanceof WrongPasswordError ? t("unlock.wrong") : String((e as Error)?.message ?? e));
      return;
    }
    const oldIds = this.keyring.keys.map((k) => k.id);
    await this.saveKeyring(added.file);
    const keys = this.keys as MasterKeys;
    keys.set(added.id, added.key);
    keys.activeKeyId = added.id;
    const files = await this.listFiles("", { everything: true });
    const res = await this.runBatch("rekey", files, this.transformFor("rekey"), { newKeyId: added.id, oldKeyIds: oldIds });
    if (res) await this.finishRekeyIfComplete(res);
  }

  /** Drops old master keys once the re-key batch has rewritten everything. */
  private async finishRekeyIfComplete(res: BatchResult): Promise<void> {
    if (res.cancelled || res.failed.length || !this.keyring || !this.keys) {
      new Notice(t("rekey.incomplete"), 10000);
      return;
    }
    // Belt and braces: make sure no file still uses an old key.
    const active = this.keyring.activeKeyId;
    const stillUsed = new Set<number>();
    for (const path of await this.listFiles("", { everything: true })) {
      try {
        const data = new Uint8Array(await this.io.readBinary(path));
        const c = containerOf(data);
        if (c) {
          const id = containerKeyId(c);
          if (id !== active) stillUsed.add(id);
        } else if (this.policy.isTextPath(path) && data.length < 50_000_000) {
          for (const b of findInlineBlocks(fromUtf8(data))) {
            const m = /^`strongbox:v1:k(\d+):/.exec(b.token);
            if (m && Number(m[1]) !== active) stillUsed.add(Number(m[1]));
          }
        }
      } catch {
        /* unreadable file: leave keys in place */
        new Notice(t("rekey.incomplete"), 10000);
        return;
      }
    }
    const drop = this.keyring.keys.map((k) => k.id).filter((id) => id !== active && !stillUsed.has(id));
    if (drop.length) {
      await this.saveKeyring(removeMasterKeys(this.keyring, drop));
      for (const id of drop) this.keys.delete(id);
    }
    if (stillUsed.size) new Notice(t("rekey.keptOld", { n: stillUsed.size }), 10000);
    else new Notice(t("rekey.done"), 8000);
    this.settingTab?.refreshIfOpen();
  }

  // ------------------------------------------------------------ keyring backup

  /** Desktop: a download; mobile browsers may ignore it, so other options exist too. */
  downloadKeyring(): void {
    const json = this.keyringJson();
    if (!json) return;
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = createEl("a", { href: url, attr: { download: `strongbox-keyring-${new Date().toISOString().slice(0, 10)}.json` } });
    activeDocument.body.appendChild(a);
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }

  /** Writes an unencrypted copy of the keyring into the vault root (bypassing encryption). */
  async saveKeyringCopyInVault(): Promise<string | null> {
    const json = this.keyringJson();
    if (!json) return null;
    let name = `Strongbox keyring backup ${new Date().toISOString().slice(0, 10)}.json`;
    let n = 2;
    while (await this.io.exists(name)) name = `Strongbox keyring backup ${new Date().toISOString().slice(0, 10)} (${n++}).json`;
    await this.io.write(name, json);
    return name;
  }

  async copyKeyringToClipboard(): Promise<void> {
    const json = this.keyringJson();
    if (!json) return;
    try {
      await navigator.clipboard.writeText(json);
      new Notice(t("keyring.copied"));
    } catch {
      new Notice(t("common.copyFailed"));
    }
  }

  /** Opens a file picker for a keyring backup (works on desktop and mobile). */
  pickAndImportKeyring(): Promise<boolean> {
    return new Promise((resolve) => {
      const input = createEl("input", { attr: { type: "file", accept: ".json,application/json" } });
      input.addEventListener("change", () => {
        const f = input.files?.[0];
        if (!f) return resolve(false);
        void f
          .text()
          .then((text) => this.importKeyringJson(text))
          .then(resolve, (e: unknown) => {
            console.error("Strongbox: import failed", e);
            resolve(false);
          });
      });
      input.click();
    });
  }

  fileRecoveryEnabled(): boolean {
    try {
      const app = this.app as unknown as { internalPlugins?: { plugins?: Record<string, { enabled?: boolean } | undefined> } };
      return !!app.internalPlugins?.plugins?.["file-recovery"]?.enabled;
    } catch {
      return false;
    }
  }

  // ------------------------------------------------------------ names

  async revealNamesNow(): Promise<void> {
    if (!(await this.ensureUnlocked())) return;
    const res = await this.hider.reveal(this.keys as MasterKeys);
    if (res.problems.length) {
      new Notice(t("names.problems", { n: res.problems.length }), 15000);
      console.warn("Strongbox: name restore problems", res.problems);
    } else new Notice(t("names.revealed", { n: res.restored }));
    this.settingTab?.refreshIfOpen();
  }

  async nameMappingText(): Promise<string | null> {
    if (!this.keys) return null;
    const steps = await this.hider.describe(this.keys);
    return steps ? steps.map((s) => `${s.to}  →  ${s.from}`).join("\n") : null;
  }

  // Exposed for the settings tab.
  get unlockedKeys(): MasterKeys | null {
    return this.keys;
  }
}

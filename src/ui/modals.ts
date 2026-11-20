import { App, ButtonComponent, Modal, Notice, Setting, TextComponent, setIcon } from "obsidian";
import { t } from "../i18n";
import type { BatchProgress } from "../vault/batch";

/** A password field with a show/hide toggle. */
export function passwordField(
  container: HTMLElement,
  name: string,
  onEnter?: () => void,
  desc?: string,
): TextComponent {
  let text!: TextComponent;
  const s = new Setting(container).setName(name);
  if (desc) s.setDesc(desc);
  s.addText((c) => {
    text = c;
    c.inputEl.type = "password";
    c.inputEl.autocomplete = "off";
    c.inputEl.spellcheck = false;
    c.inputEl.addClass("strongbox-password");
    if (onEnter) {
      c.inputEl.addEventListener("keydown", (e: KeyboardEvent) => {
        if (e.key === "Enter" && !e.isComposing) {
          e.preventDefault();
          onEnter();
        }
      });
    }
  });
  s.addExtraButton((b) => {
    b.setIcon("eye").setTooltip(t("common.showPassword"));
    b.onClick(() => {
      const shown = text.inputEl.type === "text";
      text.inputEl.type = shown ? "password" : "text";
      b.setIcon(shown ? "eye" : "eye-off");
    });
  });
  return text;
}

export function warningBox(container: HTMLElement, text: string, strong = false): HTMLElement {
  const box = container.createDiv({ cls: strong ? "strongbox-warning strongbox-warning-strong" : "strongbox-warning" });
  const icon = box.createSpan({ cls: "strongbox-warning-icon" });
  setIcon(icon, "alert-triangle");
  box.createSpan({ text });
  return box;
}

// ------------------------------------------------------------------ unlock

/** What the unlock dialog gets back: success, a wrong password, or another error to show. */
export type UnlockOutcome = "ok" | "wrong" | { error: string };

/** The one unlock dialog. Resolves true once unlocked. */
export class UnlockModal extends Modal {
  private resolved = false;
  private resolve!: (ok: boolean) => void;
  readonly result: Promise<boolean>;

  constructor(app: App, private readonly tryUnlock: (password: string) => Promise<UnlockOutcome>, private readonly reason?: string) {
    super(app);
    this.result = new Promise((r) => (this.resolve = r));
  }

  onOpen(): void {
    const { contentEl } = this;
    this.modalEl.addClass("strongbox-modal");
    this.titleEl.setText(t("unlock.title"));
    if (this.reason) contentEl.createEl("p", { text: this.reason, cls: "strongbox-muted" });
    let busy = false;
    const error = contentEl.createDiv({ cls: "strongbox-error" });
    const submit = async () => {
      if (busy) return;
      const pw = field.getValue();
      if (!pw) return;
      busy = true;
      button.setDisabled(true).setButtonText(t("unlock.working"));
      error.setText("");
      const outcome = await this.tryUnlock(pw);
      busy = false;
      button.setDisabled(false).setButtonText(t("unlock.button"));
      if (outcome === "ok") {
        // Unlocking already closed this dialog (unlockedElsewhere); do not close it twice.
        if (!this.resolved) {
          this.finish(true);
          this.close();
        }
      } else {
        error.setText(outcome === "wrong" ? t("unlock.wrong") : outcome.error);
        field.inputEl.select();
      }
    };
    const field = passwordField(contentEl, t("unlock.password"), () => void submit());
    contentEl.appendChild(error);
    contentEl.createEl("p", { text: t("unlock.noRecovery"), cls: "strongbox-muted strongbox-small" });
    let button!: ButtonComponent;
    new Setting(contentEl).addButton((b) => {
      button = b;
      b.setButtonText(t("unlock.button")).setCta().onClick(() => void submit());
    });
    window.setTimeout(() => field.inputEl.focus(), 50);
  }

  /** Strongbox was unlocked some other way: resolve and close this dialog. */
  unlockedElsewhere(): void {
    if (this.resolved) return;
    this.finish(true);
    this.close();
  }

  private finish(ok: boolean): void {
    if (this.resolved) return;
    this.resolved = true;
    this.resolve(ok);
  }

  onClose(): void {
    this.contentEl.empty();
    this.finish(false);
  }
}

// ------------------------------------------------------------------ prompts

export interface PasswordPromptOptions {
  title: string;
  desc?: string;
  confirm?: boolean;
  warning?: string;
  button?: string;
  minLength?: number;
}

/** Asks for a password (optionally twice). Resolves null when dismissed. */
export function promptPassword(app: App, options: PasswordPromptOptions): Promise<string | null> {
  return new Promise((resolve) => {
    let done = false;
    const modal = new (class extends Modal {
      onOpen() {
        const { contentEl } = this;
        this.modalEl.addClass("strongbox-modal");
        this.titleEl.setText(options.title);
        if (options.desc) contentEl.createEl("p", { text: options.desc });
        if (options.warning) warningBox(contentEl, options.warning, true);
        const error = contentEl.createDiv({ cls: "strongbox-error" });
        const submit = () => {
          const a = first.getValue();
          if (!a) return;
          if (options.minLength && a.length < options.minLength) {
            error.setText(t("password.tooShort", { n: options.minLength }));
            return;
          }
          if (second && second.getValue() !== a) {
            error.setText(t("password.mismatch"));
            return;
          }
          done = true;
          resolve(a);
          this.close();
        };
        const first = passwordField(contentEl, t("password.password"), options.confirm ? undefined : submit);
        const second = options.confirm ? passwordField(contentEl, t("password.confirm"), submit) : null;
        contentEl.appendChild(error);
        new Setting(contentEl).addButton((b) => b.setButtonText(options.button ?? t("common.ok")).setCta().onClick(submit));
        window.setTimeout(() => first.inputEl.focus(), 50);
      }
      onClose() {
        this.contentEl.empty();
        if (!done) resolve(null);
      }
    })(app);
    modal.open();
  });
}

export function confirmDialog(
  app: App,
  options: { title: string; body: string | string[]; confirm: string; danger?: boolean; checkbox?: string },
): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false;
    const modal = new (class extends Modal {
      onOpen() {
        const { contentEl } = this;
        this.modalEl.addClass("strongbox-modal");
        this.titleEl.setText(options.title);
        for (const p of Array.isArray(options.body) ? options.body : [options.body]) contentEl.createEl("p", { text: p });
        let checked = !options.checkbox;
        let button!: ButtonComponent;
        if (options.checkbox) {
          new Setting(contentEl).setName(options.checkbox).addToggle((tg) =>
            tg.setValue(false).onChange((v) => {
              checked = v;
              button.setDisabled(!v);
            }),
          );
        }
        new Setting(contentEl)
          .addButton((b) => b.setButtonText(t("common.cancel")).onClick(() => this.close()))
          .addButton((b) => {
            button = b;
            b.setButtonText(options.confirm).setDisabled(!checked).onClick(() => {
              done = true;
              resolve(true);
              this.close();
            });
            if (options.danger) b.setWarning();
            else b.setCta();
          });
      }
      onClose() {
        this.contentEl.empty();
        if (!done) resolve(false);
      }
    })(app);
    modal.open();
  });
}

// ------------------------------------------------------------------ progress

export class ProgressModal extends Modal {
  readonly controller = new AbortController();
  private bar!: HTMLElement;
  private label!: HTMLElement;
  private current!: HTMLElement;
  private cancelButton!: ButtonComponent;

  constructor(app: App, private readonly heading: string) {
    super(app);
  }

  onOpen(): void {
    const { contentEl } = this;
    this.modalEl.addClass("strongbox-modal");
    this.titleEl.setText(this.heading);
    const track = contentEl.createDiv({ cls: "strongbox-progress" });
    this.bar = track.createDiv({ cls: "strongbox-progress-bar" });
    this.label = contentEl.createDiv({ cls: "strongbox-progress-label" });
    this.current = contentEl.createDiv({ cls: "strongbox-progress-current strongbox-muted strongbox-small" });
    contentEl.createEl("p", { text: t("progress.keepOpen"), cls: "strongbox-muted strongbox-small" });
    new Setting(contentEl).addButton((b) => {
      this.cancelButton = b;
      b.setButtonText(t("progress.cancel")).onClick(() => {
        this.controller.abort();
        b.setDisabled(true).setButtonText(t("progress.cancelling"));
      });
    });
  }

  update(p: BatchProgress): void {
    if (!this.bar) return;
    const pct = p.total === 0 ? 100 : Math.round((p.processed / p.total) * 100);
    this.bar.style.width = `${pct}%`;
    this.label.setText(t("progress.counts", { done: p.processed, total: p.total, changed: p.changed, skipped: p.skipped, failed: p.failed }));
    this.current.setText(p.current ?? "");
  }

  onClose(): void {
    this.contentEl.empty();
  }
}

// ------------------------------------------------------------------ inline

/** Encrypt-selection dialog: master key or a separate password. */
export function chooseInlineMode(app: App): Promise<{ mode: "master" } | { mode: "password"; password: string } | null> {
  return new Promise((resolve) => {
    let done = false;
    const modal = new (class extends Modal {
      onOpen() {
        const { contentEl } = this;
        this.modalEl.addClass("strongbox-modal");
        this.titleEl.setText(t("inline.encryptTitle"));
        let mode: "master" | "password" = "master";
        const pwBox = contentEl.createDiv();
        new Setting(contentEl)
          .setName(t("inline.mode"))
          .addDropdown((d) =>
            d
              .addOption("master", t("inline.modeMaster"))
              .addOption("password", t("inline.modePassword"))
              .setValue("master")
              .onChange((v) => {
                mode = v as "master" | "password";
                pwBox.toggleClass("strongbox-hidden", mode !== "password");
              }),
          );
        contentEl.appendChild(pwBox);
        pwBox.addClass("strongbox-hidden");
        warningBox(pwBox, t("inline.passwordWarning"), true);
        const error = pwBox.createDiv({ cls: "strongbox-error" });
        const p1 = passwordField(pwBox, t("password.password"));
        const p2 = passwordField(pwBox, t("password.confirm"));
        pwBox.appendChild(error);
        const submit = () => {
          if (mode === "master") {
            done = true;
            resolve({ mode });
            this.close();
            return;
          }
          const a = p1.getValue();
          if (!a) return error.setText(t("password.empty"));
          if (a !== p2.getValue()) return error.setText(t("password.mismatch"));
          done = true;
          resolve({ mode, password: a });
          this.close();
        };
        new Setting(contentEl).addButton((b) => b.setButtonText(t("inline.encrypt")).setCta().onClick(submit));
      }
      onClose() {
        this.contentEl.empty();
        if (!done) resolve(null);
      }
    })(app);
    modal.open();
  });
}

export interface InlineViewOptions {
  /** Decrypts the block; `password` is given for password blocks. */
  decrypt(password?: string): Promise<string>;
  needsPassword: boolean;
  /** Replaces the block with its plaintext in the note. */
  restore?(plaintext: string): Promise<void>;
}

/** Shows a decrypted inline block, with copy and restore-in-place. */
export class InlineViewModal extends Modal {
  static open = new Set<InlineViewModal>();
  private plaintext: string | null = null;

  constructor(app: App, private readonly options: InlineViewOptions) {
    super(app);
  }

  onOpen(): void {
    InlineViewModal.open.add(this);
    this.modalEl.addClass("strongbox-modal");
    this.titleEl.setText(t("inline.viewTitle"));
    if (this.options.needsPassword) this.askPassword();
    else void this.show();
  }

  private askPassword(): void {
    const { contentEl } = this;
    contentEl.empty();
    const error = contentEl.createDiv({ cls: "strongbox-error" });
    const submit = () => void this.show(field.getValue(), error);
    const field = passwordField(contentEl, t("inline.blockPassword"), submit);
    contentEl.appendChild(error);
    new Setting(contentEl).addButton((b) => b.setButtonText(t("inline.decrypt")).setCta().onClick(submit));
    window.setTimeout(() => field.inputEl.focus(), 50);
  }

  private async show(password?: string, errorEl?: HTMLElement): Promise<void> {
    try {
      this.plaintext = await this.options.decrypt(password);
    } catch (e) {
      if (errorEl) errorEl.setText(t("inline.decryptFailed"));
      else {
        this.contentEl.empty();
        this.contentEl.createDiv({ cls: "strongbox-error", text: t("inline.decryptFailed") + " " + String((e as Error)?.message ?? e) });
      }
      return;
    }
    const { contentEl } = this;
    contentEl.empty();
    const area = contentEl.createEl("textarea", { cls: "strongbox-inline-plain" });
    area.value = this.plaintext;
    area.readOnly = true;
    area.rows = Math.min(16, Math.max(3, this.plaintext.split("\n").length + 1));
    const row = new Setting(contentEl);
    row.addButton((b) =>
      b.setButtonText(t("common.copy")).onClick(async () => {
        try {
          await navigator.clipboard.writeText(this.plaintext ?? "");
          new Notice(t("common.copied"));
        } catch {
          area.select();
          new Notice(t("common.copyFailed"));
        }
      }),
    );
    if (this.options.restore) {
      row.addButton((b) =>
        b.setButtonText(t("inline.restore")).setWarning().onClick(async () => {
          await this.options.restore?.(this.plaintext ?? "");
          this.close();
        }),
      );
    }
    row.addButton((b) => b.setButtonText(t("common.close")).onClick(() => this.close()));
  }

  onClose(): void {
    InlineViewModal.open.delete(this);
    this.plaintext = null;
    this.contentEl.empty();
  }

  static closeAll(): void {
    for (const m of [...InlineViewModal.open]) m.close();
  }
}

/** Asks whether to include attachments when protecting one file. */
export function askProtectFile(app: App, fileName: string, attachmentCount: number, defaultInclude: boolean): Promise<{ withAttachments: boolean } | null> {
  return new Promise((resolve) => {
    let done = false;
    const modal = new (class extends Modal {
      onOpen() {
        const { contentEl } = this;
        this.modalEl.addClass("strongbox-modal");
        this.titleEl.setText(t("file.protectTitle"));
        contentEl.createEl("p", { text: t("file.protectBody", { name: fileName }) });
        let include = defaultInclude && attachmentCount > 0;
        if (attachmentCount > 0) {
          new Setting(contentEl)
            .setName(t("file.withAttachments", { n: attachmentCount }))
            .setDesc(t("file.withAttachmentsDesc"))
            .addToggle((tg) => tg.setValue(include).onChange((v) => (include = v)));
        }
        new Setting(contentEl)
          .addButton((b) => b.setButtonText(t("common.cancel")).onClick(() => this.close()))
          .addButton((b) =>
            b.setButtonText(t("file.protect")).setCta().onClick(() => {
              done = true;
              resolve({ withAttachments: include });
              this.close();
            }),
          );
      }
      onClose() {
        this.contentEl.empty();
        if (!done) resolve(null);
      }
    })(app);
    modal.open();
  });
}

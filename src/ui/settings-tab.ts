import { App, Notice, Platform, PluginSettingTab, Setting } from "obsidian";
import { t } from "../i18n";
import type StrongboxPlugin from "../main";
import { normPath } from "../vault/rules";
import { confirmDialog, warningBox } from "./modals";

export class StrongboxSettingTab extends PluginSettingTab {
  private shown = false;

  constructor(app: App, private readonly plugin: StrongboxPlugin) {
    super(app, plugin);
  }

  hide(): void {
    this.shown = false;
  }

  refreshIfOpen(): void {
    if (this.shown) this.display();
  }

  /** Export buttons, also used by the setup wizard. */
  renderBackupButtons(container: HTMLElement): void {
    const p = this.plugin;
    const setting = new Setting(container).setName(t("keyring.export")).setDesc(t("keyring.exportDesc"));
    // A download link does nothing in the mobile apps; copy or save a copy instead.
    if (!Platform.isMobile) setting.addButton((b) => b.setButtonText(t("keyring.download")).onClick(() => p.downloadKeyring()));
    setting
      .addButton((b) => b.setButtonText(t("keyring.copy")).onClick(() => void p.copyKeyringToClipboard()))
      .addButton((b) =>
        b.setButtonText(t("keyring.saveInVault")).onClick(async () => {
          const name = await p.saveKeyringCopyInVault();
          if (name) new Notice(t("keyring.savedInVault", { name }), 10000);
        }),
      );
  }

  display(): void {
    this.shown = true;
    const { containerEl } = this;
    const p = this.plugin;
    const s = p.settings;
    containerEl.empty();
    containerEl.addClass("strongbox-settings");

    // ---- status
    new Setting(containerEl).setName(t("set.status")).setHeading();
    warningBox(containerEl, t("set.noRecovery"), true);
    const status = new Setting(containerEl).setName(
      !p.isInitialized() ? t("status.notSetUp") : p.isUnlocked() ? t("status.unlocked") : t("status.locked"),
    );
    if (p.currentKdfLabel()) status.setDesc(t("set.kdfInUse", { kdf: p.currentKdfLabel() as string }));
    if (!p.isInitialized()) {
      status.addButton((b) => b.setButtonText(t("set.setUp")).setCta().onClick(() => void p.openSetup().then(() => this.display())));
      status.addButton((b) => b.setButtonText(t("keyring.import")).onClick(() => void p.pickAndImportKeyring().then(() => this.display())));
    } else if (p.isUnlocked()) {
      status.addButton((b) => b.setButtonText(t("cmd.lock")).onClick(() => void p.lock("manual").then(() => this.display())));
    } else {
      status.addButton((b) => b.setButtonText(t("cmd.unlock")).setCta().onClick(() => void p.ensureUnlocked().then(() => this.display())));
    }

    void this.renderPending(containerEl.createDiv());

    // ---- what is protected
    new Setting(containerEl).setName(t("set.protection")).setHeading();
    const rules = s.rules;
    if (rules.length === 0) containerEl.createEl("p", { text: t("set.noRules"), cls: "strongbox-muted" });
    for (const rule of rules) {
      new Setting(containerEl)
        .setName(p.describeRule(rule))
        .addButton((b) => b.setButtonText(t("set.unprotect")).onClick(() => void p.removeRuleAndDecrypt(rule)));
    }
    new Setting(containerEl)
      .setName(t("set.wholeVault"))
      .setDesc(t("set.wholeVaultDesc", { config: this.app.vault.configDir }))
      .addButton((b) =>
        p.policy.hasRule("vault", "")
          ? b.setButtonText(t("vault.unprotect")).setWarning().onClick(() => void p.unprotectVault())
          : b.setButtonText(t("vault.protect")).onClick(() => void p.protectVault()),
      );
    containerEl.createEl("p", { text: t(Platform.isMobile ? "set.howToProtectMobile" : "set.howToProtect"), cls: "strongbox-muted strongbox-small" });

    new Setting(containerEl)
      .setName(t("set.excludes"))
      .setDesc(t("set.excludesDesc"))
      .addTextArea((ta) => {
        ta.setValue(s.excludes.join("\n")).setPlaceholder(t("set.excludesPlaceholder"));
        ta.inputEl.rows = 4;
        onBlur(ta.inputEl, async () => {
          const next = ta.getValue().split("\n").map((l) => normPath(l.trim())).filter(Boolean);
          if (next.join("\n") === s.excludes.join("\n")) return;
          s.excludes = next;
          await p.saveSettings();
          new Notice(t("set.excludesSaved"));
        });
      });
    new Setting(containerEl)
      .setName(t("set.textExt"))
      .setDesc(t("set.textExtDesc"))
      .addText((tx) => {
        tx.setValue(s.textExtensions.join(", "));
        onBlur(tx.inputEl, async () => {
          const next = tx.getValue().split(/[\s,]+/).map((e) => e.replace(/^\./, "").toLowerCase()).filter(Boolean);
          s.textExtensions = next.length ? next : ["md"];
          await p.saveSettings();
        });
      });

    // ---- auto lock
    new Setting(containerEl).setName(t("set.autoLock")).setHeading();
    new Setting(containerEl)
      .setName(t("set.idle"))
      .setDesc(t("set.idleDesc"))
      .addText((tx) => {
        tx.inputEl.type = "number";
        tx.setValue(String(s.idleMinutes)).onChange(async (v) => {
          const n = Math.max(0, Math.floor(Number(v)));
          if (Number.isFinite(n)) {
            s.idleMinutes = n;
            await p.saveSettings();
          }
        });
      });
    new Setting(containerEl)
      .setName(t("set.background"))
      .setDesc(t("set.backgroundDesc"))
      .addText((tx) => {
        tx.inputEl.type = "number";
        tx.setValue(String(s.backgroundLockSeconds)).onChange(async (v) => {
          const n = Math.floor(Number(v));
          if (Number.isFinite(n)) {
            s.backgroundLockSeconds = Math.max(-1, n);
            await p.saveSettings();
          }
        });
      });
    if (!Platform.isMobile) {
      new Setting(containerEl)
        .setName(t("set.statusBar"))
        .addToggle((tg) =>
          tg.setValue(s.showStatusBar).onChange(async (v) => {
            s.showStatusBar = v;
            await p.saveSettings();
            p.refreshStatus();
          }),
        );
    }
    new Setting(containerEl)
      .setName(t("set.attachDefault"))
      .addToggle((tg) =>
        tg.setValue(s.includeAttachmentsByDefault).onChange(async (v) => {
          s.includeAttachmentsByDefault = v;
          await p.saveSettings();
        }),
      );

    // ---- password and keys
    new Setting(containerEl).setName(t("set.passwordKeys")).setHeading();
    new Setting(containerEl)
      .setName(t("set.kdf"))
      .setDesc(t("set.kdfDesc"))
      .addDropdown((d) =>
        d
          .addOption("argon2id", "Argon2id")
          .addOption("pbkdf2-sha256", "PBKDF2-SHA-256")
          .setValue(s.kdfAlgorithm)
          .onChange(async (v) => {
            s.kdfAlgorithm = v as typeof s.kdfAlgorithm;
            await p.saveSettings();
            this.display();
          }),
      );
    if (s.kdfAlgorithm === "argon2id") {
      this.numberSetting(containerEl, t("set.argonMemory"), t("set.argonMemoryDesc"), s.argon2MemoryMiB, 8, 1024, async (n) => {
        s.argon2MemoryMiB = n;
        await p.saveSettings();
      });
      this.numberSetting(containerEl, t("set.argonIterations"), "", s.argon2Iterations, 1, 20, async (n) => {
        s.argon2Iterations = n;
        await p.saveSettings();
      });
    } else {
      this.numberSetting(containerEl, t("set.pbkdf2Iterations"), t("set.pbkdf2Desc"), s.pbkdf2Iterations, 100_000, 10_000_000, async (n) => {
        s.pbkdf2Iterations = n;
        await p.saveSettings();
      });
    }
    new Setting(containerEl)
      .setName(t("cmd.changePassword"))
      .setDesc(t("set.changePasswordDesc"))
      .addButton((b) => b.setButtonText(t("set.changePassword")).setDisabled(!p.isInitialized()).onClick(() => void p.changePassword()));
    new Setting(containerEl)
      .setName(t("cmd.rekey"))
      .setDesc(t("set.rekeyDesc"))
      .addButton((b) => b.setButtonText(t("rekey.start")).setDisabled(!p.isInitialized()).onClick(() => void p.rekey()));
    if (p.keyring && p.keyring.keys.length > 1) {
      containerEl.createEl("p", { text: t("set.multipleKeys", { n: p.keyring.keys.length }), cls: "strongbox-muted" });
    }

    // ---- key file
    new Setting(containerEl).setName(t("set.keyFile")).setHeading();
    containerEl.createEl("p", { text: t("set.keyFileDesc", { path: p.keyringPath }), cls: "strongbox-muted" });
    if (p.isInitialized()) this.renderBackupButtons(containerEl);
    new Setting(containerEl)
      .setName(t("keyring.import"))
      .setDesc(t("keyring.importDesc"))
      .addButton((b) => b.setButtonText(t("keyring.importButton")).onClick(() => void p.pickAndImportKeyring().then(() => this.display())));

    // ---- traces
    new Setting(containerEl).setName(t("set.traces")).setHeading();
    const fr = p.fileRecoveryEnabled();
    const frSetting = new Setting(containerEl).setName(t("set.fileRecovery")).setDesc(fr ? t("set.fileRecoveryOn") : t("set.fileRecoveryOff"));
    if (fr) frSetting.settingEl.addClass("strongbox-attention");
    containerEl.createEl("p", { text: t("set.tracesDesc"), cls: "strongbox-muted strongbox-small" });

    // ---- experimental
    new Setting(containerEl).setName(t("set.experimental")).setHeading();
    new Setting(containerEl)
      .setName(t("set.hideNames"))
      .setDesc(t("set.hideNamesDesc"))
      .addToggle((tg) =>
        tg.setValue(s.hideNames).onChange(async (v) => {
          if (v) {
            const ok = await confirmDialog(this.app, {
              title: t("set.hideNames"),
              body: [t("set.hideNamesConfirm"), t("set.hideNamesConfirm2")],
              confirm: t("common.enable"),
            });
            if (!ok) {
              tg.setValue(false);
              return;
            }
          }
          s.hideNames = v;
          await p.saveSettings();
        }),
      );
    void this.renderNames(containerEl.createDiv());
  }

  private numberSetting(el: HTMLElement, name: string, desc: string, value: number, min: number, max: number, save: (n: number) => Promise<void>): void {
    new Setting(el)
      .setName(name)
      .setDesc(desc)
      .addText((tx) => {
        tx.inputEl.type = "number";
        tx.setValue(String(value));
        onBlur(tx.inputEl, async () => {
          const n = Math.floor(Number(tx.getValue()));
          if (!Number.isFinite(n) || n < min || n > max) {
            new Notice(t("set.outOfRange", { min, max }));
            tx.setValue(String(value));
            return;
          }
          await save(n);
        });
      });
  }

  private async renderPending(el: HTMLElement): Promise<void> {
    const pending = await this.plugin.batch.pending();
    if (!pending) return;
    const op = pending.op === "encrypt" ? t("op.encrypt") : pending.op === "decrypt" ? t("op.decrypt") : t("op.rekey");
    new Setting(el)
      .setName(t("batch.pendingTitle"))
      .setDesc(t("batch.resumeBody", { op, n: pending.remaining, total: pending.total }))
      .addButton((b) => b.setButtonText(t("batch.resume")).setCta().onClick(() => void this.plugin.resumeBatch()))
      .addButton((b) => b.setButtonText(t("batch.discard")).setWarning().onClick(() => void this.plugin.discardBatch()));
  }

  private async renderNames(el: HTMLElement): Promise<void> {
    const p = this.plugin;
    if (!(await p.hider.isHidden())) return;
    const row = new Setting(el).setName(t("names.statusHidden")).setDesc(p.isUnlocked() ? t("names.statusStuck") : t("names.statusLocked"));
    if (!p.isUnlocked()) return;
    row.addButton((b) => b.setButtonText(t("names.retry")).setCta().onClick(() => void p.revealNamesNow()));
    row.addButton((b) =>
      b.setButtonText(t("names.showMapping")).onClick(async () => {
        const text = await p.nameMappingText();
        if (!text) return new Notice(t("names.noMapping"));
        const pre = el.createEl("pre", { cls: "strongbox-mapping" });
        pre.setText(text);
      }),
    );
    row.addButton((b) =>
      b.setButtonText(t("names.forget")).setWarning().onClick(async () => {
        const ok = await confirmDialog(this.app, {
          title: t("names.forget"),
          body: t("names.forgetBody"),
          confirm: t("names.forget"),
          danger: true,
          checkbox: t("names.forgetCheckbox"),
        });
        if (!ok) return;
        await p.hider.forget();
        this.display();
      }),
    );
  }
}

/** Runs an async handler when the field loses focus; errors are logged. */
function onBlur(el: HTMLElement, handler: () => Promise<void>): void {
  el.addEventListener("blur", () => {
    handler().catch((e: unknown) => console.error("Strongbox: could not save the setting", e));
  });
}

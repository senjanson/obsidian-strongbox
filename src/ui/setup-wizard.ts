import { App, ButtonComponent, Modal, Platform, Setting } from "obsidian";
import { t } from "../i18n";
import { passwordField, warningBox } from "./modals";

export const MIN_PASSWORD_LENGTH = 8;

export interface SetupActions {
  kdfLabel(): string;
  /** Creates the keyring with this password and unlocks. */
  create(password: string): Promise<void>;
  /** Renders the backup buttons (shared with the settings tab). */
  renderBackup(container: HTMLElement): void;
  /** Lets the user pick an existing keyring backup instead. */
  importKeyring(): Promise<boolean>;
  fileRecoveryEnabled(): boolean;
}

/** First-run wizard: warnings, password twice, then a keyring backup. */
export class SetupWizard extends Modal {
  private resolve!: (ok: boolean) => void;
  readonly result: Promise<boolean>;
  private created = false;

  constructor(app: App, private readonly actions: SetupActions) {
    super(app);
    this.result = new Promise((r) => (this.resolve = r));
  }

  onOpen(): void {
    this.modalEl.addClass("strongbox-modal", "strongbox-wizard");
    this.titleEl.setText(t("setup.title"));
    this.stepPassword();
  }

  private stepPassword(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("p", { text: t("setup.intro") });
    warningBox(contentEl, t("setup.warnNoRecovery"), true);
    warningBox(contentEl, t("setup.warnKeyring"), true);
    if (this.actions.fileRecoveryEnabled()) warningBox(contentEl, t("setup.warnFileRecovery"));

    let understood = false;
    let button!: ButtonComponent;
    const error = contentEl.createDiv({ cls: "strongbox-error" });
    const p1 = passwordField(contentEl, t("password.password"), undefined, t("setup.passwordDesc", { n: MIN_PASSWORD_LENGTH }));
    const submit = async () => {
      if (!understood) return;
      const a = p1.getValue();
      if (a.length < MIN_PASSWORD_LENGTH) return error.setText(t("password.tooShort", { n: MIN_PASSWORD_LENGTH }));
      if (a !== p2.getValue()) return error.setText(t("password.mismatch"));
      error.setText("");
      button.setDisabled(true).setButtonText(t("setup.creating"));
      try {
        await this.actions.create(a);
        this.created = true;
        this.stepBackup();
      } catch (e) {
        error.setText(String((e as Error)?.message ?? e));
        button.setDisabled(false).setButtonText(t("setup.create"));
      }
    };
    const p2 = passwordField(contentEl, t("password.confirm"), () => void submit());
    contentEl.appendChild(error);
    contentEl.createEl("p", { text: t("setup.kdf", { kdf: this.actions.kdfLabel() }), cls: "strongbox-muted strongbox-small" });

    new Setting(contentEl)
      .setName(t("setup.understand"))
      .setDesc(t("setup.understandDesc"))
      .addToggle((tg) =>
        tg.setValue(false).onChange((v) => {
          understood = v;
          button.setDisabled(!v);
        }),
      );
    new Setting(contentEl)
      .addButton((b) =>
        b.setButtonText(t("setup.importInstead")).onClick(async () => {
          if (await this.actions.importKeyring()) {
            this.created = true;
            this.close();
          }
        }),
      )
      .addButton((b) => {
        button = b;
        b.setButtonText(t("setup.create")).setCta().setDisabled(true).onClick(() => void submit());
      });
  }

  private stepBackup(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h3", { text: t("setup.doneTitle") });
    contentEl.createEl("p", { text: t("setup.backupIntro") });
    warningBox(contentEl, t("setup.warnKeyring"), true);
    this.actions.renderBackup(contentEl);
    contentEl.createEl("p", { text: t(Platform.isMobile ? "setup.nextMobile" : "setup.next"), cls: "strongbox-muted" });
    new Setting(contentEl).addButton((b) => b.setButtonText(t("setup.finish")).setCta().onClick(() => this.close()));
  }

  onClose(): void {
    this.contentEl.empty();
    this.resolve(this.created);
  }
}

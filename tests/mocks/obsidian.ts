/**
 * A minimal stand-in for the `obsidian` module, enough to load the plugin
 * in Node. Elements are tiny fakes with the helpers Obsidian adds to
 * HTMLElement (addClass, createSpan …).
 */
export class FakeEl {
  children: FakeEl[] = [];
  attrs: Record<string, string> = {};
  classes = new Set<string>();
  text = '';
  style: Record<string, string> = {};
  addClass(...c: string[]) { c.forEach((x) => this.classes.add(x)); }
  removeClass(...c: string[]) { c.forEach((x) => this.classes.delete(x)); }
  toggleClass(c: string, on: boolean) { on ? this.classes.add(c) : this.classes.delete(c); }
  hasClass(c: string) { return this.classes.has(c); }
  empty() { this.children = []; this.text = ''; }
  setText(t: string) { this.text = t; }
  setAttribute(k: string, v: string) { this.attrs[k] = v; }
  getAttribute(k: string) { return this.attrs[k] ?? null; }
  removeAttribute(k: string) { delete this.attrs[k]; }
  createEl(_tag: string, o?: { text?: string; cls?: string }) { const e = new FakeEl(); if (o?.text) e.text = o.text; this.children.push(e); return e; }
  createDiv(o?: { text?: string; cls?: string }) { return this.createEl('div', o); }
  createSpan(o?: { text?: string; cls?: string }) { return this.createEl('span', o); }
  appendChild(e: FakeEl) { this.children.push(e); return e; }
  querySelectorAll() { return []; }
  addEventListener() {}
}

export class App {}
export class Vault { adapter: any; }
export class TAbstractFile {
  path: string;
  name: string;
  constructor(path: string) { this.path = path; this.name = path.slice(path.lastIndexOf('/') + 1); }
}
export class TFile extends TAbstractFile {
  stat = { mtime: Date.now(), size: 0, ctime: Date.now() };
  get extension() { const i = this.name.lastIndexOf('.'); return i > 0 ? this.name.slice(i + 1) : ''; }
  get basename() { const i = this.name.lastIndexOf('.'); return i > 0 ? this.name.slice(0, i) : this.name; }
}
export class TFolder extends TAbstractFile {
  children: TAbstractFile[] = [];
  isRoot(): boolean { return this.path === '/' || this.path === ''; }
}
export class EventRef {}

export class Component {
  load() {}
  unload() {}
}

export class Plugin extends Component {
  app: any;
  manifest: any;
  commands: any[] = [];
  data: any = null;
  constructor(app: any, manifest: any) { super(); this.app = app; this.manifest = manifest; }
  async loadData() { return this.data; }
  async saveData(d: any) { this.data = JSON.parse(JSON.stringify(d)); }
  addCommand(c: any) { this.commands.push(c); return c; }
  addRibbonIcon() { return new FakeEl(); }
  addStatusBarItem() { return new FakeEl(); }
  addSettingTab() {}
  registerDomEvent() {}
  registerEvent() {}
  /** Timers are not kept running in tests. */
  registerInterval(id: any) { clearInterval(id); return id; }
  registerMarkdownPostProcessor() {}
  registerEditorExtension() {}
}

export class PluginSettingTab {
  app: any;
  containerEl = new FakeEl();
  constructor(app: any, _plugin: any) { this.app = app; }
  display() {}
  hide() {}
}
export class Setting {
  settingEl = new FakeEl();
  constructor(_el: any) {}
  setName() { return this; }
  setDesc() { return this; }
  setHeading() { return this; }
  addButton() { return this; }
  addToggle() { return this; }
  addText() { return this; }
  addTextArea() { return this; }
  addDropdown() { return this; }
  addExtraButton() { return this; }
}
export class ButtonComponent {}
export class TextComponent {}
export class WorkspaceLeaf {}
export class ItemView {}
export class TextFileView { async save() {} }
export class MarkdownView extends TextFileView {}
export class Menu {}
export class Editor {}
export class Modal {
  static opened: Modal[] = [];
  app: any;
  contentEl: any = new FakeEl();
  titleEl: any = new FakeEl();
  modalEl: any = new FakeEl();
  constructor(app: any) { this.app = app; }
  open() { Modal.opened.push(this); }
  close() { (this as any).onClose?.(); }
}
export class Notice {
  static shown: string[] = [];
  constructor(message: string, _timeout?: number) { Notice.shown.push(message); }
  hide() {}
}
export function setIcon(_el: any, _icon: string) {}
export function debounce<T extends (...a: any[]) => any>(fn: T) { return fn; }
export const editorLivePreviewField = {};
export interface MarkdownPostProcessorContext { sourcePath: string }

/** The desktop app, as the tests run in Node. */
export const Platform = {
  isDesktop: true,
  isDesktopApp: true,
  isMobile: false,
  isMobileApp: false,
  isIosApp: false,
  isAndroidApp: false,
  isMacOS: process.platform === 'darwin',
  isWin: process.platform === 'win32',
  isLinux: process.platform === 'linux',
};

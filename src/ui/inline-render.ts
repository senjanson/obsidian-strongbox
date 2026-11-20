/**
 * Shows inline encrypted blocks as a lock badge: in reading mode through a
 * Markdown post-processor (the block renders as <code>), in Live Preview
 * through a CodeMirror decoration that steps aside while the cursor or
 * selection touches the block, so its source stays editable.
 */
import { RangeSetBuilder } from "@codemirror/state";
import { Decoration, DecorationSet, EditorView, ViewPlugin, ViewUpdate, WidgetType } from "@codemirror/view";
import { MarkdownPostProcessorContext, editorLivePreviewField, setIcon } from "obsidian";
import { INLINE_BLOCK_RE, inlineBlockMode } from "../crypto/inline";
import { t } from "../i18n";

export interface InlineHost {
  /** Opens the viewer; `restore` replaces the block with plaintext in the note. */
  openInline(token: string, restore: (plain: string) => Promise<void>): void;
  /** Replaces the first occurrence of `token` in the note at `path`. */
  replaceInFile(path: string, token: string, plain: string): Promise<void>;
}

const FULL_TOKEN = new RegExp("^" + INLINE_BLOCK_RE.source + "$");

function badge(doc: Document, token: string): HTMLElement {
  const el = doc.createElement("span");
  el.className = "strongbox-inline-lock";
  el.setAttribute("role", "button");
  el.setAttribute("tabindex", "0");
  const mode = inlineBlockMode(token);
  el.setAttribute("aria-label", mode === "password" ? t("inline.badgePassword") : t("inline.badgeMaster"));
  const icon = doc.createElement("span");
  icon.className = "strongbox-inline-lock-icon";
  setIcon(icon, mode === "password" ? "key-round" : "lock");
  el.appendChild(icon);
  const label = doc.createElement("span");
  label.className = "strongbox-inline-lock-label";
  label.textContent = t("inline.badge");
  el.appendChild(label);
  return el;
}

export function inlinePostProcessor(host: InlineHost) {
  return (el: HTMLElement, ctx: MarkdownPostProcessorContext): void => {
    const codes = Array.from(el.querySelectorAll("code"));
    for (const code of codes) {
      if (code.parentElement?.tagName === "PRE") continue;
      const token = "`" + (code.textContent ?? "") + "`";
      if (!FULL_TOKEN.test(token)) continue;
      const b = badge(el.ownerDocument, token);
      const open = (e: Event) => {
        e.preventDefault();
        e.stopPropagation();
        host.openInline(token, (plain) => host.replaceInFile(ctx.sourcePath, token, plain));
      };
      b.addEventListener("click", open);
      b.addEventListener("keydown", (e: KeyboardEvent) => {
        if (e.key === "Enter" || e.key === " ") open(e);
      });
      code.replaceWith(b);
    }
  };
}

class LockWidget extends WidgetType {
  constructor(private readonly token: string, private readonly host: InlineHost) {
    super();
  }

  eq(other: LockWidget): boolean {
    return other.token === this.token;
  }

  toDOM(view: EditorView): HTMLElement {
    const el = badge(view.dom.ownerDocument, this.token);
    el.addEventListener("mousedown", (e) => {
      e.preventDefault();
      e.stopPropagation();
      this.host.openInline(this.token, async (plain) => {
        const text = view.state.doc.toString();
        const at = text.indexOf(this.token);
        if (at < 0) throw new Error(t("inline.blockGone"));
        view.dispatch({ changes: { from: at, to: at + this.token.length, insert: plain } });
      });
    });
    return el;
  }

  ignoreEvent(): boolean {
    return true;
  }
}

function build(view: EditorView, host: InlineHost): DecorationSet {
  const builder = new RangeSetBuilder<Decoration>();
  let live = true;
  try {
    live = view.state.field(editorLivePreviewField, false) ?? true;
  } catch {
    live = true;
  }
  if (!live) return builder.finish();
  const sel = view.state.selection.ranges;
  for (const { from, to } of view.visibleRanges) {
    const text = view.state.doc.sliceString(from, to);
    const re = new RegExp(INLINE_BLOCK_RE.source, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) {
      const start = from + m.index;
      const end = start + m[0].length;
      // Let the user edit the raw block when the cursor is in or next to it.
      if (sel.some((r) => r.from <= end && r.to >= start)) continue;
      builder.add(start, end, Decoration.replace({ widget: new LockWidget(m[0], host) }));
    }
  }
  return builder.finish();
}

export function inlineEditorExtension(host: InlineHost) {
  return ViewPlugin.fromClass(
    class {
      decorations: DecorationSet;
      constructor(view: EditorView) {
        this.decorations = build(view, host);
      }
      update(u: ViewUpdate) {
        if (u.docChanged || u.viewportChanged || u.selectionSet || u.startState.field(editorLivePreviewField, false) !== u.state.field(editorLivePreviewField, false)) {
          this.decorations = build(u.view, host);
        }
      }
    },
    { decorations: (v) => v.decorations },
  );
}

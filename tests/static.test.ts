import { readFileSync, readdirSync, statSync } from 'node:fs';
import { builtinModules } from 'node:module';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { allKeys, currentLanguage, setLanguage, t, tIn } from '../src/i18n';
import { DEFAULT_SETTINGS, mergeSettings } from '../src/settings';

const SRC = path.resolve(__dirname, '../src');

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = path.join(dir, n);
    return statSync(p).isDirectory() ? sources(p) : p.endsWith('.ts') ? [p] : [];
  });
}

describe('runtime code constraints', () => {
  const files = sources(SRC).map((p) => ({ p, text: readFileSync(p, 'utf8') }));

  it('imports no Node built-ins and only allowed packages', () => {
    const allowed = new Set(['obsidian', 'hash-wasm', '@codemirror/state', '@codemirror/view']);
    const builtins = new Set(builtinModules.flatMap((m) => [m, `node:${m}`]));
    for (const { p, text } of files) {
      for (const m of text.matchAll(/from\s+"([^"]+)"/g)) {
        const spec = m[1];
        if (spec.startsWith('.')) continue;
        expect(builtins.has(spec), `${p} imports ${spec}`).toBe(false);
        expect(allowed.has(spec), `${p} imports ${spec}`).toBe(true);
      }
      expect(text, p).not.toMatch(/\brequire\(/);
    }
  });

  it('makes no network requests', () => {
    for (const { p, text } of files) {
      expect(text, p).not.toMatch(/\bfetch\(|XMLHttpRequest|WebSocket|requestUrl|navigator\.sendBeacon/);
    }
  });

  it('keeps the crypto core free of the obsidian module', () => {
    for (const { p, text } of files.filter((f) => f.p.includes(`${path.sep}crypto${path.sep}`))) {
      expect(text, p).not.toMatch(/from\s+"obsidian"/);
    }
  });

  it('declares only hash-wasm as a runtime dependency', () => {
    const pkg = JSON.parse(readFileSync(path.resolve(__dirname, '../package.json'), 'utf8'));
    expect(Object.keys(pkg.dependencies)).toEqual(['hash-wasm']);
  });
});

describe('i18n', () => {
  it('has the same keys and placeholders in English and Chinese', () => {
    expect(allKeys('zh').sort()).toEqual(allKeys('en').sort());
    for (const key of allKeys('en')) {
      const vars = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
      expect(vars(tIn('zh', key as any)), key).toEqual(vars(tIn('en', key as any)));
    }
  });

  it('follows the pinned language and fills placeholders', () => {
    setLanguage('zh');
    expect(t('password.tooShort', { n: 8 })).toBe('至少需要 8 个字符。');
    setLanguage('en');
    expect(t('password.tooShort', { n: 8 })).toBe('Use at least 8 characters.');
    setLanguage(null);
  });

  it('detects Obsidian\'s language: explicit setting first, then i18next, else English', () => {
    const g = globalThis as any;
    const saved = g.window;
    const lang = (stored: string | null, i18next?: string) => {
      g.window = { localStorage: { getItem: () => stored }, i18next: i18next ? { language: i18next } : undefined };
      return currentLanguage();
    };
    try {
      setLanguage(null);
      expect(lang('zh')).toBe('zh');
      expect(lang('zh-TW')).toBe('zh');
      expect(lang(null, 'zh')).toBe('zh'); // mobile app following the system language
      expect(lang('en', 'zh')).toBe('en'); // an explicit choice wins
      expect(lang(null, 'ja')).toBe('en');
      expect(lang(null)).toBe('en');
    } finally {
      g.window = saved;
    }
  });
});

describe('settings', () => {
  it('fills defaults and drops malformed rules', () => {
    const s = mergeSettings({ rules: [{ type: 'folder', path: 'A' }, { type: 'bogus', path: 'B' }, null], kdfAlgorithm: 'md5' });
    expect(s.rules).toEqual([{ type: 'folder', path: 'A' }]);
    expect(s.kdfAlgorithm).toBe('argon2id');
    expect(s.idleMinutes).toBe(DEFAULT_SETTINGS.idleMinutes);
    expect(s.hideNames).toBe(false);
    expect(mergeSettings(null).textExtensions).toEqual(['md', 'canvas', 'base']);
  });
});

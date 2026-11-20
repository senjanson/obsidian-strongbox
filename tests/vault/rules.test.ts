import { describe, expect, it } from 'vitest';
import { ProtectionPolicy, addRule, normPath, removeRule, renameInRules } from '../../src/vault/rules';

const policy = (rules: any[], excludes: string[] = []) =>
  new ProtectionPolicy({ configDir: '.obsidian', rules, excludes, textExtensions: ['md', 'canvas', 'base'] });

describe('protection rules', () => {
  it('normalizes paths', () => {
    expect(normPath('/a//b/')).toBe('a/b');
    expect(normPath('a\\b')).toBe('a/b');
    expect(normPath('./x')).toBe('x');
  });

  it('matches files, folders and the whole vault', () => {
    const p = policy([{ type: 'file', path: 'Notes/secret.md' }, { type: 'folder', path: 'Private' }]);
    expect(p.isProtected('Notes/secret.md')).toBe(true);
    expect(p.isProtected('Notes/secret.md.bak')).toBe(false);
    expect(p.isProtected('Notes/other.md')).toBe(false);
    expect(p.isProtected('Private/a.md')).toBe(true);
    expect(p.isProtected('Private/deep/b.png')).toBe(true);
    expect(p.isProtected('PrivateNot/a.md')).toBe(false);
    expect(policy([{ type: 'vault', path: '' }]).isProtected('anything/at/all.pdf')).toBe(true);
  });

  it('never protects the config folder, trash, dot folders, OS litter or user excludes', () => {
    const p = policy([{ type: 'vault', path: '' }], ['Public', 'Inbox/shared.md']);
    for (const path of [
      '.obsidian/plugins/strongbox/keyring.json', '.obsidian/app.json', '.trash/old.md', '.git/config',
      'notes/.hidden.md', 'Public/readme.md', 'Inbox/shared.md', 'a/.DS_Store',
      'Strongbox keyring backup 2026-11-20.json', 'Strongbox keyring backup 2026-11-20 (2).json',
      'Backups/strongbox-keyring-2026-11-20.json',
    ]) {
      expect(p.isExcluded(path), path).toBe(true);
      expect(p.isProtected(path), path).toBe(false);
    }
    expect(p.isProtected('Inbox/private.md')).toBe(true);
    expect(p.isProtected('Strongbox keyring backup notes.md')).toBe(true);
    expect(p.containsExcluded('')).toBe(true);
    expect(p.containsExcluded('Inbox')).toBe(true);
    expect(p.containsExcluded('Other')).toBe(false);
  });

  it('follows a renamed config folder', () => {
    const p = new ProtectionPolicy({ configDir: '.config-obs', rules: [{ type: 'vault', path: '' }], excludes: [], textExtensions: [] });
    expect(p.isExcluded('.config-obs/plugins/strongbox/keyring.json')).toBe(true);
  });

  it('reports the most specific rule and text paths', () => {
    const p = policy([{ type: 'vault', path: '' }, { type: 'folder', path: 'A' }, { type: 'file', path: 'A/x.md' }]);
    expect(p.ruleFor('A/x.md')).toEqual({ type: 'file', path: 'A/x.md' });
    expect(p.ruleFor('A/y.md')).toEqual({ type: 'folder', path: 'A' });
    expect(p.ruleFor('B/y.md')).toEqual({ type: 'vault', path: '' });
    expect(p.isTextPath('a/b.MD')).toBe(true);
    expect(p.isTextPath('a/b.canvas')).toBe(true);
    expect(p.isTextPath('a/b.png')).toBe(false);
    expect(p.isFolderProtected('A/sub')).toBe(true);
  });

  it('adds, removes and renames rules', () => {
    let rules = addRule([], { type: 'folder', path: 'A/' });
    rules = addRule(rules, { type: 'folder', path: 'A' });
    expect(rules).toEqual([{ type: 'folder', path: 'A' }]);
    rules = addRule(rules, { type: 'file', path: 'A/b/c.md' });
    rules = renameInRules(rules, 'A', 'Z');
    expect(rules).toEqual([{ type: 'folder', path: 'Z' }, { type: 'file', path: 'Z/b/c.md' }]);
    expect(removeRule(rules, { type: 'folder', path: 'Z' })).toEqual([{ type: 'file', path: 'Z/b/c.md' }]);
  });
});

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { CODES } from '$lib/api/errors';
import { resultMessage, type ActionError } from '$lib/api/configure';
import { LANGS, mergeLocales } from './index';

/**
 * Chaque code d'erreur que Rust peut rendre a sa clé fr/en/es dans chaque
 * espace de noms qui l'affiche, et aucun espace ne garde une clé d'erreur
 * que plus rien ne produit. Les codes sont lus dans les sources Rust
 * elles-mêmes (hors tests), pas recopiés ici.
 */

const root = new URL('../../../', import.meta.url);

/** Source Rust sans son module de tests. */
function rust(path: string): string {
  const s = readFileSync(new URL(path, root), 'utf8');
  const i = s.indexOf('#[cfg(test)]');
  return i < 0 ? s : s.slice(0, i);
}

/** Corps de `fn <name>` (jusqu'à l'accolade fermante en début de ligne). */
function fnBody(src: string, name: string): string {
  const start = src.indexOf(`fn ${name}`);
  expect(start, name).toBeGreaterThan(-1);
  return src.slice(start, src.indexOf('\n}\n', start));
}

/** Codes renvoyés en chaîne : `Err("x")`, `"x".to_string()`, `"x".into()`, `=> "x"`, `ok_or("x")`, `Code("x")`. */
function codesIn(src: string): string[] {
  const re = /(?:Err\(|ok_or\(|Code\(|=>\s*)"([a-z][a-z0-9_]*)"|"([a-z][a-z0-9_]*)"\s*\.\s*(?:to_string|into)\(\)/g;
  return [...new Set([...src.matchAll(re)].map((m) => m[1] ?? m[2]))].sort();
}

const snake = (s: string) => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();

/** Variantes d'un `enum` Rust, en snake_case (comme `rename_all`). */
function variants(src: string, name: string): string[] {
  const start = src.indexOf(`pub enum ${name}`);
  expect(start, name).toBeGreaterThan(-1);
  const body = src.slice(src.indexOf('{', start) + 1, src.indexOf('\n}\n', start));
  return [...body.matchAll(/^\s{4}([A-Z][A-Za-z0-9]*)/gm)].map((m) => snake(m[1]));
}

const accounts = rust('src-tauri/src/commands/accounts.rs');
const credentials = codesIn(fnBody(accounts, 'credentials_for'));
const lock = codesIn(fnBody(accounts, 'lock'));

/** Espace de noms → codes de commande qu'il affiche par `errorKey`. */
/** Codes que le front rejette lui-même avant d'appeler Rust (`Promise.reject('x')`). */
const front = [...readFileSync(new URL('src/lib/api/configure.ts', root), 'utf8').matchAll(/Promise\.reject\('([a-z_]+)'\)/g)].map((m) => m[1]);

const shown: Record<string, string[]> = {
  accounts: codesIn(accounts),
  network: codesIn(rust('src-tauri/src/commands/discovery.rs') + rust('src-tauri/src/commands/app.rs')),
  framing: [...new Set([...codesIn(rust('src-tauri/src/commands/stream.rs')), ...credentials, ...lock])].sort(),
  free: codesIn(rust('src-tauri/src/commands/free_ips.rs')),
  configure: [...new Set([...codesIn(rust('src-tauri/src/commands/configure.rs')), ...credentials, ...lock, ...front])].sort(),
};

const actions = rust('crates/lenscout-core/src/actions.rs');
const vapix = rust('crates/lenscout-core/src/vapix.rs');
const reasons = [...new Set([...vapix.matchAll(/(?:Invalid|reject)\("([a-z_]+)"\)/g)].map((m) => m[1]))].sort();

/** Les clés que `resultMessage` peut produire pour une `ActionError`. */
const actionKeys = variants(actions, 'ActionError').flatMap((code) => {
  const e = { code, ip: '192.0.2.1', detail: 'x', status: 500 } as unknown as ActionError;
  return code === 'invalid'
    ? reasons.map((reason) => resultMessage({ key: 'k', ok: false, error: { code, reason } as ActionError })!.key)
    : [resultMessage({ key: 'k', ok: false, error: e })!.key];
});

const batchCodes = variants(rust('crates/lenscout-core/src/batch.rs'), 'BatchError');

const locales = mergeLocales(import.meta.glob('./*/*.json', { eager: true }) as Record<string, { default: unknown }>);

function lookup(lang: string, key: string): unknown {
  return key.split('.').reduce<unknown>((v, k) => (v && typeof v === 'object' ? (v as Record<string, unknown>)[k] : undefined), locales[lang]);
}

const subkeys = (lang: string, key: string) => Object.keys((lookup(lang, key) as Record<string, unknown>) ?? {});

describe('codes d’erreur Rust ↔ clés i18n', () => {
  it('lit bien les sources (garde-fou du lecteur)', () => {
    expect(shown.accounts).toContain('keyring');
    expect(shown.network).toContain('local_network_denied');
    expect(shown.configure).toContain('preview_expired');
    expect(credentials).toEqual(['keyring', 'not_found', 'secret_missing']);
    expect(reasons).toContain('gateway_is_ip');
    expect(batchCodes).toContain('ip_in_use');
    expect(shown.free).toContain('ping_unavailable');
    expect(actionKeys).toContain('elevation.refused');
    expect(front).toEqual(['no_cameras', 'no_cameras']);
  });

  it('chaque code de commande est connu de errorKey', () => {
    const unknown = Object.entries(shown).flatMap(([ns, codes]) =>
      codes.filter((c) => !(CODES as readonly string[]).includes(c)).map((c) => `${ns}: ${c}`),
    );
    expect(unknown).toEqual([]);
  });

  it('chaque code de errorKey sort de Rust ou du front', () => {
    const all = new Set(Object.values(shown).flat());
    expect(CODES.filter((c) => !all.has(c))).toEqual([]);
  });

  it('chaque code a sa clé dans chaque langue, dans chaque espace qui l’affiche', () => {
    const missing: string[] = [];
    const need = (lang: string, key: string) => {
      if (typeof lookup(lang, key) !== 'string') missing.push(`${lang} ${key}`);
    };
    for (const lang of LANGS) {
      for (const [ns, codes] of Object.entries(shown)) for (const c of [...codes, 'unknown']) need(lang, `${ns}.error.${c}`);
      for (const key of actionKeys) need(lang, key);
      for (const c of batchCodes) need(lang, `batch.error.${c}`);
    }
    expect(missing).toEqual([]);
  });

  it('aucune clé d’erreur morte', () => {
    const dead: string[] = [];
    for (const lang of LANGS) {
      for (const [ns, codes] of Object.entries(shown)) {
        const live = new Set([...codes, 'unknown']);
        if (ns === 'configure') {
          for (const k of actionKeys) if (k.startsWith('configure.error.')) live.add(k.slice('configure.error.'.length));
        }
        for (const k of subkeys(lang, `${ns}.error`)) if (!live.has(k)) dead.push(`${lang} ${ns}.error.${k}`);
      }
      for (const k of subkeys(lang, 'configure.invalid')) if (!reasons.includes(k)) dead.push(`${lang} configure.invalid.${k}`);
      for (const k of subkeys(lang, 'batch.error')) if (!batchCodes.includes(k)) dead.push(`${lang} batch.error.${k}`);
    }
    expect(dead).toEqual([]);
  });
});

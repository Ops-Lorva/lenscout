import { describe, expect, it } from 'vitest';
import { LANGS, mergeLocales } from './index';

const modules = import.meta.glob('./*/*.json', { eager: true }) as Record<string, { default: unknown }>;

/** `{ a: { b: 1 } }` → `['a.b']`, triées. */
function keysOf(value: unknown, prefix = ''): string[] {
  if (value === null || typeof value !== 'object') return [prefix];
  return Object.entries(value as Record<string, unknown>)
    .flatMap(([k, v]) => keysOf(v, prefix ? `${prefix}.${k}` : k))
    .sort();
}

function files(lang: string): string[] {
  return Object.keys(modules)
    .filter((p) => p.startsWith(`./${lang}/`))
    .map((p) => p.slice(`./${lang}/`.length))
    .sort();
}

describe('parité des langues', () => {
  it('chaque fichier existe dans les trois langues', () => {
    expect(files('fr').length).toBeGreaterThan(0);
    expect(files('en')).toEqual(files('fr'));
    expect(files('es')).toEqual(files('fr'));
  });

  it('chaque fichier a les mêmes clés partout, récursivement', () => {
    for (const file of files('fr')) {
      const ref = keysOf(modules[`./fr/${file}`]?.default);
      for (const lang of ['en', 'es']) {
        expect(keysOf(modules[`./${lang}/${file}`]?.default), `${lang}/${file}`).toEqual(ref);
      }
    }
  });

  it('aucune valeur vide', () => {
    for (const [path, m] of Object.entries(modules)) {
      const walk = (v: unknown, at: string) => {
        if (typeof v === 'string') expect(v.trim(), `${path} ${at}`).not.toBe('');
        else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, `${at}.${k}`);
      };
      walk(m.default, '');
    }
  });
});

describe('mergeLocales', () => {
  it('range chaque fichier sous son nom, par langue', () => {
    const merged = mergeLocales({
      './fr/common.json': { default: { nav: { network: 'Réseau' } } },
      './fr/accounts.json': { default: { add: 'Ajouter' } },
      './en/common.json': { default: { nav: { network: 'Network' } } },
    });
    expect(merged.fr).toEqual({ common: { nav: { network: 'Réseau' } }, accounts: { add: 'Ajouter' } });
    expect(merged.en).toEqual({ common: { nav: { network: 'Network' } } });
  });

  it('expose les trois langues', () => {
    expect([...LANGS]).toEqual(['fr', 'en', 'es']);
  });
});

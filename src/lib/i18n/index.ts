// Repris de LanProbe src/lib/i18n/index.ts le 2026-11-13
import { addMessages, init, locale } from 'svelte-i18n';

export const LANGS = ['fr', 'en', 'es'] as const;
export type Lang = (typeof LANGS)[number];

const STORAGE_KEY = 'lenscout.lang';

type Modules = Record<string, { default: unknown }>;

/**
 * `./<lang>/<espace>.json` → `{ <lang>: { <espace>: contenu } }`. Un fichier
 * par espace de noms et par tâche : aucune tâche ne touche le fichier d'une
 * autre.
 */
export function mergeLocales(modules: Modules): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  for (const [path, mod] of Object.entries(modules)) {
    const m = /^\.\/([^/]+)\/([^/]+)\.json$/.exec(path);
    if (!m) continue;
    (out[m[1]] ??= {})[m[2]] = mod.default;
  }
  return out;
}

const merged = mergeLocales(import.meta.glob('./*/*.json', { eager: true }) as Modules);
for (const [lang, dict] of Object.entries(merged)) addMessages(lang, dict as Parameters<typeof addMessages>[1]);

export function storedLang(): Lang {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v && (LANGS as readonly string[]).includes(v)) return v as Lang;
  } catch {}
  return 'fr';
}

export function initI18n(preferred?: Lang) {
  init({
    fallbackLocale: 'en',
    initialLocale: preferred ?? storedLang(),
  });
}

export function setLang(lang: Lang) {
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {}
  locale.set(lang);
}

import { writable } from 'svelte/store';

export const THEMES = ['light', 'dark', 'system'] as const;
export type Theme = (typeof THEMES)[number];

/** Même clé que le script de `src/app.html`, qui pose le thème avant le premier rendu. */
export const THEME_KEY = 'lenscout.theme';

export function storedTheme(): Theme {
  try {
    const v = localStorage.getItem(THEME_KEY);
    if (v && (THEMES as readonly string[]).includes(v)) return v as Theme;
  } catch {}
  return 'system';
}

export const theme = writable<Theme>(storedTheme());

export function setTheme(t: Theme) {
  try {
    localStorage.setItem(THEME_KEY, t);
  } catch {}
  theme.set(t);
}

type Root = Pick<Element, 'setAttribute' | 'removeAttribute'>;

/** `system` : pas d'attribut, `prefers-color-scheme` décide (voir app.css). */
export function applyTheme(t: Theme, root: Root) {
  if (t === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', t);
}

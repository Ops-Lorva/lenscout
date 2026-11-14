import { get } from 'svelte/store';
import { afterEach, expect, test } from 'vitest';
import { applyTheme, setTheme, storedTheme, theme, THEME_KEY } from './settings';

// Les tests tournent sous node : pas de `localStorage`. On en pose un faux
// quand il en faut un, et on le retire après chaque test.
function fakeStorage(init: Record<string, string> = {}) {
  const data = new Map(Object.entries(init));
  const s = {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    data,
  };
  (globalThis as { localStorage?: unknown }).localStorage = s;
  return s;
}

afterEach(() => {
  delete (globalThis as { localStorage?: unknown }).localStorage;
  theme.set('system');
});

test('sans rien de mémorisé, le thème suit le système', () => {
  expect(storedTheme()).toBe('system');
  fakeStorage();
  expect(storedTheme()).toBe('system');
});

test('le thème mémorisé est relu, une valeur inconnue est ignorée', () => {
  fakeStorage({ [THEME_KEY]: 'dark' });
  expect(storedTheme()).toBe('dark');
  fakeStorage({ [THEME_KEY]: 'sepia' });
  expect(storedTheme()).toBe('system');
});

test('setTheme persiste et met le store à jour', () => {
  const s = fakeStorage();
  setTheme('light');
  expect(get(theme)).toBe('light');
  expect(s.data.get(THEME_KEY)).toBe('light');
});

test('un localStorage qui lève ne casse rien : défaut, et setTheme agit quand même', () => {
  (globalThis as { localStorage?: unknown }).localStorage = {
    getItem: () => { throw new Error('interdit'); },
    setItem: () => { throw new Error('interdit'); },
  };
  expect(storedTheme()).toBe('system');
  expect(() => setTheme('dark')).not.toThrow();
  expect(get(theme)).toBe('dark');
});

test('applyTheme pose data-theme sur la racine, « system » le retire', () => {
  const attrs = new Map<string, string>();
  const root = {
    setAttribute: (k: string, v: string) => void attrs.set(k, v),
    removeAttribute: (k: string) => void attrs.delete(k),
  };
  applyTheme('dark', root);
  expect(attrs.get('data-theme')).toBe('dark');
  applyTheme('light', root);
  expect(attrs.get('data-theme')).toBe('light');
  applyTheme('system', root);
  expect(attrs.has('data-theme')).toBe(false);
});

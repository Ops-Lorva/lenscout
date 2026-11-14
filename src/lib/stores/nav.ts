import { writable } from 'svelte/store';
import type { Camera } from '$lib/api/types';

export const PAGES = ['network', 'framing', 'accounts', 'settings'] as const;
export type Page = (typeof PAGES)[number];

/** `#comptes`-style deep link : `index.html#settings` ouvre l'onglet (captures, essais). */
export function initialPage(hash: string): Page {
  const h = hash.replace(/^#/, '');
  return (PAGES as readonly string[]).includes(h) ? (h as Page) : 'network';
}

export const page = writable<Page>(initialPage(typeof location === 'undefined' ? '' : location.hash));

/** Caméra à cadrer, posée par l'onglet Réseau avant de passer à Cadrage. */
export const framingTarget = writable<Camera | null>(null);

/**
 * Barre d'état en bas de la fenêtre : ce qui concerne le poste, pas une
 * caméra (recherche en cours, IP temporaire). `null` : pas de barre.
 */
export interface Status {
  text: string;
  tone?: 'ok' | 'warn';
}
export const status = writable<Status | null>(null);

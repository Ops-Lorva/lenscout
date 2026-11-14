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
  /** Complément en texte courant après le message (en gras) : où, quoi. */
  detail?: string;
}
export const status = writable<Status | null>(null);

/** Retire `own` de la barre s'il y est encore ; le message d'un autre écran reste. */
export const clearStatusIf = (own: Status | null) => status.update((s) => (own !== null && s === own ? null : s));

/**
 * Onglets gardés montés : ce qu'un écran fait de son flux quand il passe
 * caché (`visible` faux) ou revient. `playing` : flux en cours ;
 * `suspended` : coupé par le passage en arrière-plan, à reprendre.
 */
export function suspendStep(visible: boolean, playing: boolean, suspended: boolean): 'suspend' | 'resume' | 'none' {
  if (!visible && playing) return 'suspend';
  if (visible && suspended && !playing) return 'resume';
  return 'none';
}

import { writable } from 'svelte/store';
import type { Camera } from '#lib/api/types.ts';
import type { OpKind } from '#lib/api/ops.ts';

export const PAGES = ['network', 'framing', 'accounts', 'operations', 'settings'] as const;
export type Page = (typeof PAGES)[number];

/** `#comptes`-style deep link : `index.html#settings` ouvre l'onglet (captures, essais). */
export function initialPage(hash: string): Page {
  const h = hash.replace(/^#/, '');
  return (PAGES as readonly string[]).includes(h) ? (h as Page) : 'network';
}

export const page = writable<Page>(initialPage(typeof location === 'undefined' ? '' : location.hash));

/** Caméra à cadrer, posée par l'onglet Réseau avant de passer à Cadrage. */
export const framingTarget = writable<Camera | null>(null);

/** Opération demandée par un raccourci de Réseau ; l'onglet Opérations la reprend puis la vide. */
export const opsRequest = writable<OpKind | null>(null);

/** Raccourci de Réseau (« IP en lot ») : Opérations, sur cette opération, avec la sélection courante. */
export function openOperations(kind: OpKind): void {
  opsRequest.set(kind);
  page.set('operations');
}

/** Interface du scan de Réseau : Opérations écrit par elle, comme la barre d'actions. */
export const scanIface = writable('');

/** Adresses changées depuis Opérations : Réseau rescanne comme après une IP (compteur). */
export const ipsChanged = writable(0);

/**
 * Barre d'état en bas de la fenêtre : ce qui concerne le poste, pas une
 * caméra (recherche en cours, IP temporaire). `null` : pas de barre.
 */
/** Message traduit au rendu, pas à la création : il suit un changement de langue. */
export interface Msg {
  key: string;
  values?: Record<string, string | number>;
}

export interface Status {
  text: Msg;
  tone?: 'ok' | 'warn';
  /** Complément en texte courant après le message (en gras) : où, quoi. */
  detail?: Msg;
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

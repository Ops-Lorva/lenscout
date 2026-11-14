import { derived, writable, type Readable } from 'svelte/store';
import type { Camera } from '#lib/api/types.ts';
import { filterCameras } from '#lib/search.ts';

/** Clé d'une caméra : son MAC, sinon son IP (une caméra garde son MAC si elle change d'IP). */
export const cameraKey = (c: Camera): string => c.mac ?? c.ip;

const ipValue = (ip: string): number =>
  ip.split('.').reduce((acc, part) => acc * 256 + (Number(part) || 0), 0);

const byKey = writable<Map<string, Camera>>(new Map());

/**
 * Adressage posé par LenScout (IP fixe, DHCP), par clé de caméra : le scan
 * ne le dit pas, et sans compte retenu (ou à travers le routeur) rien ne le
 * relit ; la ligne le garde donc d'un rescan à l'autre, jusqu'à ce qu'une
 * lecture avec le compte dise autre chose.
 */
const posed = new Map<string, NonNullable<Camera['addressing']>>();

/** Triée par IP numérique croissante : 10.0.50.9 avant 10.0.50.10. */
export const cameras: Readable<Camera[]> = derived(byKey, (m) =>
  [...m.values()].sort((a, b) => ipValue(a.ip) - ipValue(b.ip)),
);

export const selection = writable<Set<string>>(new Set());

/** Texte du champ de recherche : ce qu'il masque n'est plus sélectionné. */
export const query = writable('');

/** La liste affichée : filtrée par la recherche. */
export const visibleCameras: Readable<Camera[]> = derived([cameras, query], ([list, q]) =>
  filterCameras(list, q),
);

/**
 * Sélection ∩ liste affichée, dans l'ordre affiché : une action en lot ne
 * touche jamais une caméra que la recherche masque.
 */
export const selectedCameras: Readable<Camera[]> = derived([visibleCameras, selection], ([list, sel]) =>
  list.filter((c) => sel.has(cameraKey(c))),
);

/** Au retour sur la page : on ne rescanne (ni ne vide) que s'il n'y a rien à montrer. */
export const shouldAutoScan = (list: Camera[]): boolean => list.length === 0;

export function upsert(c: Camera): void {
  byKey.update((m) => {
    const next = new Map(m);
    // Vue d'abord par IP seule, puis avec son MAC : l'ancienne ligne fusionne
    // et sa case cochée suit la nouvelle clé.
    if (c.mac && next.delete(c.ip)) {
      selection.update((sel) => {
        if (!sel.delete(c.ip)) return sel;
        return new Set(sel).add(c.mac!);
      });
    }
    const known = c.addressing ?? posed.get(cameraKey(c));
    next.set(cameraKey(c), known ? { ...c, addressing: known } : c);
    return next;
  });
}

/** Adressage lu après le scan, posé sur la caméra de cette adresse ; les autres ne bougent pas. */
export function setAddressing(read: { ip: string; addressing: Camera['addressing'] }[]): void {
  if (read.length === 0) return;
  byKey.update((m) => {
    const next = new Map(m);
    for (const [k, c] of next) {
      const r = read.find((x) => x.ip === c.ip);
      if (r) {
        next.set(k, { ...c, addressing: r.addressing });
        posed.delete(k);
      }
    }
    return next;
  });
}

/**
 * Activation réussie : la ligne de chaque résultat `ok` (clé MAC, sinon IP)
 * passe tout de suite en « Activée », sans attendre un rescan. Un échec ne
 * change rien.
 */
export function markActivated(results: readonly { key: string; ok: boolean; error?: unknown }[]): void {
  const done = results.filter((r) => r.ok).map((r) => r.key);
  if (done.length === 0) return;
  byKey.update((m) => {
    const next = new Map(m);
    for (const k of done) {
      const c = next.get(k);
      if (c) next.set(k, { ...c, activation: 'activated' });
    }
    return next;
  });
}

/**
 * Changement d'adresse réussi : la ligne de chaque résultat `ok` prend
 * `addressing` sans attendre une lecture, comme `markActivated`. `moved` :
 * nouvelle IP par clé ; une caméra sans MAC (clé = IP) la retrouve au rescan
 * sous sa nouvelle adresse.
 */
export function markAddressing(
  results: readonly { key: string; ok: boolean; error?: unknown }[],
  addressing: NonNullable<Camera['addressing']>,
  moved: Record<string, string> = {},
): void {
  const done = results.filter((r) => r.ok).map((r) => r.key);
  if (done.length === 0) return;
  byKey.update((m) => {
    const next = new Map(m);
    for (const k of done) {
      const c = next.get(k);
      if (c) next.set(k, { ...c, addressing });
      posed.set(c?.mac ?? moved[k] ?? k, addressing);
    }
    return next;
  });
}

export function clear(): void {
  byKey.set(new Map());
  selection.set(new Set());
}

/** Rescan différé : les caméras sont remplacées, la sélection (clés MAC) reste ; `selectedCameras` écarte seule les clés disparues. */
export function clearCameras(): void {
  byKey.set(new Map());
}

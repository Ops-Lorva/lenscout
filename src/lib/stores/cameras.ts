import { derived, writable, type Readable } from 'svelte/store';
import type { Addressing, Camera } from '#lib/api/types.ts';
import { filterCameras } from '#lib/search.ts';
import { cameraBrand, cameraName, shownMac } from '#lib/api/discovery.ts';

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

/** Onglet d'état : toutes, seulement les neuves, ou seulement les activées. */
export type CameraFilter = 'all' | 'new' | 'activated';
export const filter = writable<CameraFilter>('all');

/** Colonnes de données triables du tableau Réseau. */
export type SortColumn = 'camera' | 'brand' | 'ip' | 'mac' | 'serial' | 'firmware' | 'addressing' | 'state';
export type SortDir = 'asc' | 'desc';
export interface Sort {
  col: SortColumn;
  dir: SortDir;
}

/** Tri du tableau : IP croissante par défaut (ordre historique). */
export const sort = writable<Sort>({ col: 'ip', dir: 'asc' });

/** Clic sur un en-tête : trie par cette colonne (asc), re-clic inverse le sens. */
export function toggleSort(col: SortColumn): void {
  sort.update((s) => (s.col === col ? { col, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { col, dir: 'asc' }));
}

/**
 * Adressage affiché pour le tri (miroir de `addressingKey` sans le préfixe
 * i18n) : la valeur lue, sinon DHCP pour une Axis neuve, sinon rien.
 */
const addressingValue = (c: Camera): Addressing | null =>
  c.addressing ?? (c.family === 'axis' && c.activation === 'new' ? 'dhcp' : null);

/**
 * Valeur comparable d'une caméra pour une colonne : nombre pour l'IP (ordre
 * numérique via `ipValue`), chaîne sinon. `null` = valeur absente, rangée en
 * fin de liste quel que soit le sens.
 */
function sortValue(c: Camera, col: SortColumn): number | string | null {
  switch (col) {
    case 'ip':
      return ipValue(c.ip);
    case 'camera':
      return c.brand || c.model ? cameraName(c) : null;
    case 'brand':
      return cameraBrand(c);
    case 'mac':
      return shownMac(c).mac;
    case 'serial':
      return c.serial || null;
    case 'firmware':
      return c.firmware || null;
    case 'addressing':
      return addressingValue(c);
    case 'state':
      return c.activation === 'unknown' ? null : c.activation;
  }
}

/**
 * Tri stable : valeurs absentes toujours en fin, comparaison numérique ou
 * textuelle selon la colonne, puis départage par IP numérique croissante pour
 * un ordre déterministe.
 */
export function sortCameras(list: Camera[], s: Sort): Camera[] {
  const dir = s.dir === 'asc' ? 1 : -1;
  return [...list].sort((a, b) => {
    const va = sortValue(a, s.col);
    const vb = sortValue(b, s.col);
    if (va === null || vb === null) {
      if (va === vb) return ipValue(a.ip) - ipValue(b.ip);
      return va === null ? 1 : -1;
    }
    const cmp = typeof va === 'number' && typeof vb === 'number' ? va - vb : String(va).localeCompare(String(vb));
    return cmp !== 0 ? cmp * dir : ipValue(a.ip) - ipValue(b.ip);
  });
}

/** Compteurs des onglets, sur toute la liste (indépendants de la recherche). */
export const cameraCounts: Readable<{ all: number; new: number; activated: number }> = derived(
  cameras,
  (list) => ({
    all: list.length,
    new: list.filter((c) => c.activation === 'new').length,
    activated: list.filter((c) => c.activation === 'activated').length,
  }),
);

/** La liste affichée : filtrée par l'onglet d'état, par la recherche, puis triée. */
export const visibleCameras: Readable<Camera[]> = derived(
  [cameras, query, filter, sort],
  ([list, q, f, s]) =>
    sortCameras(
      filterCameras(
        f === 'all' ? list : list.filter((c) => c.activation === f),
        q,
      ),
      s,
    ),
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

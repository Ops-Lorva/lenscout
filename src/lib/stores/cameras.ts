import { derived, writable, type Readable } from 'svelte/store';
import type { Camera } from '$lib/api/types';

/** Clé d'une caméra : son MAC, sinon son IP (une caméra garde son MAC si elle change d'IP). */
export const cameraKey = (c: Camera): string => c.mac ?? c.ip;

const ipValue = (ip: string): number =>
  ip.split('.').reduce((acc, part) => acc * 256 + (Number(part) || 0), 0);

const byKey = writable<Map<string, Camera>>(new Map());

/** Triée par IP numérique croissante : 10.0.50.9 avant 10.0.50.10. */
export const cameras: Readable<Camera[]> = derived(byKey, (m) =>
  [...m.values()].sort((a, b) => ipValue(a.ip) - ipValue(b.ip)),
);

export const selection = writable<Set<string>>(new Set());

/** Dans l'ordre affiché, pas dans l'ordre des clics. */
export const selectedCameras: Readable<Camera[]> = derived([cameras, selection], ([list, sel]) =>
  list.filter((c) => sel.has(cameraKey(c))),
);

export function upsert(c: Camera): void {
  byKey.update((m) => {
    const next = new Map(m);
    // Vue d'abord par IP seule, puis avec son MAC : l'ancienne ligne fusionne.
    if (c.mac) next.delete(c.ip);
    next.set(cameraKey(c), c);
    return next;
  });
}

export function clear(): void {
  byKey.set(new Map());
  selection.set(new Set());
}

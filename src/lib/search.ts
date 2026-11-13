import type { Camera } from './api/types';

/** Retire `: - .` et les espaces, met en majuscules. */
export function normalizeQuery(q: string): string {
  return q.replace(/[:\-.\s]/g, '').toUpperCase();
}

export function matchesCamera(c: Camera, q: string): boolean {
  const clean = normalizeQuery(q);
  if (clean === '') return true;
  if (c.mac && normalizeQuery(c.mac).includes(clean)) return true;
  if (c.serial && normalizeQuery(c.serial).includes(clean)) return true;
  // IP et modèle : requête brute (les points d'une IP comptent).
  const raw = q.trim().toLowerCase();
  return c.ip.toLowerCase().includes(raw) || (c.model?.toLowerCase().includes(raw) ?? false);
}

/** Conserve l'ordre de la liste. */
export function filterCameras(list: Camera[], q: string): Camera[] {
  return list.filter((c) => matchesCamera(c, q));
}

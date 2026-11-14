import { invoke } from '@tauri-apps/api/core';
import type { View } from './stream';
import type { Camera } from './types';

/** Miroir de `FocusWindow` (imaging.rs) : coordonnées normalisées 0 à 1, origine en haut à gauche. */
export interface FocusWindow {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** Miroir de `Optics` (imaging.rs). */
export interface Optics {
  id: string;
  focus: number | null;
  magnification: number | null;
  moving: boolean;
  window: FocusWindow | null;
  can_focus: boolean;
  can_zoom: boolean;
  max_magnification: number | null;
}

export interface Rotation {
  current: number;
  allowed: number[];
}

/** Miroir de `ImageSettings` (imaging.rs) : ce qui manque est `null`. */
export interface ImageSettings {
  sensor: number | null;
  optics: Optics | null;
  rotation: Rotation | null;
  bdc: boolean | null;
}

export type OpticsCommand =
  | { kind: 'zoom'; magnification: number }
  | { kind: 'focus'; position: number }
  | { kind: 'autofocus' }
  | { kind: 'focus_window'; window: FocusWindow }
  | { kind: 'reset_focus' };

/** Vue groupée (plusieurs capteurs, `Source=1,0`) : ni optique, ni BDC. */
export const isGroupView = (v: View | null): boolean => !!v?.source?.includes(',');

export const showOptics = (s: ImageSettings | null): boolean => !!s?.optics && (s.optics.can_zoom || s.optics.can_focus);
export const showRotation = (s: ImageSettings | null): boolean => (s?.rotation?.allowed.length ?? 0) > 1;
export const showBdc = (s: ImageSettings | null): boolean => s?.bdc != null;
export const hasPanel = (s: ImageSettings | null): boolean => showOptics(s) || showRotation(s) || showBdc(s);

/** Bornes du curseur de zoom : de 1 (grand angle) au maximum annoncé par la caméra (télé). */
export function zoomRange(o: Optics): { min: number; max: number } | null {
  return o.can_zoom && o.max_magnification ? { min: 1, max: o.max_magnification } : null;
}

/** Plus petit côté d'une zone d'autofocus, en fraction de l'image : un clic n'est pas une zone. */
const MIN_SIDE = 0.02;

/**
 * Rectangle tracé à la souris (`a` → `b`, coordonnées de la page) dans la
 * boîte de l'image → zone normalisée, bornée à l'image ; `null` si trop petite.
 */
export function normRect(
  a: { x: number; y: number },
  b: { x: number; y: number },
  box: { left: number; top: number; width: number; height: number },
): FocusWindow | null {
  if (box.width <= 0 || box.height <= 0) return null;
  const clamp = (v: number) => Math.min(1, Math.max(0, v));
  const [x0, x1] = [clamp((a.x - box.left) / box.width), clamp((b.x - box.left) / box.width)].sort((p, q) => p - q);
  const [y0, y1] = [clamp((a.y - box.top) / box.height), clamp((b.y - box.top) / box.height)].sort((p, q) => p - q);
  if (x1 - x0 < MIN_SIDE || y1 - y0 < MIN_SIDE) return null;
  return { x: x0, y: y0, width: x1 - x0, height: y1 - y0 };
}

/**
 * Bascule de la BDC : l'état relu par Rust après l'écriture ; en erreur,
 * l'interrupteur revient à la dernière valeur lue (`prev`).
 */
export async function toggleBdc(prev: boolean, wanted: boolean, set: (on: boolean) => Promise<boolean | null>): Promise<{ on: boolean | null; error: unknown }> {
  try {
    return { on: await set(wanted), error: null };
  } catch (e) {
    return { on: prev, error: e };
  }
}

const viewArg = (view: View | null) => view?.n ?? null;

/** Réglages de la vue choisie, lus par Rust avec le compte ; rien pour une autre marque. */
export const readSettings = (camera: Camera, accountId: string, view: View | null): Promise<ImageSettings | null> =>
  camera.family === 'axis' && accountId
    ? invoke<ImageSettings>('cmd_image_settings', { camera, accountId, view: viewArg(view) })
    : Promise.resolve(null);

/** Une commande d'optique ; rend l'état relu à la fin du mouvement. */
export const sendOptics = (camera: Camera, accountId: string, view: View | null, command: OpticsCommand) =>
  invoke<Optics | null>('cmd_optics', { camera, accountId, view: viewArg(view), command });

export const setRotation = (camera: Camera, accountId: string, view: View | null, degrees: number) =>
  invoke<void>('cmd_set_rotation', { camera, accountId, view: viewArg(view), degrees });

export const setBdc = (camera: Camera, accountId: string, view: View | null, on: boolean) =>
  invoke<boolean | null>('cmd_set_bdc', { camera, accountId, view: viewArg(view), on });

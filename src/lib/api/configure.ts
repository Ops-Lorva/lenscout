import { invoke } from '@tauri-apps/api/core';
import { writable } from 'svelte/store';
import type { Camera, Family } from './types';
import { cameraKey } from '$lib/stores/cameras';

/** Miroir de `ActionError` (actions.rs). `rejected.detail` vient de la caméra. */
export type ActionError =
  | { code: 'unsupported' }
  | { code: 'identity_mismatch' }
  | { code: 'identity_unreadable' }
  | { code: 'camera_off_subnet' }
  | { code: 'already_activated' }
  | { code: 'network_needs_one_camera' }
  | { code: 'unreachable'; ip: string }
  | { code: 'auth_failed' }
  | { code: 'rejected'; detail: string }
  | { code: 'elevation_refused'; ip: string };

/** Miroir de `ActionResult` ; `key` = MAC de la caméra, sinon son IP (comme `cameraKey`). */
export interface ActionResult {
  key: string;
  ok: boolean;
  error: ActionError | null;
}

/** Miroir de `ActionDto` (src-tauri/src/commands/configure.rs). */
export type ActionDto =
  | { kind: 'activate' }
  | { kind: 'network_dhcp' }
  | { kind: 'network_static'; ip: string; mask: string; gateway: string | null; dns: string[] }
  | { kind: 'time'; ntp_servers: string[]; timezone: string };

/**
 * Marques sur lesquelles une action existe. Hikvision s'ajoute ici avec la
 * tâche 14 ; le cœur refuse de toute façon ce qu'il ne sait pas faire.
 */
const ACTIONABLE: readonly Family[] = ['axis'];

/** Boutons actifs : une sélection non vide, sans aucune caméra d'une marque sans action. */
export const canAct = (cams: Camera[]): boolean =>
  cams.length > 0 && cams.every((c) => ACTIONABLE.includes(c.family));

/** Activer ne sert à rien si toutes les caméras visées le sont déjà. */
export const canActivate = (cams: Camera[]): boolean =>
  canAct(cams) && !cams.every((c) => c.activation === 'activated');

const ipNum = (ip: string): number | null => {
  const p = ip.trim().split('.');
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255)) return null;
  return p.reduce((acc, x) => acc * 256 + Number(x), 0);
};

/**
 * `ip` hors du sous-réseau du poste (adresse + masque de l'interface) ? Un
 * champ incomplet ou des détails absents ne déclenchent rien : c'est un
 * avertissement, Rust fait foi.
 */
export function outsideSubnet(ip: string, ifaceIp: string | null, mask: string | null): boolean {
  const a = ipNum(ip);
  const b = ifaceIp ? ipNum(ifaceIp) : null;
  const m = mask ? ipNum(mask) : null;
  if (a === null || b === null || m === null) return false;
  return ((a & m) >>> 0) !== ((b & m) >>> 0);
}

/** Le changement d'IP vise une seule caméra (le lot a son plan d'adresses). */
export const canChangeIp = (cams: Camera[]): boolean => cams.length === 1 && canAct(cams);

/** Résultats de la dernière action, par clé de caméra : la pastille de chaque ligne. */
export const actionResults = writable<Map<string, ActionResult>>(new Map());

export const setResults = (list: ActionResult[]) =>
  actionResults.set(new Map(list.map((r) => [r.key, r])));

export const clearResults = () => actionResults.set(new Map());

/** Les clés de ligne du front et du cœur coïncident : MAC sinon IP. */
export const resultFor = (m: Map<string, ActionResult>, c: Camera): ActionResult | undefined =>
  m.get(cameraKey(c));

/**
 * Message d'une ligne : clé i18n (sous `configure.`) et, pour un refus de la
 * caméra, son texte brut en paramètre.
 */
export function resultMessage(r: ActionResult): { key: string; detail?: string } | null {
  if (r.ok || !r.error) return null;
  if (r.error.code === 'rejected') return { key: 'error.rejected', detail: r.error.detail };
  return { key: `error.${r.error.code}` };
}

/** Fuseaux IANA proposés par le moteur du webview ; `UTC` seul s'il ne sait pas les lister. */
export function timeZones(): string[] {
  try {
    const list = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.('timeZone');
    if (list && list.length > 0) return list.includes('UTC') ? list : ['UTC', ...list];
  } catch {}
  return ['UTC'];
}

/** Fuseau du poste s'il figure dans la liste, sinon le premier. */
export function defaultTimeZone(zones: string[]): string {
  try {
    const own = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (own && zones.includes(own)) return own;
  } catch {}
  return zones[0] ?? 'UTC';
}

/** `''` → `null` ; sert la passerelle facultative. */
export const orNull = (s: string): string | null => (s.trim() === '' ? null : s.trim());

/** Lignes d'un champ libre (virgules, espaces ou retours à la ligne) → liste sans vide. */
export const splitList = (s: string): string[] => s.split(/[\s,;]+/).filter((x) => x !== '');

/** Dialogue ouvert après un changement de sélection : une sélection vide le ferme. */
export const dialogAfterSelection = <T extends string>(open: T | null, cams: Camera[]): T | null =>
  cams.length === 0 ? null : open;

/** Une liste vide ne part jamais vers Rust. */
export const applyAction = (cameras: Camera[], accountId: string, action: ActionDto, iface: string) =>
  cameras.length === 0
    ? Promise.reject('no_cameras')
    : invoke<ActionResult[]>('cmd_apply_action', { cameras, accountId, action, iface });

import { invoke } from '@tauri-apps/api/core';
import { writable } from 'svelte/store';
import type { Camera, Family } from './types';
import { cameraKey } from '#lib/stores/cameras.ts';
import { errorKey } from './errors';

/** Miroir de `ActionError` (actions.rs). `rejected.detail` vient de la caméra ; `invalid.reason` est un code. */
export type ActionError =
  | { code: 'unsupported' }
  | { code: 'identity_mismatch' }
  | { code: 'identity_unreadable' }
  | { code: 'camera_off_subnet' }
  | { code: 'camera_not_seen' }
  | { code: 'already_activated' }
  | { code: 'network_needs_one_camera' }
  | { code: 'unreachable'; ip: string }
  | { code: 'auth_failed' }
  | { code: 'rejected'; detail: string }
  | { code: 'invalid'; reason: string }
  | { code: 'http_status'; status: number }
  | { code: 'auth_insecure' }
  | { code: 'bad_reply' }
  | { code: 'elevation_refused'; ip: string }
  | { code: 'temp_ip_failed' }
  | { code: 'temp_ip_left'; ip: string }
  | { code: 'temp_ip_busy' }
  | { code: 'account_network_active' }
  | { code: 'activation_cleartext' }
  | { code: 'not_new' }
  | { code: 'mac_not_axis' };

/** Miroir de `ActionResult` ; `key` = MAC de la caméra, sinon son IP (comme `cameraKey`). */
export interface ActionResult {
  key: string;
  ok: boolean;
  error: ActionError | null;
}

/** Miroir de `ActionDto` (src-tauri/src/commands/configure.rs). */
export type ActionDto =
  | { kind: 'activate'; allow_cleartext?: boolean }
  | { kind: 'network_dhcp' }
  | { kind: 'network_static'; ip: string; mask: string; gateway: string | null; dns: string[] }
  | { kind: 'time'; ntp_servers: string[]; timezone: string };

/**
 * Marques sur lesquelles une action existe. Hikvision n'y est PAS : l'heure
 * est sans objet en v1 et l'encodage du mot de passe SADP n'a pas de source
 * publique (voir `discovery/sadp.rs`), donc Activer / IP restent grisés. Le
 * cœur refuse de toute façon ce qu'il ne sait pas faire.
 */
const ACTIONABLE: readonly Family[] = ['axis'];

/** Boutons actifs : une sélection non vide, sans aucune caméra d'une marque sans action. */
export const canAct = (cams: Camera[]): boolean =>
  cams.length > 0 && cams.every((c) => ACTIONABLE.includes(c.family));

/** Activer : au moins une caméra lue neuve au scan (Rust refuse les autres : `not_new`). */
export const canActivate = (cams: Camera[]): boolean =>
  canAct(cams) && cams.some((c) => c.activation === 'new');

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

/** Ajoute ou remplace les pastilles reçues, sans toucher aux autres lignes. */
export const mergeResults = (list: ActionResult[]) =>
  actionResults.update((m) => new Map([...m, ...list.map((r) => [r.key, r] as const)]));

/** Caméras dont l'activation attend une confirmation d'envoi en clair (https injoignable). */
export const cleartextPending = (results: ActionResult[], cams: Camera[]): Camera[] =>
  cams.filter((c) => results.some((r) => r.key === cameraKey(c) && r.error?.code === 'activation_cleartext'));

/** Les clés de ligne du front et du cœur coïncident : MAC sinon IP. */
export const resultFor = (m: Map<string, ActionResult>, c: Camera): ActionResult | undefined =>
  m.get(cameraKey(c));

/**
 * Message d'une ligne : clé i18n complète et ses valeurs (texte brut d'un
 * refus de la caméra, adresse d'une erreur d'IP temporaire).
 */
export function resultMessage(r: ActionResult): { key: string; values: Record<string, string> } | null {
  if (r.ok || !r.error) return null;
  switch (r.error.code) {
    case 'rejected':
      return { key: 'configure.error.rejected', values: { detail: r.error.detail } };
    case 'invalid':
      return { key: `configure.invalid.${r.error.reason}`, values: {} };
    case 'http_status':
      return { key: 'configure.error.http_status', values: { status: String(r.error.status) } };
    case 'elevation_refused':
      return { key: 'elevation.refused', values: { ip: r.error.ip } };
    case 'temp_ip_failed':
      return { key: 'elevation.failed', values: {} };
    case 'temp_ip_left':
      return { key: 'elevation.left', values: { ip: r.error.ip } };
    case 'temp_ip_busy':
      return { key: 'elevation.busy', values: {} };
    default:
      return { key: `configure.error.${r.error.code}`, values: {} };
  }
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

/**
 * Envoi du mot de passe en http clair confirmé par le technicien pour CETTE
 * caméra : jamais pour une liste (Rust refuse aussi plus d'une caméra).
 */
export const activateCleartext = (camera: Camera, accountId: string, iface: string) =>
  applyAction([camera], accountId, { kind: 'activate', allow_cleartext: true }, iface);

/** Le lot vise au moins deux caméras d'une marque configurable (une seule : « IP »). */
export const canBatchIp = (cams: Camera[]): boolean => cams.length > 1 && canAct(cams);

/** Miroir de `BatchError` (batch.rs). */
export type BatchError =
  | { code: 'no_selection' }
  | { code: 'missing_mac'; ip: string }
  | { code: 'unsupported'; ip: string }
  | { code: 'invalid_mask' }
  | { code: 'range_overflow' }
  | { code: 'network_or_broadcast'; ip: string }
  | { code: 'gateway_in_range'; ip: string }
  | { code: 'gateway_out_of_subnet'; ip: string }
  | { code: 'too_many_dns' }
  | { code: 'ip_in_use'; ip: string; mac: string | null };

/** Miroir de `Assignment`. */
export interface Assignment {
  mac: string;
  serial: string | null;
  family: Family;
  current_ip: string;
  new_ip: string;
}

export interface BatchPreview {
  id: string;
  rows: Assignment[];
}

export interface BatchRequest {
  start: string;
  mask: string;
  gateway: string | null;
  dns: string[];
}

/** Aperçu calculé et gardé par Rust ; rien n'est envoyé aux caméras. */
export const batchPreview = (selection: Camera[], others: Camera[], req: BatchRequest, iface: string) =>
  selection.length === 0
    ? Promise.reject('no_cameras')
    : invoke<BatchPreview>('cmd_batch_preview', { selection, others, req, iface });

/** Applique l'aperçu gardé par Rust sous `previewId` (usage unique). */
export const batchApply = (previewId: string, accountId: string, iface: string) =>
  invoke<ActionResult[]>('cmd_batch_apply', { previewId, accountId, iface });

/** La sélection (ordre compris), l'interface ou un champ qui changent : l'aperçu n'est plus celui de l'écran. */
export const batchFingerprint = (
  cams: Camera[],
  f: { iface: string; start: string; mask: string; gateway: string; dns: string },
): string =>
  JSON.stringify([f.iface, cams.map(cameraKey), f.start.trim(), f.mask.trim(), f.gateway.trim(), splitList(f.dns)]);

/**
 * Message d'une ligne pour l'erreur d'un aperçu : `BatchError` (objet à code)
 * ou code de commande (chaîne). Clé i18n complète et ses valeurs.
 */
export function batchErrorMessage(e: unknown): { key: string; values: Record<string, string> } {
  if (e && typeof e === 'object' && 'code' in e && typeof (e as { code: unknown }).code === 'string') {
    const b = e as { code: string; ip?: string };
    return { key: `batch.error.${b.code}`, values: b.ip ? { ip: b.ip } : {} };
  }
  return { key: `configure.${errorKey(e)}`, values: {} };
}

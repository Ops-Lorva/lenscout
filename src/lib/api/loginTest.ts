import { Channel, invoke } from '@tauri-apps/api/core';
import { matchesCamera } from '../search';
import { cameraName, shownMac } from './discovery';
import type { Camera } from './types';

/** Miroir de `LoginOutcome` (login_test.rs), dans l'ordre des pastilles. */
export const LOGIN_CODES = ['ok', 'denied', 'unreachable', 'not_activated', 'unsupported', 'other_device', 'held'] as const;
export type LoginCode = (typeof LOGIN_CODES)[number];

/** Miroir de `LoginResult` : `index` = place de la caméra dans la sélection envoyée. */
export interface LoginResult {
  index: number;
  key: string;
  ip: string;
  code: LoginCode;
}

/** Miroir de `LoginEvent` (commands/login_test.rs). */
export type LoginEvent = ({ kind: 'result' } & LoginResult) | { kind: 'done'; cancelled: boolean };

// Numéro d'un passage : l'horloge d'abord, puis un compteur (comme freeIps.ts).
let counter = 0;
export const nextLoginRun = () => Date.now() * 1000 + (counter++ % 1000);

/**
 * Lance le test sur `cameras` avec le compte `accountId`. Rend la main à la
 * fin du passage ; rejette avec un code stable (`no_cameras`, `secret_missing`…).
 */
export function startLoginTest(id: number, cameras: Camera[], accountId: string, iface: string, onEvent: (e: LoginEvent) => void): Promise<void> {
  const channel = new Channel<LoginEvent>();
  channel.onmessage = onEvent;
  return invoke<void>('cmd_login_test', { id, cameras, accountId, iface, channel });
}

export const cancelLoginTest = (id: number) => invoke<void>('cmd_login_test_cancel', { id });

/** Nombre de lignes par résultat ; un résultat absent n'a pas de clé. */
export function loginCounts(rows: LoginResult[]): Partial<Record<LoginCode, number>> {
  const out: Partial<Record<LoginCode, number>> = {};
  for (const r of rows) out[r.code] = (out[r.code] ?? 0) + 1;
  return out;
}

/** Lignes des résultats cochés (aucun coché : tous) dont la caméra répond à la recherche (IP, MAC, n° de série, modèle). */
export function filterLogin(rows: LoginResult[], cams: Camera[], codes: ReadonlySet<LoginCode>, query: string): LoginResult[] {
  return rows.filter((r) => (codes.size === 0 || codes.has(r.code)) && (!cams[r.index] || matchesCamera(cams[r.index], query)));
}

/** Le CSV de la vue affichée : Caméra, IP, MAC, Résultat. Rien du compte n'y figure. */
export function loginCsvRows(rows: LoginResult[], cams: Camera[], t: (key: string) => string): { header: string[]; rows: string[][] } {
  return {
    header: ['camera', 'ip', 'mac', 'result'].map((c) => t(`logintest.col.${c}`)),
    rows: rows.map((r) => {
      const c = cams[r.index];
      return [c ? cameraName(c) : '', r.ip, (c && shownMac(c).mac) ?? '', t(`logintest.code.${r.code}`)];
    }),
  };
}

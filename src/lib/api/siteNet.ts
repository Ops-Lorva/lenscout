import { Channel, invoke } from '@tauri-apps/api/core';
import { normalizeQuery } from '../search';
import type { NetworkFill } from './accounts';
import type { Camera } from './types';

/** Types devinés, dans l'ordre des pastilles. Miroir de `DeviceKind` (site_survey/device.rs). */
export const DEVICE_KINDS = ['camera', 'nvr', 'switch', 'pc', 'printer', 'gateway', 'this_pc', 'unknown'] as const;
export type DeviceKind = (typeof DEVICE_KINDS)[number];

/** Miroir de `SeenDevice` : un appareil relevé sur le réseau du compte. */
export interface SeenDevice {
  ip: string;
  mac?: string | null;
  /** Constructeur lu dans l'OUI de la MAC. */
  vendor?: string | null;
  kind: DeviceKind;
  name?: string | null;
  model?: string | null;
  /** Secondes depuis l'époque Unix. */
  first_seen: number;
  last_seen: number;
}

/** Miroir de `SurveyEvent` (commands/site_survey.rs). */
export type SurveyEvent =
  | { kind: 'progress'; done: number; total: number }
  | { kind: 'done'; devices: SeenDevice[]; surveyed_at: number; fill: NetworkFill | null; truncated: boolean };

/** Miroir de `AccountDevices` (commands/accounts.rs). */
export interface AccountDevices {
  devices: SeenDevice[];
  surveyed_at: number | null;
}

// Numéro d'un relevé : l'horloge d'abord, puis un compteur (comme les IP libres).
let counter = 0;
export const nextSurveyRun = () => Date.now() * 1000 + (counter++ % 1000);

/**
 * Relève le réseau du compte depuis `iface`. Rejette avec un code stable
 * (`not_on_account_network`, `ping_unavailable`…) ; `id` sert à l'annuler.
 * `cameras` : celles du dernier scan, pour deviner caméras et NVR.
 */
export function startSurvey(id: number, accountId: string, iface: string, cameras: Camera[], onEvent: (e: SurveyEvent) => void): Promise<void> {
  const channel = new Channel<SurveyEvent>();
  channel.onmessage = onEvent;
  return invoke<void>('cmd_site_survey', { id, accountId, interface: iface, cameras, channel });
}

export const cancelSurvey = (id: number) => invoke<void>('cmd_site_survey_cancel', { id });
export const accountDevices = (id: string) => invoke<AccountDevices>('cmd_account_devices', { id });
/** `key` : la MAC, sinon l'IP (`deviceKey`). */
export const forgetDevice = (id: string, key: string) => invoke<void>('cmd_account_forget_device', { id, key });

/** Clé d'un appareil, comme Rust : la MAC en majuscules, sinon l'IP. */
export const deviceKey = (d: SeenDevice): string => d.mac?.toUpperCase() ?? d.ip;

/** Nom affiché : celui annoncé sur le réseau, sinon le modèle de caméra. */
export const deviceName = (d: SeenDevice): string => d.name ?? d.model ?? '';

/** IP à ouvrir au Cadrage depuis le relevé : les caméras seulement. */
export const frameIp = (d: SeenDevice): string | null => (d.kind === 'camera' ? d.ip : null);

/**
 * Au-delà, un appareil relevé muet ne compte plus pris (miroir de
 * `STALE_DEVICE_SECS`, accounts.rs) ; il reste dans l'inventaire.
 */
export const STALE_DAYS = 180;
export const stale = (d: SeenDevice, now: number): boolean => now - d.last_seen > STALE_DAYS * 24 * 3600;

/** Miroir de `ReservedIp` : une adresse réservée à la main dans le réseau du compte. */
export interface ReservedIp {
  ip: string;
  label?: string | null;
  /** Secondes depuis l'époque Unix. */
  at: number;
}

export const accountReservations = (id: string) => invoke<ReservedIp[]>('cmd_account_reservations', { id });
/** Libellé vide : pas de libellé. */
export const reserveIp = (id: string, ip: string, label: string) =>
  invoke<void>('cmd_account_reserve', { id, ip, label: label.trim() || null });
export const releaseIp = (id: string, ip: string) => invoke<void>('cmd_account_release', { id, ip });

/**
 * Adresses libres du réseau, d'après la barre : les hôtes hors de toute
 * portion (passerelle, PC, exclues, réservées, caméras, appareils). Au plus
 * `cap` (un /16 en compte des dizaines de milliers) ; `more` : il en reste.
 * `query` filtre sur le texte de l'adresse.
 */
export function freeAddresses(fill: NetworkFill, query: string, cap: number): { ips: string[]; more: boolean } {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/\d+$/.exec(fill.network);
  if (!m) return { ips: [], more: false };
  const base = m.slice(1, 5).reduce((n, x) => n * 256 + Number(x), 0);
  const segs = [...fill.segments].sort((a, b) => a.first - b.first);
  const q = query.trim();
  const ips: string[] = [];
  let s = 0;
  for (let off = 1; off <= fill.size - 2; off++) {
    while (s < segs.length && segs[s].last < off) s++;
    if (s < segs.length && segs[s].first <= off) {
      off = segs[s].last;
      continue;
    }
    const n = base + off;
    const ip = [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
    if (q && !ip.includes(q)) continue;
    if (ips.length === cap) return { ips, more: true };
    ips.push(ip);
  }
  return { ips, more: false };
}

/** Pas entendu au dernier relevé : reste compté pris jusqu'à « Oublier ». */
export const absent = (d: SeenDevice, surveyedAt: number | null): boolean => surveyedAt !== null && d.last_seen < surveyedAt;

/** Types cochés (aucun : tous), puis recherche dans l'IP, la MAC, le constructeur, le nom et le modèle. */
export function filterDevices(list: SeenDevice[], kinds: ReadonlySet<DeviceKind>, query: string): SeenDevice[] {
  const raw = query.trim().toLowerCase();
  const clean = normalizeQuery(query);
  const hit = (d: SeenDevice) =>
    raw === '' ||
    d.ip.includes(raw) ||
    (clean !== '' && !!d.mac && normalizeQuery(d.mac).includes(clean)) ||
    [d.vendor, d.name, d.model].some((s) => s?.toLowerCase().includes(raw));
  return list.filter((d) => (kinds.size === 0 || kinds.has(d.kind)) && hit(d));
}

/** Lignes du CSV, dans l'ordre et le filtre de la vue. */
export function devicesCsvRows(
  list: SeenDevice[],
  t: (key: string) => string,
  date: (unix: number) => string,
): { header: string[]; rows: string[][] } {
  return {
    header: ['ip', 'mac', 'vendor', 'kind', 'name', 'seen'].map((c) => t(`sitenet.col.${c}`)),
    rows: list.map((d) => [d.ip, d.mac ?? '', d.vendor ?? '', t(`sitenet.kind.${d.kind}`), deviceName(d), date(d.last_seen)]),
  };
}

const num = (ip: string): number | null => {
  const p = ip.trim().split('.');
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255)) return null;
  return p.reduce((acc, x) => acc * 256 + Number(x), 0);
};

/**
 * Garde « sur place », comme Rust : l'adresse vue par le scan (`activeAddress` :
 * celle de l'interface, du compte posé, ou le réseau du compte en mode routé)
 * est dans le réseau de l'IP du PC du compte.
 */
export function onAccountNetwork(addr: { ip: string | null; mask?: string | null }, account: { pc_ip?: string | null } | null): boolean {
  const [pc, p] = (account?.pc_ip ?? '').split('/');
  const prefix = Number(p);
  const a = addr.ip ? num(addr.ip) : null;
  const b = num(pc ?? '');
  if (a === null || b === null || !/^\d{1,2}$/.test(p ?? '') || prefix > 32) return false;
  const size = 2 ** (32 - prefix);
  return Math.floor(a / size) === Math.floor(b / size);
}

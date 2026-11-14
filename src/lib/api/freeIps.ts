import { Channel, invoke } from '@tauri-apps/api/core';
import { errorKey } from './errors';

/** Miroir de `FreeRange` (free_ips.rs). */
export interface FreeRange {
  first: string;
  last: string;
  count: number;
}

/** Miroir de `FreeIpsEvent` (commands/free_ips.rs). */
export type FreeIpsEvent =
  | { kind: 'progress'; done: number; total: number }
  | { kind: 'done'; ranges: FreeRange[]; truncated: boolean };

export type FreeState =
  | { phase: 'scanning'; done: number; total: number }
  | { phase: 'done'; ranges: FreeRange[]; truncated: boolean }
  | { phase: 'error'; code: string };

/** Un événement de plus : un balayage terminé ne se rouvre pas (progression en retard). */
export function reduceFreeEvent(state: FreeState | null, e: FreeIpsEvent): FreeState {
  if (e.kind === 'done') return { phase: 'done', ranges: e.ranges, truncated: e.truncated };
  if (state && state.phase !== 'scanning') return state;
  return { phase: 'scanning', done: e.done, total: e.total };
}

// Numéro unique d'un balayage : l'horloge d'abord (un rechargement de la page ne
// retombe pas sur un numéro déjà annulé), puis un compteur.
let counter = 0;
const nextId = () => Date.now() * 1000 + (counter++ % 1000);

/**
 * `done` rend la main à la fin du balayage et rejette avec un code stable
 * (`ping_unavailable`…) ; `id` sert à l'annuler, même avant son démarrage.
 */
export function startFreeIps(iface: string, onEvent: (e: FreeIpsEvent) => void): { id: number; done: Promise<void> } {
  const id = nextId();
  const channel = new Channel<FreeIpsEvent>();
  channel.onmessage = onEvent;
  return { id, done: invoke<void>('cmd_free_ips', { id, interface: iface, channel }) };
}

export const cancelFreeIps = (id: number) => invoke<void>('cmd_free_ips_cancel', { id });

/** Clé i18n (espace `free`) d'une erreur du balayage. */
export const freeErrorKey = (e: unknown): string => `free.${errorKey(e)}`;

const num = (ip: string): number | null => {
  const p = ip.trim().split('.');
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255)) return null;
  return p.reduce((n, x) => n * 256 + Number(x), 0);
};

/** « 192.168.1.2–19 » : le préfixe commun n'est écrit qu'une fois. */
export function rangeLabel(r: FreeRange): string {
  if (r.first === r.last) return r.first;
  const a = r.first.split('.');
  const b = r.last.split('.');
  return a.slice(0, 3).join('.') === b.slice(0, 3).join('.') ? `${r.first}–${b[3]}` : `${r.first}–${r.last}`;
}

/** La première plage d'au moins `n` adresses : son adresse de tête. */
export function firstFit(ranges: FreeRange[], n: number): string | null {
  if (n < 1) return null;
  return ranges.find((r) => r.count >= n)?.first ?? null;
}

/** La plage qui contient l'adresse saisie : celle qu'on marque comme choisie. */
export function rangeContaining(ranges: FreeRange[], ip: string): FreeRange | undefined {
  const n = num(ip);
  if (n === null) return undefined;
  return ranges.find((r) => n >= (num(r.first) ?? Infinity) && n <= (num(r.last) ?? -1));
}

/** « en0, 192.168.1.0/24 » ; l'interface seule si l'adresse ou le masque manque. */
export function networkLabel(iface: string, ip: string | null, mask: string | null): string {
  const a = ip ? num(ip) : null;
  const m = mask ? num(mask) : null;
  if (a === null || m === null) return iface;
  const net = (a & m) >>> 0;
  const prefix = m.toString(2).replace(/0+$/, '').length;
  return `${iface}, ${[24, 16, 8, 0].map((s) => (net >>> s) & 255).join('.')}/${prefix}`;
}

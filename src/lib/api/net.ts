import { invoke } from '@tauri-apps/api/core';
import { writable } from 'svelte/store';

/** Masque proposé par les feuilles IP tant qu'aucun compte n'en donne un. */
export const DEFAULT_MASK = '255.255.255.0';

const num = (ip: string): number | null => {
  const p = ip.trim().split('.');
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255)) return null;
  return p.reduce((acc, x) => acc * 256 + Number(x), 0);
};

const dotted = (n: number) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');

/** `a.b.c.d/n` → adresse (nombre) et préfixe 1 à 32, sinon `null`. */
function cidr(s: string): { ip: number; prefix: number } | null {
  const [ip, p, ...rest] = s.trim().split('/');
  if (rest.length || p === undefined || !/^\d{1,2}$/.test(p)) return null;
  const prefix = Number(p);
  const n = num(ip);
  return n === null || prefix < 1 || prefix > 32 ? null : { ip: n, prefix };
}

const maskBits = (prefix: number) => (prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0);

/** `192.168.1.250/24` → `192.168.1.0/24` ; illisible → `''`. Aide du formulaire de compte. */
export function networkOf(pcIp: string): string {
  const c = cidr(pcIp);
  return c ? `${dotted((c.ip & maskBits(c.prefix)) >>> 0)}/${c.prefix}` : '';
}

/** `192.168.1.0/24` → `255.255.255.0` ; illisible → `''`. */
export function maskOf(s: string): string {
  const c = cidr(s);
  return c ? dotted(maskBits(c.prefix)) : '';
}

/**
 * Valeur d'un champ prérempli : `current` reste s'il a été saisi (différent du
 * dernier préremplissage `lastAuto` et non vide), sinon il prend `wanted`.
 */
export const autoFill = (current: string, lastAuto: string, wanted: string): string =>
  current.trim() === '' || current === lastAuto ? wanted : current;

export interface AccountNet {
  pc_ip?: string | null;
  network?: string | null;
  gateway?: string | null;
}

/** Masque et passerelle qu'un compte propose aux feuilles IP (réseau, sinon préfixe de l'IP du PC). */
export function prefillFor(a: AccountNet | null): { mask: string; gateway: string } {
  const mask = maskOf(a?.network ?? '') || maskOf(a?.pc_ip ?? '') || DEFAULT_MASK;
  return { mask, gateway: a?.gateway ?? '' };
}

/** Miroir de `JoinedOut` (commands/join.rs) : l'IP du PC posée pour un compte. */
export interface Joined {
  account_id: string;
  iface: string;
  ip: string;
  mask: string;
  cidr: string;
}

/** L'adresse posée pour un compte, partagée par l'écran Réseau et les feuilles IP. */
export const joined = writable<Joined | null>(null);

export const joinNetwork = (accountId: string, iface: string) => invoke<Joined>('cmd_join_network', { accountId, iface });
export const leaveNetwork = () => invoke<void>('cmd_leave_network');
export const joinedNetwork = () => invoke<Joined | null>('cmd_joined_network');

/** Adresse et masque du poste vus par le scan : ceux du compte posé sur cette interface, sinon ceux de l'interface. */
export function activeAddress(
  iface: string,
  details: { ip: string | null; subnet: string | null } | null,
  j: Joined | null,
): { ip: string | null; mask: string | null } {
  if (j && j.iface === iface) return { ip: j.ip, mask: j.mask };
  return { ip: details?.ip ?? null, mask: details?.subnet ?? null };
}

/** Interface et choix du sélecteur de compte ; `account === ''` : DHCP. */
export interface JoinChoice {
  iface: string;
  account: string;
}

/** Ce qu'un changement de choix demande au cœur. */
export function joinStep(applied: JoinChoice, wanted: JoinChoice): 'none' | 'join' | 'leave' {
  if (wanted.account === '') return applied.account === '' ? 'none' : 'leave';
  return applied.account === wanted.account && applied.iface === wanted.iface ? 'none' : 'join';
}

export type JoinResult =
  | { kind: 'done'; applied: JoinChoice; joined: Joined | null }
  | { kind: 'failed'; code: unknown; applied: JoinChoice }
  | { kind: 'ignored'; applied: JoinChoice };

/**
 * Le sélecteur de compte de l'écran Réseau : un changement à la fois (un
 * second pendant le premier est ignoré), et le choix appliqué revient tel
 * quel en cas d'échec. Poser un compte quand un autre l'est : le cœur
 * retire l'ancien d'abord.
 */
export function createJoinSwitch(ops: {
  join: (account: string, iface: string) => Promise<Joined>;
  leave: () => Promise<void>;
}) {
  let applied: JoinChoice = { iface: '', account: '' };
  let busy = false;
  return {
    get applied() {
      return { ...applied };
    },
    get busy() {
      return busy;
    },
    /** État du cœur à l'ouverture de l'écran. */
    init(iface: string, j: Joined | null) {
      applied = j ? { iface: j.iface, account: j.account_id } : { iface, account: '' };
    },
    async change(wanted: JoinChoice): Promise<JoinResult> {
      if (busy) return { kind: 'ignored', applied: { ...applied } };
      busy = true;
      try {
        const step = joinStep(applied, wanted);
        let j: Joined | null = null;
        if (step === 'join') j = await ops.join(wanted.account, wanted.iface);
        else if (step === 'leave') await ops.leave();
        applied = { ...wanted };
        return { kind: 'done', applied: { ...applied }, joined: j };
      } catch (code) {
        return { kind: 'failed', code, applied: { ...applied } };
      } finally {
        busy = false;
      }
    },
  };
}

export interface MaskGateway {
  mask: string;
  gateway: string;
}

/**
 * Préremplissage des feuilles IP par le compte retenu : `fields` = valeurs à
 * l'écran, `last` = dernier préremplissage. Un champ saisi reste ; un champ
 * vide ou encore prérempli suit le compte (ou revient au défaut).
 */
export function applyPrefill(fields: MaskGateway, last: MaskGateway, account: AccountNet | null): { fields: MaskGateway; last: MaskGateway } {
  const wanted = prefillFor(account);
  return {
    fields: { mask: autoFill(fields.mask, last.mask, wanted.mask), gateway: autoFill(fields.gateway, last.gateway, wanted.gateway) },
    last: wanted,
  };
}

/** État initial d'une feuille : masque par défaut, passerelle vide, tous deux « préremplis ». */
export const INITIAL_PREFILL: MaskGateway = { mask: DEFAULT_MASK, gateway: '' };

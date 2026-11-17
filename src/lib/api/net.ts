import { invoke } from '@tauri-apps/api/core';
import { writable } from 'svelte/store';
import { joinable, type Account } from './accounts';

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

/** `192.168.1.250/24` → `192.168.1.0/24` ; illisible → `''`. */
export function networkOf(pcIp: string): string {
  const c = cidr(pcIp);
  return c ? `${dotted((c.ip & maskBits(c.prefix)) >>> 0)}/${c.prefix}` : '';
}

/** `192.168.1.0/24` → `255.255.255.0` ; illisible → `''`. */
export function maskOf(s: string): string {
  const c = cidr(s);
  return c ? dotted(maskBits(c.prefix)) : '';
}

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
  /**
   * Mode routé : la passerelle du poste par laquelle passe le réseau du
   * compte. Rien n'est posé ; `ip`, `mask` et `cidr` sont ceux de ce réseau.
   */
  via?: string | null;
}

/** L'adresse posée pour un compte, partagée par l'écran Réseau et les feuilles IP. */
export const joined = writable<Joined | null>(null);

export const joinNetwork = (accountId: string, iface: string) => invoke<Joined>('cmd_join_network', { accountId, iface });
export const leaveNetwork = () => invoke<void>('cmd_leave_network');
export const joinedNetwork = () => invoke<Joined | null>('cmd_joined_network');
/** Attend que l'adresse posée soit sur le poste (code `pc_ip_not_present` au-delà du délai). */
export const joinReady = () => invoke<void>('cmd_join_ready');

/** Adresse et masque du poste vus par le scan : ceux du compte posé sur cette interface, sinon ceux de l'interface. */
export function activeAddress(
  iface: string,
  details: { ip: string | null; subnet: string | null } | null,
  j: Joined | null,
): { ip: string | null; mask: string | null } {
  if (j && j.iface === iface) return { ip: j.ip, mask: j.mask };
  return { ip: details?.ip ?? null, mask: details?.subnet ?? null };
}

/**
 * Adresse affichée à côté des sélecteurs : DHCP, celle de l'interface ;
 * compte posé, l'IP posée ; mode routé, celle de l'interface (rien n'est
 * posé) avec la passerelle par laquelle passe le compte.
 */
export function shownAddress(account: string, j: Joined | null, ifaceAddr: string): { addr: string; via: string | null } {
  if (!account) return { addr: ifaceAddr, via: null };
  if (j?.account_id !== account) return { addr: '', via: null };
  return j.via ? { addr: ifaceAddr, via: j.via } : { addr: j.cidr, via: null };
}

/** Option du sélecteur de compte de l'écran Réseau. */
export interface AccountChoice {
  id: string;
  name: string;
  /** Compte supprimé alors que son IP est encore posée. */
  deleted: boolean;
}

/**
 * Comptes proposés (ceux qui ont une IP du PC), plus le compte posé s'il a
 * été supprimé entre-temps : son IP reste sur le poste, le sélecteur doit le
 * montrer (et permettre le retour en DHCP), pas une case vide.
 */
export function accountChoices(list: Account[], j: Joined | null): AccountChoice[] {
  const out = joinable(list).map((a) => ({ id: a.id, name: a.name, deleted: false }));
  if (j && !list.some((a) => a.id === j.account_id)) out.push({ id: j.account_id, name: '', deleted: true });
  return out;
}

/**
 * Un scan peut-il partir ? Jamais pendant la pose d'une IP : il verrait
 * l'ancien réseau, ou rien (l'adresse n'est pas encore là).
 */
export const canScan = (iface: string, posing: boolean): boolean => !!iface && !posing;

/** Jetons de génération : seule la dernière attente lancée compte. */
export function generations() {
  let n = 0;
  return {
    next: () => ++n,
    current: (g: number) => g === n,
  };
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
 * Préremplissage des feuilles IP par le compte retenu : un champ touché
 * (saisi par l'utilisateur) reste, les autres suivent le compte ou
 * reviennent au défaut.
 */
export function prefillFields(fields: MaskGateway, touched: { mask: boolean; gateway: boolean }, account: AccountNet | null): MaskGateway {
  const wanted = prefillFor(account);
  return { mask: touched.mask ? fields.mask : wanted.mask, gateway: touched.gateway ? fields.gateway : wanted.gateway };
}

/** État initial d'une feuille : masque par défaut, passerelle vide. */
export const INITIAL_PREFILL: MaskGateway = { mask: DEFAULT_MASK, gateway: '' };

/**
 * Le DNS des feuilles IP : la passerelle (du compte ou saisie) tant que
 * l'utilisateur n'a pas tapé dans le champ. Une fois touché, il reste,
 * même vide : c'est un choix.
 */
export const dnsFollowing = (dns: string, touched: boolean, gateway: string): string => (touched ? dns : gateway);

/**
 * Le compte retenu par une feuille IP doit-il être posé sur le PC avant le
 * balayage des adresses libres ? Oui s'il a une IP de PC et que ce n'est pas
 * lui qui est posé : sinon le balayage partait du réseau de l'interface (le
 * DHCP du technicien) et proposait des adresses d'un autre réseau.
 */
export function needsJoin(
  account: Pick<Account, 'id' | 'pc_ip'> | null | undefined,
  j: Joined | null,
  ifaceIp: string | null = null,
): boolean {
  if (!account?.pc_ip || j?.account_id === account.id) return false;
  // Carte déjà réglée à la main dans le réseau du compte : rien à poser.
  const c = cidr(account.pc_ip);
  const n = ifaceIp ? num(ifaceIp) : null;
  if (c && n !== null && ((n & maskBits(c.prefix)) >>> 0) === ((c.ip & maskBits(c.prefix)) >>> 0)) return false;
  return true;
}

/**
 * Demande de poser un compte, venue d'une feuille IP : l'écran Réseau, seul
 * à tenir le sélecteur de compte, la traite comme un choix dans ce sélecteur.
 */
export const joinRequest = writable<string | null>(null);

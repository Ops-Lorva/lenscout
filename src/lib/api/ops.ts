import { invoke } from '@tauri-apps/api/core';
import type { Addressing, Camera } from './types';
import { cameraKey } from '#lib/stores/cameras.ts';
import { orNull, splitList, type ActionResult } from './configure';

/** Les opérations de l'onglet Opérations. */
export type OpKind = 'keep_ip' | 'renumber' | 'time' | 'change_credentials';

/** Miroir de `NetConfig` (vapix.rs) : le réglage lu sur la caméra. */
export interface NetConfig {
  addressing: Addressing;
  ip: string;
  mask: string;
  gateway: string | null;
  dns: string[];
}

/** Miroir de `NetTarget` (ops.rs) : ce que la caméra recevra. */
export interface NetTarget {
  ip: string;
  mask: string;
  gateway: string | null;
  dns: string[];
}

/** Miroir de `Conflict` (ops.rs). */
export type Conflict =
  | { code: 'unsupported' }
  | { code: 'missing_identity' }
  | { code: 'unreadable' }
  | { code: 'dhcp' }
  | { code: 'ip_in_use'; ip: string; mac: string | null }
  | { code: 'network_or_broadcast'; ip: string }
  | { code: 'gateway_out_of_subnet'; ip: string }
  | { code: 'gateway_is_ip'; ip: string }
  | { code: 'outside_account'; network: string };

/** Miroir de `OpRow`. */
export interface OpRow {
  key: string;
  ip: string;
  before: NetConfig | null;
  after: NetTarget | null;
  conflicts: Conflict[];
}

/** Miroir de `OpsPreview` : `id` absent tant qu'une ligne bloque. */
export interface OpsPreview {
  id: string | null;
  rows: OpRow[];
}

/** Miroir de `StepResult` : `reachable` après un changement d'adresse réussi. */
export interface StepResult extends ActionResult {
  reachable: boolean | null;
}

/** Miroir de `CredOutcome` (ops.rs) : la sortie d'une caméra pour « changer les identifiants ». */
export type CredOutcome =
  | { code: 'posed'; login: string }
  | { code: 'already_up_to_date' }
  | { code: 'no_credential' }
  | { code: 'stopped_by_guard' }
  | { code: 'unsupported' }
  | { code: 'unreachable' }
  | { code: 'rejected'; detail: string };

/** Miroir de `CredResult` : la clé de la ligne et sa sortie (jamais de mot de passe). */
export type CredResult = { key: string } & CredOutcome;

/** Un résultat de ligne, selon l'opération : réseau/heure, ou identifiants. */
export type AnyResult = StepResult | CredResult;

/** Un résultat de changement d'identifiants porte `code` ; un `StepResult` porte `ok`. */
export const isCredResult = (r: AnyResult): r is CredResult => 'code' in r;

/** Un couple identifiant / mot de passe à essayer (n'existe qu'en mémoire). */
export interface CredPair {
  login: string;
  password: string;
}

/**
 * Miroir de `OpRequestDto` (commands/ops.rs) ; `keep_ip` : `null` = inchangé.
 * Les mots de passe de `change_credentials` ne vivent qu'en mémoire : jamais
 * journalisés ni mis dans l'empreinte.
 */
export type OpRequest =
  | { kind: 'keep_ip'; mask: string | null; gateway: string | null; dns: string[] | null }
  | { kind: 'renumber'; start: string; mask: string; gateway: string | null; dns: string[] }
  | { kind: 'time'; ntp_servers: string[]; timezone: string }
  | { kind: 'change_credentials'; candidates: CredPair[] };

/** Les champs de l'écran, toutes opérations confondues. */
export interface OpFields {
  kind: OpKind;
  start: string;
  mask: string;
  gateway: string;
  dns: string;
  ntp: string;
  timezone: string;
}

/** Seul l'avertissement « hors du réseau du compte » laisse appliquer. */
export const isBlocking = (c: Conflict): boolean => c.code !== 'outside_account';

/**
 * Appliquer : un plan gardé par Rust (`id`), aucune ligne bloquée, rien en
 * cours. La confirmation est un bouton en deux clics (comme Supprimer dans
 * Comptes), portée par l'écran.
 */
export const canApply = (p: OpsPreview | null, running: boolean): boolean =>
  !!p?.id && !running && !p.rows.some((r) => r.conflicts.some(isBlocking));

export function conflictMessage(c: Conflict): { key: string; values: Record<string, string> } {
  const values: Record<string, string> = {};
  if ('ip' in c) values.ip = c.ip;
  if ('network' in c) values.network = c.network;
  return { key: `ops.conflict.${c.code}`, values };
}

/**
 * Requête d'aperçu. Pour `change_credentials`, l'aperçu ne dépend pas des
 * identifiants (il n'essaie rien) : on ne renvoie qu'un marqueur, les secrets
 * partent à part (`credsRequest`), jamais dans l'empreinte.
 */
export function opRequest(f: OpFields): OpRequest | { kind: 'change_credentials' } {
  switch (f.kind) {
    case 'keep_ip': {
      const dns = splitList(f.dns);
      return { kind: 'keep_ip', mask: orNull(f.mask), gateway: orNull(f.gateway), dns: dns.length ? dns : null };
    }
    case 'renumber':
      return { kind: 'renumber', start: f.start.trim(), mask: f.mask.trim(), gateway: orNull(f.gateway), dns: splitList(f.dns) };
    case 'time':
      return { kind: 'time', ntp_servers: splitList(f.ntp), timezone: f.timezone };
    case 'change_credentials':
      return { kind: 'change_credentials' };
  }
}

/**
 * Requête backend « changer les identifiants » : l'identifiant visé est celui
 * du compte sélectionné (Rust le lit), la requête ne porte que les couples à
 * essayer. Secrets en clair, uniquement en mémoire.
 */
export const credsRequest = (pairs: CredPair[]): OpRequest => ({
  kind: 'change_credentials',
  candidates: pairs.filter((p) => p.login.trim() !== '' || p.password !== '').map((p) => ({ login: p.login.trim(), password: p.password })),
});

/**
 * La sélection (ordre compris), l'opération, ses champs, l'interface ou le
 * compte qui changent : l'aperçu n'est plus celui de l'écran. `extra` invalide
 * l'aperçu quand un champ hors empreinte change (p. ex. une édition des
 * identifiants), sans y mettre de secret.
 */
export const opsFingerprint = (cams: Camera[], f: OpFields, iface: string, accountId: string, extra = ''): string =>
  JSON.stringify([iface, accountId, extra, cams.map(cameraKey), opRequest(f)]);

export interface Cell {
  before: string | null;
  after: string | null;
  changed: boolean;
}

/**
 * Colonnes réseau d'une ligne d'aperçu, avant → après. `before` absent :
 * réglage non lu ; `after` absent : opération sans écriture réseau (l'heure).
 */
export function cells(r: OpRow): { ip: Cell; mask: Cell; gateway: Cell; dns: Cell } {
  const cell = (before: string | null, after: string | null): Cell => ({ before, after, changed: after !== null && before !== after });
  const b = r.before;
  const a = r.after;
  return {
    ip: cell(b?.ip ?? r.ip, a?.ip ?? null),
    mask: cell(b?.mask ?? null, a?.mask ?? null),
    gateway: cell(b ? (b.gateway ?? '') : null, a ? (a.gateway ?? '') : null),
    dns: cell(b ? b.dns.join(', ') : null, a ? a.dns.join(', ') : null),
  };
}

/**
 * Une ligne après l'autre ; `stopped` est relu avant chaque ligne (Arrêter
 * laisse finir la caméra en cours, jamais la suivante). Une erreur de
 * commande (aperçu expiré, compte…) arrête la série et remonte.
 */
export async function runSteps<R>(
  count: number,
  step: (i: number) => Promise<R>,
  stopped: () => boolean,
  onResult: (i: number, r: R) => void,
): Promise<{ stopped: boolean; done: number }> {
  for (let i = 0; i < count; i++) {
    if (stopped()) return { stopped: true, done: i };
    onResult(i, await step(i));
  }
  return { stopped: false, done: count };
}

/** Rapport : réussies, échouées, écrites mais muettes à leur nouvelle adresse, non faites (Arrêter). */
export function summarize(results: (StepResult | undefined)[], total: number) {
  const done = results.filter((r): r is StepResult => !!r);
  return {
    ok: done.filter((r) => r.ok && r.reachable !== false).length,
    failed: done.filter((r) => !r.ok).length,
    unreachable: done.filter((r) => r.ok && r.reachable === false).length,
    skipped: total - done.length,
  };
}

/** Rapport de « changer les identifiants » : posées, déjà à jour, aucun identifiant, arrêtées par le garde-fou, non prises en charge, injoignables, refusées, non faites. */
export function credSummarize(results: (CredResult | undefined)[], total: number) {
  const done = results.filter((r): r is CredResult => !!r);
  const n = (code: CredOutcome['code']) => done.filter((r) => r.code === code).length;
  return {
    posed: n('posed'),
    alreadyUpToDate: n('already_up_to_date'),
    noCredential: n('no_credential'),
    stopped: n('stopped_by_guard'),
    unsupported: n('unsupported'),
    unreachable: n('unreachable'),
    rejected: n('rejected'),
    skipped: total - done.length,
  };
}

/** Nouvelle IP par clé de ligne, pour les lignes réseau réussies (`markAddressing`). */
export function movedIps(rows: OpRow[], results: (StepResult | undefined)[]): Record<string, string> {
  return Object.fromEntries(
    rows.flatMap((r, i) => (r.after && results[i]?.ok ? [[r.key, r.after.ip] as const] : [])),
  );
}

/** Aperçu calculé par Rust ; rien n'est écrit sur les caméras. */
export const opsPreview = (selection: Camera[], others: Camera[], req: OpRequest, iface: string, accountId: string) =>
  invoke<OpsPreview>('cmd_ops_preview', { selection, others, req, iface, accountId });

/** Applique la ligne `index` de l'opération gardée par Rust. */
export const opsStep = (opId: string, index: number, accountId: string, iface: string) =>
  invoke<StepResult>('cmd_ops_step', { opId, index, accountId, iface });

/** Applique la ligne `index` d'un changement d'identifiants (essais + pose). */
export const opsCredsStep = (opId: string, index: number, accountId: string, iface: string) =>
  invoke<CredResult>('cmd_ops_creds_step', { opId, index, accountId, iface });

/** Arrêter ou abandonner : Rust oublie l'opération. */
export const opsClose = (opId: string) => invoke<void>('cmd_ops_close', { opId });

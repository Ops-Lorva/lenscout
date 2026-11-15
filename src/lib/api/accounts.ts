import { invoke } from '@tauri-apps/api/core';

/** Miroir de `Account` (accounts.rs). Aucun mot de passe ne revient de Rust, sauf `accountPassword`. */
export interface Account {
  id: string;
  name: string;
  login: string;
  /** Champs réseau facultatifs, en clair : absents s'ils ne sont pas renseignés. */
  pc_ip?: string;
  network?: string;
  gateway?: string;
  /** Adresses et plages jamais proposées aux caméras (`a.b.c.d, a.b.c.d-a.b.c.e`). */
  exclusions?: string;
}

/** Champs réseau envoyés à Rust : `null` pour un champ vide. */
export interface AccountNetIn {
  pc_ip: string | null;
  network: string | null;
  gateway: string | null;
  exclusions: string | null;
}

const orNull = (s: string) => (s.trim() === '' ? null : s.trim());

/** Les champs du formulaire → ce que Rust attend ; le réseau, Rust le déduit de l'IP du PC. */
export const netIn = (pc_ip: string, gateway: string, exclusions = ''): AccountNetIn => ({
  pc_ip: orNull(pc_ip),
  network: null,
  gateway: orNull(gateway),
  exclusions: orNull(exclusions),
});

/** Erreur à afficher sous le champ IP du PC (même clé que le code Rust `missing_mask`), sinon `''`. */
export const pcIpError = (pcIp: string): string => {
  const s = pcIp.trim();
  return s !== '' && !s.includes('/') ? 'error.missing_mask' : '';
};

/** Entrée de liste : `has_secret` dit seulement si le mot de passe est au trousseau. */
export interface AccountEntry extends Account {
  has_secret: boolean;
}

export const ACCOUNT_KEY = 'lenscout.account';

export const listAccounts = () => invoke<AccountEntry[]>('cmd_accounts_list');
/** Code d'un démarrage dégradé (rendu une seule fois), ou `null`. */
export const accountsStartup = () => invoke<string | null>('cmd_accounts_startup');
export const createAccount = (name: string, login: string, password: string, net: AccountNetIn) =>
  invoke<Account>('cmd_account_create', { name, login, password, net });
/** `password` absent ou `null` : le mot de passe reste inchangé. Les champs réseau sont remplacés. */
export const updateAccount = (id: string, name: string, login: string, password: string | null, net: AccountNetIn) =>
  invoke<Account>('cmd_account_update', { id, name, login, password, net });
export const removeAccount = (id: string) => invoke<void>('cmd_account_remove', { id });
/** Mot de passe d'UN compte, pour la fiche Modifier ; `null` : à ressaisir. Ne pas le garder après la fiche. */
export const accountPassword = (id: string) => invoke<string | null>('cmd_account_password', { id });

/** Mot de passe à envoyer à la modification : `null` (conservé) si le champ est vide ou n'a pas bougé depuis le préremplissage. */
export const passwordToSend = (current: string, prefilled: string): string | null =>
  current === '' || current === prefilled ? null : current;

/** Miroir de `KnownCamera` (accounts.rs) : une caméra vue ou adressée avec le compte. */
export interface KnownCamera {
  ip: string;
  serial?: string;
  mac?: string;
  model?: string;
  /** Secondes depuis l'époque Unix. */
  last_seen: number;
}

/** Miroir de `Segment` : décalages depuis l'adresse de réseau. */
export interface FillSegment {
  kind: 'gateway' | 'pc' | 'excluded' | 'camera';
  first: number;
  last: number;
}

/** Miroir de `NetworkFill` : chaque adresse d'hôte comptée une fois. */
export interface NetworkFill {
  network: string;
  size: number;
  usable: number;
  gateway: number;
  pc: number;
  excluded: number;
  cameras: number;
  free: number;
  /** Moins de 10 % d'adresses libres. */
  almost_full: boolean;
  segments: FillSegment[];
}

/** Clé d'une caméra connue, comme Rust : le n° de série, sinon la MAC. */
export const knownKey = (c: KnownCamera): string => c.serial ?? c.mac ?? '';

/** Colonnes triables du tableau des caméras connues (la modale « agrandir »). */
export type KnownSortColumn = 'ip' | 'id' | 'type' | 'model' | 'seen';
export type KnownSortDir = 'asc' | 'desc';
export interface KnownSort {
  col: KnownSortColumn;
  dir: KnownSortDir;
}

const ipNum = (ip: string): number =>
  ip.split('.').reduce((acc, part) => acc * 256 + (Number(part) || 0), 0);

/**
 * Valeur comparable d'une caméra connue pour une colonne : nombre pour l'IP
 * (ordre numérique) et « Vue le » (last_seen), chaîne sinon. `null` = valeur
 * absente, rangée en fin de liste quel que soit le sens.
 */
function knownValue(c: KnownCamera, col: KnownSortColumn): number | string | null {
  switch (col) {
    case 'ip':
      return ipNum(c.ip);
    case 'id':
      return knownKey(c) || null;
    case 'type':
      return c.serial ? 'serial' : c.mac ? 'mac' : null;
    case 'model':
      return c.model || null;
    case 'seen':
      return c.last_seen;
  }
}

/**
 * Tri stable : valeurs absentes toujours en fin, comparaison numérique ou
 * textuelle selon la colonne, puis départage par IP numérique croissante.
 */
export function sortKnown(list: KnownCamera[], s: KnownSort): KnownCamera[] {
  const dir = s.dir === 'asc' ? 1 : -1;
  return [...list].sort((a, b) => {
    const va = knownValue(a, s.col);
    const vb = knownValue(b, s.col);
    if (va === null || vb === null) {
      if (va === vb) return ipNum(a.ip) - ipNum(b.ip);
      return va === null ? 1 : -1;
    }
    const cmp = typeof va === 'number' && typeof vb === 'number' ? va - vb : String(va).localeCompare(String(vb));
    return cmp !== 0 ? cmp * dir : ipNum(a.ip) - ipNum(b.ip);
  });
}

export const accountCameras = (id: string) => invoke<KnownCamera[]>('cmd_account_cameras', { id });
/** `null` : compte sans IP du PC. */
export const accountFill = (id: string) => invoke<NetworkFill | null>('cmd_account_fill', { id });
export const forgetCamera = (id: string, key: string) => invoke<void>('cmd_account_forget_camera', { id, key });

/** Place d'une portion dans la barre, en % de la taille du réseau. */
export const segmentBox = (s: FillSegment, size: number) => ({
  left: (s.first / size) * 100,
  width: ((s.last - s.first + 1) / size) * 100,
});

/** Bornes de la barre (`10.0.8.0/24` → réseau et diffusion) ; `null` si illisible. */
export function networkEnds(network: string): [string, string] | null {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(network);
  if (!m) return null;
  const base = m.slice(1, 5).reduce((n, x) => n * 256 + Number(x), 0);
  const last = base + 2 ** (32 - Number(m[5])) - 1;
  const ip = (n: number) => [24, 16, 8, 0].map((b) => Math.floor(n / 2 ** b) % 256).join('.');
  return [ip(base), ip(last)];
}

/** Compteurs de la légende : « 37 caméras · 206 libres sur 243 » (243 = adresses laissées aux caméras). */
export const fillLabel = (f: NetworkFill) => ({ cameras: f.cameras, free: f.free, total: f.cameras + f.free });

/** Plan d'import (miroir de `ImportPlanOut`) : aucun secret, seulement ce qui diffère. */
export interface ImportItem {
  name: string;
  kind: 'new' | 'identical' | 'differs';
  login_differs: boolean;
  password_differs: boolean;
  network_differs: boolean;
  /** Passerelle du fichier écartée : hors du réseau de l'IP du PC. */
  gateway_dropped: boolean;
}

/** Clés i18n (sous `accounts.why.`) de ce qui diffère, dans l'ordre, puis
 * la passerelle écartée (tout compte, nouveau ou identique compris). */
export function whyKeys(i: ImportItem): string[] {
  const keys: string[] = [];
  if (i.login_differs && i.password_differs) keys.push('both');
  else if (i.login_differs) keys.push('login');
  else if (i.password_differs) keys.push('password');
  if (i.network_differs) keys.push('network');
  if (i.gateway_dropped) keys.push('gateway_dropped');
  return keys;
}

/** Comptes proposés par le sélecteur de l'écran Réseau : ceux qui ont une IP du PC. */
export const joinable = <T extends Account>(accounts: T[]): T[] => accounts.filter((a) => !!a.pc_ip);
export interface ImportPlan {
  items: ImportItem[];
}
export interface ImportSummary {
  added: number;
  identical: number;
  replaced: number;
  kept_both: number;
  skipped: number;
}
/** Choix pour un nom déjà présent qui diffère. */
export type Choice = 'replace' | 'keep_both' | 'skip';
export const CHOICES: Choice[] = ['replace', 'keep_both', 'skip'];

/** Nom proposé par la boîte Enregistrer, et extension du filtre des deux boîtes. */
export const EXPORT_NAME = 'lenscout-comptes.lenscout';
export const EXPORT_EXT = 'lenscout';

// Le chemin vient de la boîte Enregistrer / Ouvrir du plugin dialog, jamais d'une saisie.
/** Nombre de comptes écrits. */
export const exportAccounts = (path: string) => invoke<number>('cmd_accounts_export', { path });
export const importPlan = (path: string) => invoke<ImportPlan>('cmd_accounts_import_plan', { path });
export const applyImport = (path: string, choices: Record<string, Choice>) =>
  invoke<ImportSummary>('cmd_accounts_import_apply', { path, choices });

/** Les trois groupes de la feuille d'import, dans l'ordre du fichier. */
export function groupPlan(plan: ImportPlan) {
  return {
    differs: plan.items.filter((i) => i.kind === 'differs'),
    added: plan.items.filter((i) => i.kind === 'new'),
    identical: plan.items.filter((i) => i.kind === 'identical'),
  };
}

/** Remplacer pour chaque compte qui diffère : le fichier vient le plus souvent d'un backup plus récent. */
export function defaultChoices(plan: ImportPlan): Record<string, Choice> {
  return Object.fromEntries(groupPlan(plan).differs.map((i) => [i.name, 'replace' as Choice]));
}

/** Nom que prendrait « Garder les deux » : premier suffixe libre à partir de 2 (casse ignorée, comme le carnet). */
export function suffixedName(name: string, taken: string[]): string {
  const used = new Set(taken.map((t) => t.toLowerCase()));
  for (let n = 2; ; n++) {
    const candidate = `${name} ${n}`;
    if (!used.has(candidate.toLowerCase())) return candidate;
  }
}

/**
 * Noms créés par « Garder les deux », dans l'ordre du fichier. Les suffixes évitent
 * le carnet et TOUS les noms du fichier, comme le fait le core.
 */
export function keepBothNames(plan: ImportPlan, choices: Record<string, Choice>, existing: string[]): string[] {
  const taken = [...existing, ...plan.items.map((i) => i.name)];
  const names: string[] = [];
  for (const i of groupPlan(plan).differs) {
    if (choices[i.name] !== 'keep_both') continue;
    const n = suffixedName(i.name, taken);
    taken.push(n);
    names.push(n);
  }
  return names;
}

/** Le fichier d'export porte `.lenscout` (Rust l'ajoute aussi : même règle). */
export const withExtension = (path: string) =>
  path.toLowerCase().endsWith(`.${EXPORT_EXT}`) ? path : `${path}.${EXPORT_EXT}`;

/** Le dernier choix s'il existe encore, sinon le premier compte, sinon rien. */
export function pickAccount(accounts: Account[], saved: string): string {
  return accounts.find((a) => a.id === saved)?.id ?? accounts[0]?.id ?? '';
}

/** Création, ou compte dont le secret manque : sans mot de passe on croirait l'avoir réparé. */
export const passwordRequired = (entry: AccountEntry | null) => entry === null || !entry.has_secret;

/** Clé i18n (sous `accounts.`) du signalement de démarrage. */
export function noticeKey(code: string | null): string | null {
  return code === 'quarantined' || code === 'unwritable' || code === 'migration_incomplete' ? `notice.${code}` : null;
}

import { invoke } from '@tauri-apps/api/core';

/** Miroir de `Account` (accounts.rs). Aucun mot de passe ne revient jamais de Rust. */
export interface Account {
  id: string;
  name: string;
  login: string;
}

/** Entrée de liste : `has_secret` dit seulement si le mot de passe est au trousseau. */
export interface AccountEntry extends Account {
  has_secret: boolean;
}

export const ACCOUNT_KEY = 'lenscout.account';

export const listAccounts = () => invoke<AccountEntry[]>('cmd_accounts_list');
/** Code d'un démarrage dégradé (rendu une seule fois), ou `null`. */
export const accountsStartup = () => invoke<string | null>('cmd_accounts_startup');
export const createAccount = (name: string, login: string, password: string) =>
  invoke<Account>('cmd_account_create', { name, login, password });
/** `password` absent ou `null` : le mot de passe reste inchangé. */
export const updateAccount = (id: string, name: string, login: string, password: string | null) =>
  invoke<Account>('cmd_account_update', { id, name, login, password });
export const removeAccount = (id: string) => invoke<void>('cmd_account_remove', { id });

/** Plan d'import (miroir de `ImportPlanOut`) : aucun secret, seulement ce qui diffère. */
export interface ImportItem {
  name: string;
  kind: 'new' | 'identical' | 'differs';
  login_differs: boolean;
  password_differs: boolean;
}
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
  return code === 'quarantined' || code === 'unwritable' ? `notice.${code}` : null;
}

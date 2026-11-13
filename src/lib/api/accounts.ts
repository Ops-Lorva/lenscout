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

import { invoke } from '@tauri-apps/api/core';

/** Miroir de `Account` (accounts.rs). Aucun mot de passe ne revient jamais de Rust. */
export interface Account {
  id: string;
  name: string;
  login: string;
}

export const ACCOUNT_KEY = 'lenscout.account';

export const listAccounts = () => invoke<Account[]>('cmd_accounts_list');
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

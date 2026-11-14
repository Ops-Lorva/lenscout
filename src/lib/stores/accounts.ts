import { get, writable } from 'svelte/store';
import { listAccounts, type AccountEntry } from '$lib/api/accounts';

/**
 * Comptes, partagés par tous les écrans (onglets gardés montés) : `null`
 * tant que la liste n'est pas chargée. L'écran Comptes la rafraîchit après
 * un ajout, une modification, une suppression ou un import, et chaque
 * sélecteur suit.
 */
export const accountList = writable<AccountEntry[] | null>(null);

let loading: Promise<void> | null = null;

/** Relit la liste ; l'erreur remonte, la liste en place reste. */
export async function refreshAccounts(): Promise<void> {
  accountList.set(await listAccounts());
}

/** Premier chargement (rien si la liste est là), partagé entre les écrans qui le demandent ensemble. */
export function ensureAccounts(): Promise<void> {
  if (get(accountList) !== null) return Promise.resolve();
  loading ??= refreshAccounts().finally(() => (loading = null));
  return loading;
}

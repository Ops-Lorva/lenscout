import { get } from 'svelte/store';
import { beforeEach, expect, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import { accountList, ensureAccounts, refreshAccounts } from './accounts';

beforeEach(() => {
  invoke.mockReset();
  accountList.set(null);
});

const a = (id: string) => ({ id, name: id, login: 'r', has_secret: true });

test('un seul chargement partagé : chaque écran lit la même liste', async () => {
  invoke.mockResolvedValue([a('x')]);
  await Promise.all([ensureAccounts(), ensureAccounts()]);
  expect(invoke).toHaveBeenCalledTimes(1);
  expect(get(accountList)?.map((x) => x.id)).toEqual(['x']);
  await ensureAccounts();
  expect(invoke).toHaveBeenCalledTimes(1);
});

test('après un ajout, un import ou une suppression, tous les sélecteurs voient la nouvelle liste', async () => {
  invoke.mockResolvedValueOnce([a('x')]).mockResolvedValueOnce([a('x'), a('y')]);
  await ensureAccounts();
  await refreshAccounts();
  expect(invoke).toHaveBeenLastCalledWith('cmd_accounts_list');
  expect(get(accountList)?.map((x) => x.id)).toEqual(['x', 'y']);
});

test('échec : l’erreur remonte, la liste reste', async () => {
  invoke.mockResolvedValueOnce([a('x')]).mockRejectedValueOnce('io');
  await refreshAccounts();
  await expect(refreshAccounts()).rejects.toBe('io');
  expect(get(accountList)?.map((x) => x.id)).toEqual(['x']);
});

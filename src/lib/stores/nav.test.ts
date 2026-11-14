import { get } from 'svelte/store';
import { beforeEach, expect, test } from 'vitest';
import { clearStatusIf, initialPage, status, suspendStep, type Status } from './nav';

beforeEach(() => status.set(null));

test('initialPage lit le fragment, sinon Réseau', () => {
  expect(initialPage('#settings')).toBe('settings');
  expect(initialPage('#accounts')).toBe('accounts');
  expect(initialPage('#ailleurs')).toBe('network');
  expect(initialPage('')).toBe('network');
});

test('clearStatusIf n’efface que le message qu’on a posé soi-même', () => {
  const scan: Status = { text: 'Recherche sur en0' };
  status.set(scan);
  clearStatusIf(scan);
  expect(get(status)).toBeNull();

  const other: Status = { text: '4 comptes exportés', tone: 'ok' };
  status.set(other);
  clearStatusIf(scan);
  expect(get(status)).toBe(other);
  clearStatusIf(null);
  expect(get(status)).toBe(other);
});

test('flux du Cadrage : suspendu quand l’onglet se cache, repris au retour', () => {
  expect(suspendStep(false, true, false)).toBe('suspend');
  expect(suspendStep(true, false, true)).toBe('resume');
  // Rien en cours, ou déjà dans le bon état : rien à faire.
  expect(suspendStep(false, false, false)).toBe('none');
  expect(suspendStep(true, true, false)).toBe('none');
  expect(suspendStep(true, false, false)).toBe('none');
});

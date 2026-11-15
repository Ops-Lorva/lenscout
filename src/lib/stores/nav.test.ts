import { get } from 'svelte/store';
import { beforeEach, expect, test } from 'vitest';
import { clearStatusIf, initialPage, openOperations, opsRequest, page, PAGES, status, suspendStep, type Status } from './nav';

beforeEach(() => status.set(null));

test('initialPage lit le fragment, sinon Réseau', () => {
  expect(initialPage('#settings')).toBe('settings');
  expect(initialPage('#accounts')).toBe('accounts');
  expect(initialPage('#operations')).toBe('operations');
  expect(initialPage('#ailleurs')).toBe('network');
  expect(initialPage('')).toBe('network');
});

test('clearStatusIf n’efface que le message qu’on a posé soi-même', () => {
  const scan: Status = { text: { key: 'network.scanning', values: { iface: 'en0', count: 0 } } };
  status.set(scan);
  clearStatusIf(scan);
  expect(get(status)).toBeNull();

  const other: Status = { text: { key: 'accounts.exported', values: { count: 4 } }, tone: 'ok' };
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

test('Opérations vient juste après Comptes', () => {
  expect(PAGES.indexOf('operations')).toBe(PAGES.indexOf('accounts') + 1);
});

test('« IP en lot » ouvre Opérations sur Renuméroter', () => {
  page.set('network');
  opsRequest.set(null);
  openOperations('renumber');
  expect(get(page)).toBe('operations');
  expect(get(opsRequest)).toBe('renumber');
});

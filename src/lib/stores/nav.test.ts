import { get } from 'svelte/store';
import { beforeEach, expect, test } from 'vitest';
import {
  clearStatusIf, framingRequest, initialPage, openFraming, openOperations, openSite, opsRequest, page, PAGES, siteRequest, status, suspendStep, type Status,
} from './nav';

beforeEach(() => status.set(null));

test('initialPage lit le fragment, sinon Réseau', () => {
  expect(initialPage('#settings')).toBe('settings');
  expect(initialPage('#accounts')).toBe('accounts');
  expect(initialPage('#operations')).toBe('operations');
  expect(initialPage('#site')).toBe('site');
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

test('Site entre Comptes et Opérations', () => {
  expect(PAGES.indexOf('site')).toBe(PAGES.indexOf('accounts') + 1);
  expect(PAGES.indexOf('operations')).toBe(PAGES.indexOf('site') + 1);
});

test('« Voir le site » ouvre Site sur ce compte', () => {
  page.set('accounts');
  siteRequest.set(null);
  openSite('acc-1');
  expect(get(page)).toBe('site');
  expect(get(siteRequest)).toBe('acc-1');
});

test('une caméra du relevé ouvre Cadrage avec son IP et le compte du site', () => {
  page.set('site');
  framingRequest.set(null);
  openFraming('192.168.1.64', 'acc-1');
  expect(get(page)).toBe('framing');
  expect(get(framingRequest)).toEqual({ ip: '192.168.1.64', accountId: 'acc-1' });
});

test('« IP en lot » ouvre Opérations sur Renuméroter', () => {
  page.set('network');
  opsRequest.set(null);
  openOperations('renumber');
  expect(get(page)).toBe('operations');
  expect(get(opsRequest)).toBe('renumber');
});

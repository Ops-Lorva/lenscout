import { get } from 'svelte/store';
import { beforeEach, expect, test } from 'vitest';
import { clearStatusIf, initialPage, status, type Status } from './nav';

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

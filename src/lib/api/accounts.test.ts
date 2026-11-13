import { expect, test } from 'vitest';
import { noticeKey, passwordRequired, pickAccount } from './accounts';
import { errorKey } from './errors';

const list = [
  { id: 'a', name: 'A', login: 'root' },
  { id: 'b', name: 'B', login: 'admin' },
];

test('le dernier choix est repris s’il existe encore', () => {
  expect(pickAccount(list, 'b')).toBe('b');
});

test('un choix disparu ou absent retombe sur le premier compte', () => {
  expect(pickAccount(list, 'zzz')).toBe('a');
  expect(pickAccount(list, '')).toBe('a');
});

test('aucun compte : aucun choix', () => {
  expect(pickAccount([], 'a')).toBe('');
});

test('les codes de comptes ont leur libellé', () => {
  for (const code of ['empty_field', 'duplicate_name', 'not_found', 'secret_missing', 'keyring', 'io']) {
    expect(errorKey(code)).toBe(`error.${code}`);
  }
});

test('le mot de passe est obligatoire en création et pour un compte sans secret', () => {
  expect(passwordRequired(null)).toBe(true);
  expect(passwordRequired({ id: 'a', name: 'A', login: 'r', has_secret: false })).toBe(true);
  expect(passwordRequired({ id: 'a', name: 'A', login: 'r', has_secret: true })).toBe(false);
});

test('le signalement de démarrage a son libellé, un code inconnu est ignoré', () => {
  expect(noticeKey('quarantined')).toBe('notice.quarantined');
  expect(noticeKey('unwritable')).toBe('notice.unwritable');
  expect(noticeKey(null)).toBeNull();
  expect(noticeKey('autre')).toBeNull();
});

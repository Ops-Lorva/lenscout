import { expect, test } from 'vitest';
import { pickAccount } from './accounts';
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

import { expect, test } from 'vitest';
import { errorKey } from './errors';

test('un code connu a son libellé', () => {
  expect(errorKey('iface_unknown')).toBe('error.iface_unknown');
  expect(errorKey('bad_ip')).toBe('error.bad_ip');
});

test('un code inconnu ou un message brut tombe sur le libellé générique', () => {
  expect(errorKey('quelque chose de brut')).toBe('error.unknown');
  expect(errorKey(new Error('x'))).toBe('error.unknown');
});

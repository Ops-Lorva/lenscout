import { expect, test } from 'vitest';
import { shouldShow, type UpdateInfo } from './update';

const info: UpdateInfo = {
  current_version: '0.1.0',
  latest_version: '0.2.0',
  has_update: true,
  asset_url: 'https://example.test/a',
  asset_name: 'a',
  platform_supported: true,
  release_notes_url: null,
};

test('une version plus récente est annoncée', () => {
  expect(shouldShow(info, null)).toBe(true);
});

test('pas de mise à jour, pas de bandeau', () => {
  expect(shouldShow({ ...info, has_update: false }, null)).toBe(false);
  expect(shouldShow(null, null)).toBe(false);
});

test('une version écartée ne revient pas, la suivante oui', () => {
  expect(shouldShow(info, '0.2.0')).toBe(false);
  expect(shouldShow({ ...info, latest_version: '0.3.0' }, '0.2.0')).toBe(true);
});

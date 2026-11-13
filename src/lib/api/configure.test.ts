import { expect, test } from 'vitest';
import type { Camera } from './types';
import { canAct, canChangeIp, orNull, resultMessage, splitList, timeZones, defaultTimeZone } from './configure';

const cam = (family: Camera['family'], ip = '10.0.50.11'): Camera => ({
  ip, mac: null, family, brand: null, model: null, serial: null, firmware: null,
  activation: 'new', http_port: 80, sources: ['mdns'],
});

test('aucun bouton sans sélection', () => {
  expect(canAct([])).toBe(false);
  expect(canChangeIp([])).toBe(false);
});

test('une caméra « autre » grise toutes les actions', () => {
  expect(canAct([cam('axis'), cam('other')])).toBe(false);
  expect(canAct([cam('other')])).toBe(false);
  expect(canChangeIp([cam('other')])).toBe(false);
});

test('Hikvision reste grisée tant que la tâche 14 n’a pas ouvert la marque', () => {
  expect(canAct([cam('hikvision')])).toBe(false);
});

test('IP : une seule Axis', () => {
  expect(canAct([cam('axis'), cam('axis', '10.0.50.12')])).toBe(true);
  expect(canChangeIp([cam('axis'), cam('axis', '10.0.50.12')])).toBe(false);
  expect(canChangeIp([cam('axis')])).toBe(true);
});

test('un message par code d’erreur, le texte brut seulement pour un refus', () => {
  expect(resultMessage({ key: 'k', ok: true, error: null })).toBeNull();
  expect(resultMessage({ key: 'k', ok: false, error: { code: 'identity_mismatch' } })).toEqual({ key: 'error.identity_mismatch' });
  expect(resultMessage({ key: 'k', ok: false, error: { code: 'unreachable', ip: '10.0.50.11' } })).toEqual({ key: 'error.unreachable' });
  expect(resultMessage({ key: 'k', ok: false, error: { code: 'rejected', detail: 'Error: x' } })).toEqual({ key: 'error.rejected', detail: 'Error: x' });
});

test('champs libres : virgules, espaces et lignes', () => {
  expect(splitList('a.example, b.example\n c.example ')).toEqual(['a.example', 'b.example', 'c.example']);
  expect(splitList('  ')).toEqual([]);
  expect(orNull(' ')).toBeNull();
  expect(orNull(' 10.0.0.1 ')).toBe('10.0.0.1');
});

test('fuseaux : jamais vide, fuseau du poste s’il est listé', () => {
  const zones = timeZones();
  expect(zones.length).toBeGreaterThan(0);
  expect(defaultTimeZone(['A/B'])).toBe('A/B');
  expect(defaultTimeZone([])).toBe('UTC');
});

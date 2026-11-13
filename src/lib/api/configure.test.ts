import { expect, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import type { Camera } from './types';
import { applyAction, dialogAfterSelection, canActivate, outsideSubnet, canAct, canChangeIp, orNull, resultMessage, splitList, timeZones, defaultTimeZone } from './configure';

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
  expect(resultMessage({ key: 'k', ok: false, error: { code: 'identity_mismatch' } })).toEqual({ key: 'configure.error.identity_mismatch', values: {} });
  expect(resultMessage({ key: 'k', ok: false, error: { code: 'unreachable', ip: '10.0.50.11' } })).toEqual({ key: 'configure.error.unreachable', values: {} });
  expect(resultMessage({ key: 'k', ok: false, error: { code: 'rejected', detail: 'Error: x' } })).toEqual({ key: 'configure.error.rejected', values: { detail: 'Error: x' } });
});

test('erreurs d’IP temporaire : espace elevation, adresse en paramètre', () => {
  expect(resultMessage({ key: 'k', ok: false, error: { code: 'elevation_refused', ip: '169.254.10.20' } })).toEqual({
    key: 'elevation.refused',
    values: { ip: '169.254.10.20' },
  });
  expect(resultMessage({ key: 'k', ok: false, error: { code: 'temp_ip_failed' } })).toEqual({ key: 'elevation.failed', values: {} });
  expect(resultMessage({ key: 'k', ok: false, error: { code: 'temp_ip_busy' } })).toEqual({ key: 'elevation.busy', values: {} });
  expect(resultMessage({ key: 'k', ok: false, error: { code: 'temp_ip_left', ip: '169.254.7.7' } })).toEqual({
    key: 'elevation.left',
    values: { ip: '169.254.7.7' },
  });
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

test('« Activer » grisé quand toutes les caméras sont déjà activées', () => {
  const done = (ip: string): Camera => ({ ...cam('axis', ip), activation: 'activated' });
  expect(canActivate([done('10.0.50.11'), done('10.0.50.12')])).toBe(false);
  expect(canActivate([done('10.0.50.11'), cam('axis', '10.0.50.12')])).toBe(true);
  expect(canActivate([{ ...cam('axis'), activation: 'unknown' }])).toBe(true);
  expect(canActivate([])).toBe(false);
  expect(canActivate([cam('other')])).toBe(false);
});

test('hors du sous-réseau du poste : masque appliqué aux deux adresses', () => {
  expect(outsideSubnet('10.0.50.20', '10.0.50.2', '255.255.255.0')).toBe(false);
  expect(outsideSubnet('10.0.51.20', '10.0.50.2', '255.255.255.0')).toBe(true);
  expect(outsideSubnet('10.0.51.20', '10.0.50.2', '255.255.254.0')).toBe(false);
  // champ en cours de saisie, ou détails absents : pas d'avertissement
  expect(outsideSubnet('10.0.5', '10.0.50.2', '255.255.255.0')).toBe(false);
  expect(outsideSubnet('10.0.50.20', null, null)).toBe(false);
});

test('les nouveaux codes ont un message', () => {
  for (const code of ['identity_unreadable', 'camera_off_subnet', 'camera_not_seen', 'already_activated', 'network_needs_one_camera'] as const) {
    expect(resultMessage({ key: 'k', ok: false, error: { code } })).toEqual({ key: `configure.error.${code}`, values: {} });
  }
});

test('aucune caméra : rien n’est envoyé à Rust', async () => {
  invoke.mockClear();
  await expect(applyAction([], 'a', { kind: 'activate' }, 'eth0')).rejects.toBe('no_cameras');
  expect(invoke).not.toHaveBeenCalled();
  invoke.mockResolvedValue([]);
  await applyAction([cam('axis')], 'a', { kind: 'activate' }, 'eth0');
  expect(invoke).toHaveBeenCalledTimes(1);
});

test('le dialogue se ferme quand la sélection devient vide', () => {
  expect(dialogAfterSelection('network', [])).toBeNull();
  expect(dialogAfterSelection('network', [cam('axis')])).toBe('network');
  expect(dialogAfterSelection(null, [cam('axis')])).toBeNull();
});

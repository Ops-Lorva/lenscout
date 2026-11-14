import { expect, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import { get } from 'svelte/store';
import type { Camera } from './types';
import { canReset, rescanDelaysAfter, RESET_RESCAN_DELAYS_MS, resetLine, activateCleartext, cleartextPending, pendingAfterConfirm, pendingAfterRun, mergeResults, actionResults, applyAction, canBatchIp, batchErrorMessage, batchFingerprint, batchPreview, batchApply, dialogAfterSelection, canActivate, outsideSubnet, canAct, canChangeIp, orNull, resultMessage, splitList, timeZones, defaultTimeZone } from './configure';

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
  expect(resultMessage({ key: 'k', ok: false, error: { code: 'invalid', reason: 'gateway_is_ip' } })).toEqual({ key: 'configure.invalid.gateway_is_ip', values: {} });
  expect(resultMessage({ key: 'k', ok: false, error: { code: 'http_status', status: 500 } })).toEqual({ key: 'configure.error.http_status', values: { status: '500' } });
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

test('« Activer » grisé seulement si toutes les caméras sont lues activées', () => {
  const done = (ip: string): Camera => ({ ...cam('axis', ip), activation: 'activated' });
  expect(canActivate([done('10.0.50.11'), done('10.0.50.12')])).toBe(false);
  expect(canActivate([done('10.0.50.11'), cam('axis', '10.0.50.12')])).toBe(true);
  // Inconnue (hors sous-réseau au scan) : Rust relit l'état au moment de l'action.
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
  for (const code of ['identity_unreadable', 'camera_off_subnet', 'camera_not_seen', 'already_activated', 'network_needs_one_camera', 'activation_cleartext', 'not_new', 'mac_not_axis'] as const) {
    expect(resultMessage({ key: 'k', ok: false, error: { code } })).toEqual({ key: `configure.error.${code}`, values: {} });
  }
});

test('https injoignable : les caméras à confirmer, une par une', () => {
  const a = { ...cam('axis', '10.0.50.11'), mac: 'AC:CC:8E:00:00:01' };
  const b = { ...cam('axis', '10.0.50.12'), mac: 'AC:CC:8E:00:00:02' };
  const c = cam('axis', '10.0.50.13');
  const results = [
    { key: 'AC:CC:8E:00:00:01', ok: false, error: { code: 'activation_cleartext' as const } },
    { key: 'AC:CC:8E:00:00:02', ok: true, error: null },
    { key: '10.0.50.13', ok: false, error: { code: 'activation_cleartext' as const } },
  ];
  expect(cleartextPending(results, [a, b, c])).toEqual([a, c]);
  expect(cleartextPending([], [a])).toEqual([]);
});

test('dialogue d’activation : il reste ouvert tant qu’une caméra attend sa confirmation', () => {
  const a = { ...cam('axis', '10.0.50.11'), mac: 'AC:CC:8E:00:00:01' };
  const b = { ...cam('axis', '10.0.50.12'), mac: 'AC:CC:8E:00:00:02' };
  const wait = (key: string) => ({ key, ok: false, error: { code: 'activation_cleartext' as const } });
  const ok = (key: string) => ({ key, ok: true, error: null });
  // Activation : seules les caméras en attente restent, le dialogue avec elles.
  expect(pendingAfterRun({ kind: 'activate' }, [wait(a.mac), ok(b.mac)], [a, b])).toEqual([a]);
  expect(pendingAfterRun({ kind: 'activate' }, [ok(a.mac), ok(b.mac)], [a, b])).toEqual([]);
  // Une autre action ne demande jamais de confirmation.
  expect(pendingAfterRun({ kind: 'network_dhcp' }, [wait(a.mac)], [a])).toEqual([]);
  // Une confirmation retire sa seule caméra, quel que soit son résultat.
  expect(pendingAfterConfirm([a, b], a)).toEqual([b]);
  expect(pendingAfterConfirm([b], b)).toEqual([]);
});

test('envoi en clair confirmé : une seule caméra, le drapeau pour elle seule', async () => {
  invoke.mockClear();
  invoke.mockResolvedValue([{ key: '10.0.50.11', ok: true, error: null }]);
  const one = cam('axis');
  await activateCleartext(one, 'acc', 'eth0');
  expect(invoke).toHaveBeenCalledWith('cmd_apply_action', {
    cameras: [one],
    accountId: 'acc',
    action: { kind: 'activate', allow_cleartext: true },
    iface: 'eth0',
  });
});

test('le résultat d’une confirmation remplace la pastille de sa seule caméra', () => {
  actionResults.set(new Map());
  mergeResults([
    { key: 'a', ok: false, error: { code: 'activation_cleartext' } },
    { key: 'b', ok: true, error: null },
  ]);
  mergeResults([{ key: 'a', ok: true, error: null }]);
  const m = get(actionResults);
  expect(m.get('a')?.ok).toBe(true);
  expect(m.get('b')?.ok).toBe(true);
  expect(m.size).toBe(2);
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

test('lot : deux Axis au moins, jamais une marque sans action', () => {
  expect(canBatchIp([cam('axis')])).toBe(false);
  expect(canBatchIp([cam('axis'), cam('axis', '10.0.50.12')])).toBe(true);
  expect(canBatchIp([cam('axis'), cam('hikvision', '10.0.50.12')])).toBe(false);
  expect(canBatchIp([cam('axis'), cam('other', '10.0.50.12')])).toBe(false);
});

test('lot : un message par code, l’adresse en paramètre', () => {
  expect(batchErrorMessage({ code: 'ip_in_use', ip: '10.0.50.12', mac: null })).toEqual({
    key: 'batch.error.ip_in_use',
    values: { ip: '10.0.50.12' },
  });
  expect(batchErrorMessage({ code: 'range_overflow' })).toEqual({ key: 'batch.error.range_overflow', values: {} });
  expect(batchErrorMessage('preview_expired')).toEqual({ key: 'configure.error.preview_expired', values: {} });
  expect(batchErrorMessage('???')).toEqual({ key: 'configure.error.unknown', values: {} });
});

test('lot : l’empreinte change avec un champ ou la sélection', () => {
  const f = { iface: 'eth0', start: '10.0.50.11', mask: '255.255.255.0', gateway: '', dns: '' };
  const a = [cam('axis'), cam('axis', '10.0.50.12')];
  const base = batchFingerprint(a, f);
  expect(batchFingerprint(a, { ...f, start: ' 10.0.50.11 ' })).toBe(base);
  expect(batchFingerprint(a, { ...f, start: '10.0.50.20' })).not.toBe(base);
  expect(batchFingerprint(a, { ...f, gateway: '10.0.50.1' })).not.toBe(base);
  expect(batchFingerprint(a, { ...f, dns: '1.1.1.1' })).not.toBe(base);
  expect(batchFingerprint(a, { ...f, iface: 'wlan0' })).not.toBe(base);
  expect(batchFingerprint(a.slice(0, 1), f)).not.toBe(base);
  expect(batchFingerprint([a[1], a[0]], f)).not.toBe(base);
  // Un autre compte, d'autres IP exclues : l'aperçu n'est plus le bon.
  expect(batchFingerprint(a, { ...f, accountId: 'b' })).not.toBe(batchFingerprint(a, { ...f, accountId: 'a' }));
});

test('lot : liste vide jamais envoyée, aperçu et application passent par Rust', async () => {
  invoke.mockClear();
  const req = { start: '10.0.50.11', mask: '255.255.255.0', gateway: null, dns: [] };
  await expect(batchPreview([], [], req, 'eth0', 'acc')).rejects.toBe('no_cameras');
  expect(invoke).not.toHaveBeenCalled();
  invoke.mockResolvedValue({ id: 'x', rows: [] });
  await batchPreview([cam('axis')], [], req, 'eth0', 'acc');
  expect(invoke).toHaveBeenCalledWith('cmd_batch_preview', { selection: [cam('axis')], others: [], req, iface: 'eth0', accountId: 'acc' });
  await batchPreview([cam('axis')], [], req, 'eth0', '');
  expect(invoke).toHaveBeenLastCalledWith('cmd_batch_preview', { selection: [cam('axis')], others: [], req, iface: 'eth0', accountId: null });
  await batchApply('x', 'acc', 'eth0');
  expect(invoke).toHaveBeenLastCalledWith('cmd_batch_apply', { previewId: 'x', accountId: 'acc', iface: 'eth0' });
});

test('réinitialisation : Axis et Hikvision, une ou plusieurs ; jamais une autre marque', () => {
  expect(canReset([cam('axis')])).toBe(true);
  expect(canReset([cam('axis'), cam('hikvision', '10.0.50.12')])).toBe(true);
  expect(canReset([cam('axis'), cam('other', '10.0.50.12')])).toBe(false);
  expect(canReset([])).toBe(false);
});

test('après une réinitialisation, le rescan attend le redémarrage de la caméra', () => {
  expect(rescanDelaysAfter('factory_reset')).toEqual(RESET_RESCAN_DELAYS_MS);
  expect(Math.min(...RESET_RESCAN_DELAYS_MS)).toBeGreaterThanOrEqual(60_000);
  // Changement d’IP : le rescan habituel, rapide.
  expect(rescanDelaysAfter('network_static')).toEqual([3000, 15000]);
  expect(rescanDelaysAfter('batch')).toEqual([3000, 15000]);
});

test('la confirmation rappelle nom, IP et MAC de chaque caméra', () => {
  const c = { ...cam('axis'), brand: 'AXIS', model: 'P4705-PLVE', mac: 'AC:CC:8E:12:34:56' };
  expect(resetLine(c)).toEqual({ name: 'AXIS P4705-PLVE', ip: '10.0.50.11', mac: 'AC:CC:8E:12:34:56' });
  expect(resetLine(cam('hikvision'))).toEqual({ name: '—', ip: '10.0.50.11', mac: '—' });
});

test('la réinitialisation part avec son mode', async () => {
  invoke.mockClear();
  invoke.mockResolvedValue([]);
  await applyAction([cam('axis')], 'acc', { kind: 'factory_reset', mode: 'keep_ip' }, 'eth0');
  expect(invoke).toHaveBeenLastCalledWith('cmd_apply_action', {
    cameras: [cam('axis')], accountId: 'acc', action: { kind: 'factory_reset', mode: 'keep_ip' }, iface: 'eth0',
  });
});

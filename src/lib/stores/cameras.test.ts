import { get } from 'svelte/store';
import { beforeEach, expect, test } from 'vitest';
import type { Camera } from '#lib/api/types.ts';
import { cameras, clear, clearCameras, markActivated, markAddressing, query, selectedCameras, selection, setAddressing, shouldAutoScan, sort, sortCameras, toggleSort, upsert, visibleCameras } from './cameras';

const cam = (over: Partial<Camera>): Camera => ({
  ip: '10.0.50.5',
  mac: 'AA:BB:CC:00:00:01',
  family: 'axis',
  brand: 'Axis',
  model: null,
  serial: null,
  firmware: null,
  activation: 'unknown',
  http_port: 80,
  sources: ['mdns'],
  ...over,
});

beforeEach(() => {
  clear();
  query.set('');
  sort.set({ col: 'ip', dir: 'asc' });
});

test('upsert garde une ligne par MAC et met à jour', () => {
  upsert(cam({ firmware: '10.0' }));
  upsert(cam({ firmware: '11.2' }));
  const list = get(cameras);
  expect(list).toHaveLength(1);
  expect(list[0].firmware).toBe('11.2');
});

test('liste triée par IP numérique', () => {
  upsert(cam({ ip: '10.0.50.10', mac: 'AA:BB:CC:00:00:0A' }));
  upsert(cam({ ip: '10.0.50.9', mac: 'AA:BB:CC:00:00:09' }));
  upsert(cam({ ip: '10.0.9.200', mac: 'AA:BB:CC:00:00:C8' }));
  expect(get(cameras).map((c) => c.ip)).toEqual(['10.0.9.200', '10.0.50.9', '10.0.50.10']);
});

test('une caméra qui change d’IP reste une seule ligne', () => {
  upsert(cam({ ip: '10.0.50.5' }));
  upsert(cam({ ip: '10.0.50.77' }));
  const list = get(cameras);
  expect(list).toHaveLength(1);
  expect(list[0].ip).toBe('10.0.50.77');
});

test('une caméra vue d’abord sans MAC fusionne quand son MAC arrive', () => {
  upsert(cam({ mac: null }));
  upsert(cam({}));
  expect(get(cameras)).toHaveLength(1);
});

test('sans MAC, la clé est l’IP', () => {
  upsert(cam({ mac: null, ip: '10.0.50.1' }));
  upsert(cam({ mac: null, ip: '10.0.50.2' }));
  expect(get(cameras)).toHaveLength(2);
});

test('selectedCameras suit l’ordre affiché, pas l’ordre de clic', () => {
  upsert(cam({ ip: '10.0.50.9', mac: 'AA:BB:CC:00:00:09' }));
  upsert(cam({ ip: '10.0.50.10', mac: 'AA:BB:CC:00:00:0A' }));
  upsert(cam({ ip: '10.0.50.11', mac: null }));
  selection.set(new Set(['10.0.50.11', 'AA:BB:CC:00:00:0A', 'AA:BB:CC:00:00:09']));
  expect(get(selectedCameras).map((c) => c.ip)).toEqual(['10.0.50.9', '10.0.50.10', '10.0.50.11']);
});

test('clear vide la liste et la sélection', () => {
  upsert(cam({}));
  selection.set(new Set(['AA:BB:CC:00:00:01']));
  clear();
  expect(get(cameras)).toEqual([]);
  expect(get(selection).size).toBe(0);
});

test('une caméra masquée par la recherche n’est plus sélectionnée', () => {
  upsert(cam({ ip: '10.0.50.1', mac: 'AA:BB:CC:00:00:01' }));
  upsert(cam({ ip: '10.0.50.2', mac: 'AA:BB:CC:00:00:02' }));
  selection.set(new Set(['AA:BB:CC:00:00:01', 'AA:BB:CC:00:00:02']));
  query.set('10.0.50.2');
  expect(get(selectedCameras).map((c) => c.ip)).toEqual(['10.0.50.2']);
  query.set('');
  expect(get(selectedCameras)).toHaveLength(2);
});

test('la clé de sélection passe de l’IP au MAC avec la caméra', () => {
  upsert(cam({ mac: null }));
  selection.set(new Set(['10.0.50.5']));
  upsert(cam({}));
  expect([...get(selection)]).toEqual(['AA:BB:CC:00:00:01']);
  expect(get(selectedCameras)).toHaveLength(1);
});

test('au retour sur la page, pas de scan automatique si une liste existe', () => {
  expect(shouldAutoScan(get(cameras))).toBe(true);
  upsert(cam({}));
  expect(shouldAutoScan(get(cameras))).toBe(false);
});

test('un rescan différé remplace les caméras et garde la sélection', () => {
  upsert(cam({ ip: '10.0.50.5' }));
  selection.set(new Set(['AA:BB:CC:00:00:01']));
  clearCameras();
  expect(get(cameras)).toHaveLength(0);
  expect(get(selection).size).toBe(1);
  // la caméra reparaît à une autre IP : sa clé (MAC) est toujours cochée
  upsert(cam({ ip: '10.0.50.99' }));
  expect(get(selectedCameras).map((c) => c.ip)).toEqual(['10.0.50.99']);
});

test('une caméra qui ne reparaît pas n’est plus dans la sélection effective', () => {
  upsert(cam({}));
  selection.set(new Set(['AA:BB:CC:00:00:01']));
  clearCameras();
  expect(get(selectedCameras)).toEqual([]);
});

test('l’adressage lu après le scan se pose sur la caméra de cette adresse, sans rien écraser d’autre', () => {
  upsert(cam({ ip: '10.0.50.11', mac: 'AA:BB:CC:00:00:0B', firmware: '11.2' }));
  upsert(cam({ ip: '10.0.50.12', mac: 'AA:BB:CC:00:00:0C', addressing: 'static' }));
  setAddressing([{ ip: '10.0.50.11', addressing: 'dhcp' }, { ip: '10.0.50.99', addressing: 'static' }]);
  const list = get(cameras);
  expect(list).toHaveLength(2);
  expect(list[0]).toMatchObject({ ip: '10.0.50.11', addressing: 'dhcp', firmware: '11.2' });
  // Pas de lecture pour .12 : ce qu’on savait reste.
  expect(list[1].addressing).toBe('static');
});

test('une activation réussie passe la ligne en « Activée », un échec ne change rien', () => {
  upsert(cam({ activation: 'new' }));
  upsert(cam({ mac: null, ip: '10.0.50.6', activation: 'new' }));
  upsert(cam({ mac: 'AA:BB:CC:00:00:07', ip: '10.0.50.7', activation: 'new' }));
  markActivated([
    { key: 'AA:BB:CC:00:00:01', ok: true, error: null },
    { key: '10.0.50.6', ok: true, error: null },
    { key: 'AA:BB:CC:00:00:07', ok: false, error: { code: 'auth_failed' } },
  ]);
  expect(get(cameras).map((c) => c.activation)).toEqual(['activated', 'activated', 'new']);
  // Clé inconnue : rien.
  markActivated([{ key: 'nope', ok: true, error: null }]);
  expect(get(cameras)).toHaveLength(3);
});

test('une IP posée par LenScout passe la ligne en « IP fixe » tout de suite, et le reste au rescan', () => {
  upsert(cam({ ip: '10.0.60.5', mac: 'AA:BB:CC:00:01:05' }));
  upsert(cam({ ip: '10.0.60.6', mac: 'AA:BB:CC:00:01:06' }));
  markAddressing(
    [
      { key: 'AA:BB:CC:00:01:05', ok: true, error: null },
      { key: 'AA:BB:CC:00:01:06', ok: false, error: { code: 'auth_failed' } },
    ],
    'static',
  );
  expect(get(cameras).map((c) => c.addressing ?? null)).toEqual(['static', null]);
  // Le rescan qui suit ne sait pas l'adressage : ce qu'on a posé reste.
  clearCameras();
  upsert(cam({ ip: '10.0.60.50', mac: 'AA:BB:CC:00:01:05' }));
  expect(get(cameras)[0].addressing).toBe('static');
  // Une lecture avec le compte fait foi.
  setAddressing([{ ip: '10.0.60.50', addressing: 'dhcp' }]);
  clearCameras();
  upsert(cam({ ip: '10.0.60.50', mac: 'AA:BB:CC:00:01:05' }));
  expect(get(cameras)[0].addressing ?? null).toBeNull();
});

test('passage en DHCP : la ligne prend « DHCP » ; une caméra sans MAC suit sa nouvelle IP', () => {
  upsert(cam({ ip: '10.0.61.5', mac: 'AA:BB:CC:00:02:05', addressing: 'static' }));
  markAddressing([{ key: 'AA:BB:CC:00:02:05', ok: true, error: null }], 'dhcp');
  expect(get(cameras)[0].addressing).toBe('dhcp');
  // Vue à travers le routeur : la clé est l'IP, elle change avec elle.
  upsert(cam({ ip: '10.0.62.11', mac: null }));
  markAddressing([{ key: '10.0.62.11', ok: true, error: null }], 'static', { '10.0.62.11': '10.0.62.40' });
  expect(get(cameras).find((c) => c.ip === '10.0.62.11')?.addressing).toBe('static');
  clearCameras();
  upsert(cam({ ip: '10.0.62.40', mac: null }));
  expect(get(cameras)[0].addressing).toBe('static');
});

// --- Tri par colonne ---

const ips = (list: Camera[]) => list.map((c) => c.ip);

test('tri par IP : numérique, pas lexicographique, dans les deux sens', () => {
  const a = cam({ ip: '10.0.50.9', mac: 'AA:BB:CC:00:00:09' });
  const b = cam({ ip: '10.0.50.10', mac: 'AA:BB:CC:00:00:0A' });
  const c = cam({ ip: '10.0.9.200', mac: 'AA:BB:CC:00:00:C8' });
  expect(ips(sortCameras([a, b, c], { col: 'ip', dir: 'asc' }))).toEqual(['10.0.9.200', '10.0.50.9', '10.0.50.10']);
  expect(ips(sortCameras([a, b, c], { col: 'ip', dir: 'desc' }))).toEqual(['10.0.50.10', '10.0.50.9', '10.0.9.200']);
});

test('tri par N° de série, asc et desc', () => {
  const a = cam({ ip: '10.0.50.1', mac: 'AA:BB:CC:00:00:01', serial: 'B100' });
  const b = cam({ ip: '10.0.50.2', mac: 'AA:BB:CC:00:00:02', serial: 'A200' });
  expect(sortCameras([a, b], { col: 'serial', dir: 'asc' }).map((c) => c.serial)).toEqual(['A200', 'B100']);
  expect(sortCameras([a, b], { col: 'serial', dir: 'desc' }).map((c) => c.serial)).toEqual(['B100', 'A200']);
});

test('valeurs manquantes (série) rangées en fin, quel que soit le sens', () => {
  const withSerial = cam({ ip: '10.0.50.2', mac: 'AA:BB:CC:00:00:02', serial: 'S1' });
  const noSerial = cam({ ip: '10.0.50.1', mac: 'AA:BB:CC:00:00:01', serial: null });
  expect(sortCameras([noSerial, withSerial], { col: 'serial', dir: 'asc' }).map((c) => c.serial)).toEqual(['S1', null]);
  expect(sortCameras([withSerial, noSerial], { col: 'serial', dir: 'desc' }).map((c) => c.serial)).toEqual(['S1', null]);
});

test('valeurs manquantes (MAC, firmware) rangées en fin', () => {
  const full = cam({ ip: '10.0.50.2', mac: 'AA:BB:CC:00:00:02', firmware: '11.0' });
  const bare = cam({ ip: '10.0.50.1', mac: null, declared_mac: null, firmware: null });
  expect(sortCameras([bare, full], { col: 'mac', dir: 'asc' })[0].ip).toBe('10.0.50.2');
  expect(sortCameras([bare, full], { col: 'mac', dir: 'desc' })[1].ip).toBe('10.0.50.1');
  expect(sortCameras([bare, full], { col: 'firmware', dir: 'asc' })[1].ip).toBe('10.0.50.1');
  expect(sortCameras([bare, full], { col: 'firmware', dir: 'desc' })[1].ip).toBe('10.0.50.1');
});

test('tri stable : à valeur de colonne égale, départage par IP croissante', () => {
  const a = cam({ ip: '10.0.50.20', mac: 'AA:BB:CC:00:00:14', firmware: '9.0' });
  const b = cam({ ip: '10.0.50.5', mac: 'AA:BB:CC:00:00:05', firmware: '9.0' });
  expect(ips(sortCameras([a, b], { col: 'firmware', dir: 'asc' }))).toEqual(['10.0.50.5', '10.0.50.20']);
  expect(ips(sortCameras([a, b], { col: 'firmware', dir: 'desc' }))).toEqual(['10.0.50.5', '10.0.50.20']);
});

test('tri par nom de caméra (brand/model), absence rangée en fin', () => {
  const zed = cam({ ip: '10.0.50.1', mac: 'AA:BB:CC:00:00:01', brand: 'Zed', model: null });
  const axis = cam({ ip: '10.0.50.2', mac: 'AA:BB:CC:00:00:02', brand: 'Axis', model: 'P1' });
  const none = cam({ ip: '10.0.50.3', mac: 'AA:BB:CC:00:00:03', brand: null, model: null });
  const r = sortCameras([zed, axis, none], { col: 'camera', dir: 'asc' });
  expect(r.map((c) => c.ip)).toEqual(['10.0.50.2', '10.0.50.1', '10.0.50.3']);
});

test('toggleSort : nouvelle colonne = asc, re-clic = inverse', () => {
  toggleSort('mac');
  expect(get(sort)).toEqual({ col: 'mac', dir: 'asc' });
  toggleSort('mac');
  expect(get(sort)).toEqual({ col: 'mac', dir: 'desc' });
  toggleSort('ip');
  expect(get(sort)).toEqual({ col: 'ip', dir: 'asc' });
});

test('visibleCameras applique le tri APRÈS le filtre d’onglet et la recherche', () => {
  upsert(cam({ ip: '10.0.50.10', mac: 'AA:BB:CC:00:00:0A', serial: 'C' }));
  upsert(cam({ ip: '10.0.50.9', mac: 'AA:BB:CC:00:00:09', serial: 'A' }));
  upsert(cam({ ip: '10.0.50.200', mac: 'AA:BB:CC:00:00:C8', serial: 'B' }));
  // Par défaut : IP croissante.
  expect(ips(get(visibleCameras))).toEqual(['10.0.50.9', '10.0.50.10', '10.0.50.200']);
  sort.set({ col: 'serial', dir: 'asc' });
  expect(get(visibleCameras).map((c) => c.serial)).toEqual(['A', 'B', 'C']);
  sort.set({ col: 'serial', dir: 'desc' });
  expect(get(visibleCameras).map((c) => c.serial)).toEqual(['C', 'B', 'A']);
});

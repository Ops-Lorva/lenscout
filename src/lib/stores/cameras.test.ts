import { get } from 'svelte/store';
import { beforeEach, expect, test } from 'vitest';
import type { Camera } from '#lib/api/types.ts';
import { cameras, clear, clearCameras, markActivated, markAddressing, query, selectedCameras, selection, setAddressing, shouldAutoScan, upsert } from './cameras';

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

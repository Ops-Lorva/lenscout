import { get } from 'svelte/store';
import { beforeEach, expect, test } from 'vitest';
import type { Camera } from '#lib/api/types.ts';
import { cameras, clear, clearCameras, query, selectedCameras, selection, shouldAutoScan, upsert } from './cameras';

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

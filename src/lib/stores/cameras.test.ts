import { get } from 'svelte/store';
import { beforeEach, expect, test } from 'vitest';
import type { Camera } from '$lib/api/types';
import { cameras, clear, selectedCameras, selection, upsert } from './cameras';

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

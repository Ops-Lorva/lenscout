import { describe, expect, test } from 'vitest';
import type { Camera } from './api/types';
import { filterCameras, matchesCamera, normalizeQuery } from './search';

function cam(over: Partial<Camera>): Camera {
  return {
    ip: '192.0.2.1',
    mac: null,
    family: 'axis',
    brand: 'Axis',
    model: null,
    serial: null,
    firmware: null,
    activation: 'unknown',
    http_port: 80,
    sources: ['mdns'],
    ...over,
  };
}

// 500 caméras, MAC toutes différentes, une seule AC:CC:8E:12:34:56.
const list500: Camera[] = Array.from({ length: 500 }, (_, i) => {
  const hex = (0xb0000000 + i).toString(16).toUpperCase().padStart(8, '0');
  const mac = `00:11:${hex.slice(0, 2)}:${hex.slice(2, 4)}:${hex.slice(4, 6)}:${hex.slice(6, 8)}`;
  return cam({ ip: `192.0.2.${i}`, mac });
});
list500[77] = cam({ ip: '10.0.50.77', mac: 'AC:CC:8E:12:34:56' });

describe('recherche', () => {
  test('les formats de MAC courants trouvent la même caméra', () => {
    for (const q of ['AC:CC:8E:12:34:56', 'ACCC8E123456', 'ac-cc-8e-12-34-56', 'accc.8e12.3456', '123456'])
      expect(filterCameras(list500, q).map((c) => c.ip)).toEqual(['10.0.50.77']);
  });

  test('la MAC déclarée (Axis vue à travers le routeur) se cherche comme la MAC', () => {
    const list = [...list500, cam({ ip: '10.0.20.11', sources: ['http'], declared_mac: 'B8:A4:4F:F5:10:EF' })];
    for (const q of ['B8:A4:4F:F5:10:EF', 'B8A44FF510EF', 'b8-a4-4f-f5-10-ef', 'b8a4.4ff5.10ef', 'F510EF'])
      expect(filterCameras(list, q).map((c) => c.ip)).toEqual(['10.0.20.11']);
  });

  test('n° de série avec ou sans tirets', () => {
    const list = [cam({ ip: '192.0.2.5', serial: 'ACCC-8E12-3456' }), cam({ ip: '192.0.2.6', serial: 'ZZZ' })];
    expect(filterCameras(list, 'accc8e123456').map((c) => c.ip)).toEqual(['192.0.2.5']);
    expect(filterCameras(list, 'accc-8e12').map((c) => c.ip)).toEqual(['192.0.2.5']);
  });

  test('IP et modèle : requête brute, insensible à la casse', () => {
    const list = [cam({ ip: '192.0.2.10', model: 'P3265-LVE' }), cam({ ip: '192.0.2.20', model: 'M1065' })];
    expect(filterCameras(list, '2.20').map((c) => c.ip)).toEqual(['192.0.2.20']);
    expect(filterCameras(list, 'p3265').map((c) => c.ip)).toEqual(['192.0.2.10']);
  });

  test('requête vide rend toute la liste, dans le même ordre', () => {
    expect(filterCameras(list500, '')).toEqual(list500);
    expect(filterCameras(list500, ' : - ')).toEqual(list500);
  });

  test('caméra sans MAC ni série : pas de plantage', () => {
    expect(matchesCamera(cam({}), 'abc')).toBe(false);
  });

  test('normalizeQuery nettoie séparateurs et casse', () => {
    expect(normalizeQuery(' ac:cc-8e.12 34 ')).toBe('ACCC8E1234');
  });
});

import { describe, expect, it, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke, Channel: class {} }));
import { addressingKey, cameraBrand, cameraName, readAddressing, shownMac, startScan } from './discovery';
import type { Camera } from './types';

const cam = (over: Partial<Camera>): Camera => ({
  ip: '10.0.50.11', mac: null, family: 'axis', brand: null, model: null, serial: null, firmware: null,
  activation: 'activated', http_port: 80, sources: ['mdns'], ...over,
});

test('adressage affiché : celui lu, DHCP d’usine pour une Axis neuve, sinon inconnu', () => {
  expect(addressingKey(cam({ addressing: 'dhcp' }))).toBe('network.addressing.dhcp');
  expect(addressingKey(cam({ addressing: 'static' }))).toBe('network.addressing.static');
  // Axis neuve : DHCP d’usine.
  expect(addressingKey(cam({ activation: 'new' }))).toBe('network.addressing.dhcp');
  // Activée sans lecture, ou état inconnu : on ne devine pas.
  expect(addressingKey(cam({}))).toBe('network.addressing.unknown');
  expect(addressingKey(cam({ activation: 'unknown', addressing: null }))).toBe('network.addressing.unknown');
  // Une Hikvision neuve : seule la réponse SADP compte.
  expect(addressingKey(cam({ family: 'hikvision', activation: 'new' }))).toBe('network.addressing.unknown');
});

test('MAC affichée : celle vue sur le réseau, sinon celle que la caméra déclare, marquée', () => {
  expect(shownMac(cam({ mac: 'AC:CC:8E:12:34:56' }))).toEqual({ mac: 'AC:CC:8E:12:34:56', declared: false });
  expect(shownMac(cam({ mac: 'AC:CC:8E:12:34:56', declared_mac: 'B8:A4:4F:F5:10:EF' }))).toEqual({ mac: 'AC:CC:8E:12:34:56', declared: false });
  expect(shownMac(cam({ sources: ['http'], declared_mac: 'B8:A4:4F:F5:10:EF' }))).toEqual({ mac: 'B8:A4:4F:F5:10:EF', declared: true });
  expect(shownMac(cam({}))).toEqual({ mac: null, declared: false });
});

test('lecture de l’adressage : seules les Axis partent, avec le compte retenu', async () => {
  invoke.mockResolvedValue([{ ip: '10.0.50.11', addressing: 'dhcp' }]);
  const axis = cam({});
  const hik = cam({ ip: '10.0.50.12', family: 'hikvision' });
  expect(await readAddressing([axis, hik], 'acc')).toEqual([{ ip: '10.0.50.11', addressing: 'dhcp' }]);
  expect(invoke).toHaveBeenLastCalledWith('cmd_read_addressing', { cameras: [axis], accountId: 'acc' });
  // Sans compte, ou sans Axis : rien ne part.
  invoke.mockClear();
  expect(await readAddressing([axis], '')).toEqual([]);
  expect(await readAddressing([hik], 'acc')).toEqual([]);
  expect(invoke).not.toHaveBeenCalled();
});

describe('cameraName', () => {
  it('drops the brand when the model already starts with it', () => {
    expect(cameraName({ brand: 'AXIS', model: 'AXIS P4705-PLVE' })).toBe('AXIS P4705-PLVE');
    expect(cameraName({ brand: 'Axis', model: 'AXIS P4705-PLVE' })).toBe('AXIS P4705-PLVE');
  });
  it('joins brand and model otherwise', () => {
    expect(cameraName({ brand: 'Hikvision', model: 'DS-2CD2143G2' })).toBe('Hikvision DS-2CD2143G2');
    expect(cameraName({ brand: 'AXIS', model: 'AXISP' })).toBe('AXIS AXISP');
    expect(cameraName({ brand: null, model: null })).toBe('—');
  });
});

describe('cameraBrand', () => {
  it('shows the raw brand as-is when present (LTS kept apart from Hikvision)', () => {
    expect(cameraBrand({ family: 'hikvision', brand: 'LTS' })).toBe('LTS');
    expect(cameraBrand({ family: 'axis', brand: 'AXIS' })).toBe('AXIS');
  });
  it('falls back to a family label when the brand is absent or blank', () => {
    expect(cameraBrand({ family: 'axis', brand: null })).toBe('Axis');
    expect(cameraBrand({ family: 'hikvision', brand: '' })).toBe('Hikvision');
    expect(cameraBrand({ family: 'axis', brand: '  ' })).toBe('Axis');
  });
  it('returns null for an unknown family without brand', () => {
    expect(cameraBrand({ family: 'other', brand: null })).toBeNull();
  });
});

test('le scan part avec le compte du réseau retenu, aucun en DHCP', async () => {
  invoke.mockResolvedValue(undefined);
  await startScan('eth0', 'acc-1', () => {});
  expect(invoke).toHaveBeenLastCalledWith('cmd_scan_start', expect.objectContaining({ iface: 'eth0', accountId: 'acc-1' }));
  await startScan('eth0', '', () => {});
  expect(invoke).toHaveBeenLastCalledWith('cmd_scan_start', expect.objectContaining({ accountId: null }));
});

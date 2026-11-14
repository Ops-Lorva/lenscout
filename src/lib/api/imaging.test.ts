import { expect, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import {
  hasPanel, isGroupView, normRect, readSettings, sendOptics, setBdc, setRotation, showBdc, showOptics, showRotation, toggleBdc, zoomRange,
  type ImageSettings, type Optics,
} from './imaging';
import type { Camera } from './types';

const axis: Camera = {
  ip: '10.0.20.11', mac: null, family: 'axis', brand: 'AXIS', model: 'P4705-PLVE', serial: 'B8A44F000001',
  firmware: '11.11', activation: 'activated', http_port: 80, sources: ['http'],
};

const optics: Optics = {
  id: '0', focus: 0.43, magnification: 1, moving: false, window: null, can_focus: true, can_zoom: true, max_magnification: 2.4,
};

const group = { n: 3, name: 'Group View', source: '1,0', resolution: '1280x360' };
const sensor0 = { n: 1, name: 'Camera 1', source: '0', resolution: '640x360' };

test('la vue groupée n’a pas de panneau', () => {
  expect(isGroupView(group)).toBe(true);
  expect(isGroupView(sensor0)).toBe(false);
  expect(isGroupView(null)).toBe(false);
  // Ce que Rust rend pour elle : rien à montrer.
  const none: ImageSettings = { sensor: null, optics: null, rotation: null, bdc: null };
  expect(hasPanel(none)).toBe(false);
  // Rotation figée à 0 : pas de choix, pas de sélecteur.
  expect(showRotation({ ...none, rotation: { current: 0, allowed: [0] } })).toBe(false);
  expect(hasPanel(null)).toBe(false);
});

test('panneau d’une vue de capteur : chaque bloc selon ce que la caméra annonce', () => {
  const s: ImageSettings = { sensor: 0, optics, rotation: { current: 0, allowed: [0, 90, 180, 270] }, bdc: false };
  expect([showOptics(s), showRotation(s), showBdc(s), hasPanel(s)]).toEqual([true, true, true, true]);
  // BDC non réglable par l’utilisateur : interrupteur caché.
  expect(showBdc({ ...s, bdc: null })).toBe(false);
  expect(showOptics({ ...s, optics: { ...optics, can_focus: false, can_zoom: false } })).toBe(false);
  expect(zoomRange(optics)).toEqual({ min: 1, max: 2.4 });
  expect(zoomRange({ ...optics, can_zoom: false })).toBeNull();
});

test('zone d’autofocus : rectangle normalisé, borné à l’image, dans les deux sens', () => {
  const box = { left: 100, top: 50, width: 400, height: 200 };
  expect(normRect({ x: 200, y: 100 }, { x: 400, y: 200 }, box)).toEqual({ x: 0.25, y: 0.25, width: 0.5, height: 0.5 });
  expect(normRect({ x: 400, y: 200 }, { x: 200, y: 100 }, box)).toEqual({ x: 0.25, y: 0.25, width: 0.5, height: 0.5 });
  // Débordement : ramené au bord.
  expect(normRect({ x: 0, y: 0 }, { x: 300, y: 150 }, box)).toEqual({ x: 0, y: 0, width: 0.5, height: 0.5 });
  // Un clic n’est pas une zone.
  expect(normRect({ x: 200, y: 100 }, { x: 201, y: 101 }, box)).toBeNull();
});

test('BDC : l’état relu, ou la dernière valeur lue en erreur', async () => {
  expect(await toggleBdc(false, true, async () => true)).toEqual({ on: true, error: null });
  expect(await toggleBdc(false, true, () => Promise.reject('setting_failed'))).toEqual({ on: false, error: 'setting_failed' });
});

test('les commandes passent la vue par son numéro, jamais le capteur', async () => {
  invoke.mockResolvedValue(null);
  await readSettings(axis, 'acc', sensor0);
  expect(invoke.mock.lastCall).toEqual(['cmd_image_settings', { camera: axis, accountId: 'acc', view: 1 }]);
  await sendOptics(axis, 'acc', sensor0, { kind: 'focus', position: 0.5 });
  expect(invoke.mock.lastCall).toEqual(['cmd_optics', { camera: axis, accountId: 'acc', view: 1, command: { kind: 'focus', position: 0.5 } }]);
  await setRotation(axis, 'acc', null, 180);
  expect(invoke.mock.lastCall?.[1]).toMatchObject({ view: null, degrees: 180 });
  await setBdc(axis, 'acc', sensor0, true);
  expect(invoke.mock.lastCall?.[1]).toMatchObject({ view: 1, on: true });
  // Autre marque ou sans compte : rien ne part.
  invoke.mockClear();
  expect(await readSettings({ ...axis, family: 'hikvision' }, 'acc', null)).toBeNull();
  expect(await readSettings(axis, '', null)).toBeNull();
  expect(invoke).not.toHaveBeenCalled();
});

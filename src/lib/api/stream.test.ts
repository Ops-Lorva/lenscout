import { expect, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke, Channel: class {} }));
import { FramePresenter, identifyCamera, identityChanged, listViews, needsIdentify, noticeKey, startStream, viewLabel } from './stream';
import type { Camera } from './types';

function setup() {
  const shown: (string | null)[] = [];
  const revoked: string[] = [];
  const queue: (() => void)[] = [];
  let n = 0;
  const p = new FramePresenter(
    (u) => shown.push(u),
    (fn) => queue.push(fn),
    () => `blob:${++n}`,
    (u) => revoked.push(u),
    () => handled++,
  );
  let handled = 0;
  const tick = () => queue.splice(0).forEach((f) => f());
  return { p, shown, revoked, tick, handled: () => handled };
}

const buf = (n: number) => new Uint8Array([n]).buffer;

test('une image arrivée avant l’affichage de la précédente la remplace', () => {
  const { p, shown, tick } = setup();
  p.push(buf(1));
  p.push(buf(2));
  p.push(buf(3));
  tick();
  expect(shown).toEqual(['blob:1']); // une seule URL créée : les deux plus anciennes sont abandonnées
});

test('chaque nouvelle image révoque l’URL précédente', () => {
  const { p, revoked, tick } = setup();
  p.push(buf(1)); tick();
  p.push(buf(2)); tick();
  p.push(buf(3)); tick();
  expect(revoked).toEqual(['blob:1', 'blob:2']);
});

test('clear et dispose révoquent l’URL courante, et plus rien ne s’affiche ensuite', () => {
  const { p, shown, revoked, tick } = setup();
  p.push(buf(1)); tick();
  p.clear();
  expect(revoked).toEqual(['blob:1']);
  expect(shown.at(-1)).toBeNull();
  p.push(buf(2)); tick();
  p.dispose();
  expect(revoked).toEqual(['blob:1', 'blob:2']);
  p.push(buf(3)); tick();
  expect(shown.length).toBe(3);
});

test('chaque image poussée est acquittée une fois : affichée ou abandonnée', () => {
  const { p, tick, handled } = setup();
  p.push(buf(1));
  p.push(buf(2)); // abandonne la 1
  expect(handled()).toBe(1);
  tick(); // affiche la 2
  expect(handled()).toBe(2);
  p.push(buf(3));
  p.clear(); // abandonne la 3 en attente
  expect(handled()).toBe(3);
  p.dispose();
  p.push(buf(4)); // fermé : abandonnée aussitôt
  expect(handled()).toBe(4);
});

test('IP saisie dans Cadrage : Rust l’identifie avec le compte choisi', async () => {
  invoke.mockResolvedValue({ ip: '192.168.1.64' });
  await identifyCamera(' 192.168.1.64 ', 'acc');
  expect(invoke).toHaveBeenLastCalledWith('cmd_identify_camera', { ip: '192.168.1.64', accountId: 'acc' });
});

const axis = {
  ip: '192.0.2.20', mac: null, family: 'axis', brand: 'AXIS', model: 'P4705-PLVE', serial: null, firmware: null,
  activation: 'activated', http_port: 80, sources: [],
} as const;

test('le flux part avec la vue choisie, sinon sans vue', async () => {
  invoke.mockResolvedValue(undefined);
  await startStream({ ...axis, sources: [] }, 'acc', () => {}, { n: 3, name: 'Group View', source: '1,0', resolution: '1280x360' });
  expect(invoke.mock.lastCall?.[1]).toMatchObject({ accountId: 'acc', view: 3, resolution: '1280x360' });
  await startStream({ ...axis, sources: [] }, 'acc', () => {});
  expect(invoke.mock.lastCall?.[1]).toMatchObject({ view: null, resolution: null });
});

test('les vues se demandent à Rust ; une seule vue : pas de sélecteur', async () => {
  invoke.mockResolvedValue([{ n: 1, name: null }, { n: 2, name: 'Quai' }]);
  expect(await listViews({ ...axis, sources: [] }, 'acc')).toHaveLength(2);
  expect(invoke).toHaveBeenLastCalledWith('cmd_stream_views', { camera: { ...axis, sources: [] }, accountId: 'acc' });
  // Hikvision ou sans compte : rien ne part, une vue.
  invoke.mockClear();
  expect(await listViews({ ...axis, sources: [], family: 'hikvision' }, 'acc')).toEqual([]);
  expect(await listViews({ ...axis, sources: [] }, '')).toEqual([]);
  expect(invoke).not.toHaveBeenCalled();
});

test('libellé d’une vue : son nom s’il y en a un, sinon « Vue N »', () => {
  expect(viewLabel({ n: 2, name: 'Quai' })).toEqual({ key: 'framing.viewNamed', values: { n: 2, name: 'Quai' } });
  expect(viewLabel({ n: 3, name: null })).toEqual({ key: 'framing.view', values: { n: 3 } });
});

test('une caméra non tranchée (« other ») ou vue anonymement à travers le routeur se relit, une marque de couche 2 non', () => {
  // Non tranchée (« other ») : à relire, d'où qu'elle vienne.
  expect(needsIdentify({ ...axis, sources: [], family: 'other' })).toBe(true);
  // Le balayage routé (source « http ») n'identifie QU'anonymement : une Axis y
  // paraît parfois Hikvision (ou reste non confirmée). On la relit avec le
  // compte, comme l'ouverture par IP, pour trancher sa marque.
  expect(needsIdentify({ ...axis, sources: ['http'], family: 'hikvision' })).toBe(true);
  // Une Axis confirmée à l'anonyme (basicdeviceinfo) passe tout droit, même routée.
  expect(needsIdentify({ ...axis, sources: ['http'] })).toBe(false);
  // Une marque de couche 2 (ouverture par IP, SADP/mDNS/WSD) est faite avec le
  // compte ou l'annonce de la caméra : elle passe tout droit.
  expect(needsIdentify({ ...axis, sources: [] })).toBe(false);
  expect(needsIdentify({ ...axis, sources: ['sadp'], family: 'hikvision' })).toBe(false);
  expect(needsIdentify({ ...axis, sources: [], family: 'hikvision' })).toBe(false);
});

test('identité changée après relecture : marque, modèle, série, famille, IP ou source', () => {
  const base: Camera = { ...axis, sources: ['http'], family: 'other', brand: null, model: null, serial: null };
  expect(identityChanged(base, base)).toBe(false);
  expect(identityChanged({ ...base, family: 'axis' }, base)).toBe(true);
  expect(identityChanged({ ...base, brand: 'AXIS' }, base)).toBe(true);
  expect(identityChanged({ ...base, model: 'P4705-PLVE' }, base)).toBe(true);
  expect(identityChanged({ ...base, serial: 'ACCC8E000002' }, base)).toBe(true);
  expect(identityChanged({ ...base, ip: '192.0.2.21' }, base)).toBe(true);
  // Relue avec le compte : `identify` rend une caméra sans source (`sources: []`).
  // Même marque, mais la source change : on repose quand même la cible, pour que
  // la caméra routée cesse d'être « à relire » et que son flux démarre.
  expect(identityChanged({ ...base, sources: [] }, base)).toBe(true);
});

test('message visible d’un échec : identifiants refusés distingués du reste', () => {
  expect(noticeKey('auth_failed')).toBe('framing.notice.authRefused');
  expect(noticeKey('auth_insecure')).toBe('framing.notice.authRefused');
  expect(noticeKey('unreachable')).toBe('framing.notice.unavailable');
  expect(noticeKey('not_a_camera')).toBe('framing.notice.unavailable');
  expect(noticeKey(new Error('boum'))).toBe('framing.notice.unavailable');
});

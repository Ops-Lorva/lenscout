import { expect, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke, Channel: class {} }));
import { FramePresenter, identifyCamera, listViews, startStream, viewLabel } from './stream';

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
  await startStream({ ...axis, sources: [] }, 'acc', () => {}, 2);
  expect(invoke.mock.lastCall?.[1]).toMatchObject({ accountId: 'acc', view: 2 });
  await startStream({ ...axis, sources: [] }, 'acc', () => {});
  expect(invoke.mock.lastCall?.[1].view).toBeNull();
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

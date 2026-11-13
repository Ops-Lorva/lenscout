import { expect, test } from 'vitest';
import { FramePresenter } from './stream';

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

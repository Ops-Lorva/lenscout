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
  );
  const tick = () => queue.splice(0).forEach((f) => f());
  return { p, shown, revoked, tick };
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

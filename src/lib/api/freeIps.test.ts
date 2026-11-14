import { expect, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({
  invoke,
  Channel: class {
    onmessage: ((m: unknown) => void) | null = null;
  },
}));
import { cancelFreeIps, firstFit, networkLabel, rangeContaining, rangeLabel, reduceFreeEvent, startFreeIps, type FreeRange, type FreeState } from './freeIps';

const r = (first: string, last: string, count: number): FreeRange => ({ first, last, count });

test('un balayage commence à 0 / 0 puis suit la progression', () => {
  let s = reduceFreeEvent(null, { kind: 'progress', done: 0, total: 254 });
  expect(s).toEqual({ phase: 'scanning', done: 0, total: 254 });
  s = reduceFreeEvent(s, { kind: 'progress', done: 137, total: 254 });
  expect(s).toEqual({ phase: 'scanning', done: 137, total: 254 });
});

test('Done donne les plages et le drapeau tronqué', () => {
  const ranges = [r('10.0.0.2', '10.0.0.9', 8)];
  expect(reduceFreeEvent({ phase: 'scanning', done: 5, total: 5 }, { kind: 'done', ranges, truncated: true })).toEqual({
    phase: 'done', ranges, truncated: true,
  });
});

test('une progression en retard ne rouvre pas un balayage terminé', () => {
  const done: FreeState = { phase: 'done', ranges: [], truncated: false };
  expect(reduceFreeEvent(done, { kind: 'progress', done: 3, total: 4 })).toBe(done);
});

test('l’étiquette d’une plage abrège le préfixe commun', () => {
  expect(rangeLabel(r('192.168.1.2', '192.168.1.19', 18))).toBe('192.168.1.2–19');
  expect(rangeLabel(r('192.168.1.7', '192.168.1.7', 1))).toBe('192.168.1.7');
  expect(rangeLabel(r('10.0.0.250', '10.0.1.9', 16))).toBe('10.0.0.250–10.0.1.9');
});

test('première plage assez grande pour n caméras', () => {
  const rs = [r('10.0.0.5', '10.0.0.6', 2), r('10.0.0.20', '10.0.0.22', 3)];
  expect(firstFit(rs, 1)).toBe('10.0.0.5');
  expect(firstFit(rs, 3)).toBe('10.0.0.20');
  expect(firstFit(rs, 4)).toBeNull();
  expect(firstFit(rs, 0)).toBeNull();
});

test('la plage active est celle qui contient l’adresse saisie', () => {
  const rs = [r('10.0.0.5', '10.0.0.6', 2), r('10.0.0.20', '10.0.0.22', 3)];
  expect(rangeContaining(rs, ' 10.0.0.21 ')).toBe(rs[1]);
  expect(rangeContaining(rs, '10.0.0.7')).toBeUndefined();
  expect(rangeContaining(rs, 'abc')).toBeUndefined();
});

test('le réseau est affiché avec son interface', () => {
  expect(networkLabel('en0', '192.168.1.37', '255.255.255.0')).toBe('en0, 192.168.1.0/24');
  expect(networkLabel('eth0', '10.1.2.3', '255.255.0.0')).toBe('eth0, 10.1.0.0/16');
  expect(networkLabel('eth0', null, null)).toBe('eth0');
});

test('startFreeIps numérote le balayage, relaie ses événements, et cancelFreeIps vise ce numéro', async () => {
  invoke.mockResolvedValue(undefined);
  const got: unknown[] = [];
  const run = startFreeIps('eth0', (e) => got.push(e));
  await run.done;
  const [cmd, args] = invoke.mock.calls[0];
  expect(cmd).toBe('cmd_free_ips');
  expect(args.interface).toBe('eth0');
  expect(args.id).toBe(run.id);
  args.channel.onmessage({ kind: 'progress', done: 1, total: 2 });
  expect(got).toEqual([{ kind: 'progress', done: 1, total: 2 }]);
  await cancelFreeIps(run.id);
  expect(invoke).toHaveBeenLastCalledWith('cmd_free_ips_cancel', { id: run.id });
});

test('deux balayages ont deux numéros différents', () => {
  invoke.mockResolvedValue(undefined);
  const a = startFreeIps('eth0', () => {});
  const b = startFreeIps('eth0', () => {});
  expect(b.id).not.toBe(a.id);
  expect(Number.isSafeInteger(a.id)).toBe(true);
});

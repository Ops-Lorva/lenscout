import { expect, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import {
  activeAddress, autoFill, createJoinSwitch, DEFAULT_MASK, joinStep, maskOf, networkOf, prefillFor, type Joined,
} from './net';

test('le réseau se déduit de l’IP du PC', () => {
  expect(networkOf('192.168.1.250/24')).toBe('192.168.1.0/24');
  expect(networkOf(' 10.20.30.40/16 ')).toBe('10.20.0.0/16');
  expect(networkOf('172.16.5.9/32')).toBe('172.16.5.9/32');
  for (const bad of ['', '192.168.1.250', '192.168.1.250/33', '192.168.1.250/0', '300.1.1.1/24', 'x/24']) {
    expect(networkOf(bad), bad).toBe('');
  }
});

test('masque d’un CIDR', () => {
  expect(maskOf('192.168.1.0/24')).toBe('255.255.255.0');
  expect(maskOf('10.0.0.0/22')).toBe('255.255.252.0');
  expect(maskOf('nope')).toBe('');
});

test('un champ saisi n’est jamais écrasé ; vide ou prérempli, il suit le compte', () => {
  expect(autoFill('', '', '192.168.1.1')).toBe('192.168.1.1');
  expect(autoFill('192.168.1.1', '192.168.1.1', '10.0.0.1')).toBe('10.0.0.1');
  expect(autoFill('192.168.1.254', '192.168.1.1', '10.0.0.1')).toBe('192.168.1.254');
  expect(autoFill('192.168.1.254', '', '10.0.0.1')).toBe('192.168.1.254');
});

test('préremplissage : masque et passerelle du compte, sinon les valeurs par défaut', () => {
  expect(prefillFor({ network: '192.168.1.0/22', gateway: '192.168.1.1' })).toEqual({ mask: '255.255.252.0', gateway: '192.168.1.1' });
  // Sans réseau, le préfixe de l’IP du PC.
  expect(prefillFor({ pc_ip: '10.1.2.250/16' })).toEqual({ mask: '255.255.0.0', gateway: '' });
  expect(prefillFor(null)).toEqual({ mask: DEFAULT_MASK, gateway: '' });
  expect(prefillFor({})).toEqual({ mask: DEFAULT_MASK, gateway: '' });
});

const joined = (iface: string, account_id = 'a'): Joined => ({
  account_id, iface, ip: '192.168.1.250', mask: '255.255.255.0', cidr: '192.168.1.250/24',
});

test('adresse active : celle posée pour un compte sur cette interface, sinon celle de l’interface', () => {
  const d = { ip: '10.0.0.5', subnet: '255.255.0.0' };
  expect(activeAddress('en0', d, null)).toEqual({ ip: '10.0.0.5', mask: '255.255.0.0' });
  expect(activeAddress('en0', d, joined('en0'))).toEqual({ ip: '192.168.1.250', mask: '255.255.255.0' });
  expect(activeAddress('en0', d, joined('en1'))).toEqual({ ip: '10.0.0.5', mask: '255.255.0.0' });
  expect(activeAddress('en0', null, null)).toEqual({ ip: null, mask: null });
});

test('enchaînements du sélecteur : DHCP, compte, changement de compte et d’interface', () => {
  const dhcp = (iface: string) => ({ iface, account: '' });
  const acc = (iface: string, account: string) => ({ iface, account });
  expect(joinStep(dhcp('en0'), dhcp('en0'))).toBe('none');
  expect(joinStep(dhcp('en0'), dhcp('en1'))).toBe('none');
  expect(joinStep(dhcp('en0'), acc('en0', 'a'))).toBe('join');
  expect(joinStep(acc('en0', 'a'), acc('en0', 'a'))).toBe('none');
  expect(joinStep(acc('en0', 'a'), acc('en0', 'b'))).toBe('join');
  expect(joinStep(acc('en0', 'a'), acc('en1', 'a'))).toBe('join');
  expect(joinStep(acc('en0', 'a'), dhcp('en0'))).toBe('leave');
  expect(joinStep(acc('en0', 'a'), dhcp('en1'))).toBe('leave');
});

function ops() {
  const calls: string[] = [];
  let failNext: string | null = null;
  const gate: { open: (() => void) | null } = { open: null };
  return {
    calls,
    failWith: (code: string) => (failNext = code),
    hold: () => new Promise<void>((r) => (gate.open = r)),
    gate,
    join: async (account: string, iface: string) => {
      calls.push(`join ${account}@${iface}`);
      if (failNext) { const c = failNext; failNext = null; throw c; }
      return joined(iface, account);
    },
    leave: async () => {
      calls.push('leave');
      if (failNext) { const c = failNext; failNext = null; throw c; }
    },
  };
}

test('choisir un compte le pose, revenir sur DHCP le retire', async () => {
  const o = ops();
  const sw = createJoinSwitch(o);
  sw.init('en0', null);
  expect(sw.applied).toEqual({ iface: 'en0', account: '' });
  expect(await sw.change({ iface: 'en0', account: 'a' })).toEqual({ kind: 'done', applied: { iface: 'en0', account: 'a' }, joined: joined('en0') });
  expect(await sw.change({ iface: 'en0', account: '' })).toEqual({ kind: 'done', applied: { iface: 'en0', account: '' }, joined: null });
  expect(o.calls).toEqual(['join a@en0', 'leave']);
});

test('changer de compte ou d’interface repose l’IP (le cœur retire la précédente d’abord)', async () => {
  const o = ops();
  const sw = createJoinSwitch(o);
  sw.init('en0', joined('en0', 'a'));
  expect(sw.applied).toEqual({ iface: 'en0', account: 'a' });
  await sw.change({ iface: 'en0', account: 'b' });
  await sw.change({ iface: 'en1', account: 'b' });
  expect(o.calls).toEqual(['join b@en0', 'join b@en1']);
  expect(sw.applied).toEqual({ iface: 'en1', account: 'b' });
});

test('changer d’interface en DHCP ne pose rien mais compte comme un changement', async () => {
  const o = ops();
  const sw = createJoinSwitch(o);
  sw.init('en0', null);
  expect(await sw.change({ iface: 'en1', account: '' })).toEqual({ kind: 'done', applied: { iface: 'en1', account: '' }, joined: null });
  expect(o.calls).toEqual([]);
});

test('échec ou refus : le choix précédent revient, avec le code', async () => {
  const o = ops();
  const sw = createJoinSwitch(o);
  sw.init('en0', null);
  o.failWith('elevation_refused');
  expect(await sw.change({ iface: 'en0', account: 'a' })).toEqual({ kind: 'failed', code: 'elevation_refused', applied: { iface: 'en0', account: '' } });
  expect(sw.applied).toEqual({ iface: 'en0', account: '' });
  await sw.change({ iface: 'en0', account: 'a' });
  o.failWith('temp_ip_left');
  expect(await sw.change({ iface: 'en0', account: '' })).toEqual({ kind: 'failed', code: 'temp_ip_left', applied: { iface: 'en0', account: 'a' } });
});

test('un seul changement à la fois : un second pendant le premier est ignoré', async () => {
  const o = ops();
  let release!: () => void;
  const slow = { ...o, join: async (a: string, i: string) => { o.calls.push(`join ${a}@${i}`); await new Promise<void>((r) => (release = r)); return joined(i, a); } };
  const sw = createJoinSwitch(slow);
  sw.init('en0', null);
  const first = sw.change({ iface: 'en0', account: 'a' });
  expect(sw.busy).toBe(true);
  expect(await sw.change({ iface: 'en0', account: 'b' })).toEqual({ kind: 'ignored', applied: { iface: 'en0', account: '' } });
  release();
  await first;
  expect(sw.busy).toBe(false);
  expect(o.calls).toEqual(['join a@en0']);
  expect(sw.applied).toEqual({ iface: 'en0', account: 'a' });
});

test('état du cœur au retour sur l’écran : un compte posé sur une autre interface la désigne', () => {
  const sw = createJoinSwitch(ops());
  sw.init('en0', joined('en1', 'a'));
  expect(sw.applied).toEqual({ iface: 'en1', account: 'a' });
});

test('feuilles IP : le compte remplit masque et passerelle sans écraser une saisie', async () => {
  const { applyPrefill, INITIAL_PREFILL } = await import('./net');
  const a = { network: '10.0.0.0/16', gateway: '10.0.0.1' };
  // Ouverture : masque par défaut et passerelle vide → valeurs du compte.
  let r = applyPrefill(INITIAL_PREFILL, INITIAL_PREFILL, a);
  expect(r.fields).toEqual({ mask: '255.255.0.0', gateway: '10.0.0.1' });
  // Autre compte : les valeurs préremplies suivent.
  r = applyPrefill(r.fields, r.last, { gateway: '192.168.1.1', pc_ip: '192.168.1.250/24' });
  expect(r.fields).toEqual({ mask: '255.255.255.0', gateway: '192.168.1.1' });
  // Saisie de l'utilisateur : elle reste quel que soit le compte.
  r = applyPrefill({ mask: '255.255.255.128', gateway: '192.168.1.254' }, r.last, a);
  expect(r.fields).toEqual({ mask: '255.255.255.128', gateway: '192.168.1.254' });
  // Compte sans réseau : retour au défaut pour ce qui était prérempli.
  r = applyPrefill({ mask: '255.255.0.0', gateway: '10.0.0.1' }, { mask: '255.255.0.0', gateway: '10.0.0.1' }, null);
  expect(r.fields).toEqual(INITIAL_PREFILL);
});

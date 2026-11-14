import { expect, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import {
  accountChoices, activeAddress, canScan, createJoinSwitch, DEFAULT_MASK, generations, joinReady, joinStep, maskOf, networkOf, prefillFor,
  type Joined,
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

test('feuilles IP : le compte remplit masque et passerelle, jamais un champ touché', async () => {
  const { prefillFields, INITIAL_PREFILL } = await import('./net');
  const a = { network: '10.0.0.0/16', gateway: '10.0.0.1' };
  const none = { mask: false, gateway: false };
  // Ouverture : rien de touché → valeurs du compte.
  let f = prefillFields(INITIAL_PREFILL, none, a);
  expect(f).toEqual({ mask: '255.255.0.0', gateway: '10.0.0.1' });
  // Autre compte : les champs non touchés suivent.
  f = prefillFields(f, none, { gateway: '192.168.1.1', pc_ip: '192.168.1.250/24' });
  expect(f).toEqual({ mask: '255.255.255.0', gateway: '192.168.1.1' });
  // Champ touché, même avec la valeur d'un compte : il reste.
  f = prefillFields({ mask: '255.255.255.0', gateway: '192.168.1.254' }, { mask: true, gateway: true }, a);
  expect(f).toEqual({ mask: '255.255.255.0', gateway: '192.168.1.254' });
  // Compte sans réseau : retour au défaut pour ce qui n'est pas touché.
  expect(prefillFields({ mask: '255.255.0.0', gateway: '10.0.0.1' }, none, null)).toEqual(INITIAL_PREFILL);
});

test('le DNS suit la passerelle tant qu’il n’est pas touché', async () => {
  const { dnsFollowing } = await import('./net');
  // Ouverture : DNS vide, passerelle préremplie par le compte → le DNS la prend.
  expect(dnsFollowing('', false, '10.0.0.1')).toBe('10.0.0.1');
  // Passerelle changée (compte ou saisie) : le DNS non touché suit.
  expect(dnsFollowing('10.0.0.1', false, '192.168.1.1')).toBe('192.168.1.1');
  // Passerelle vidée : le DNS non touché se vide aussi.
  expect(dnsFollowing('192.168.1.1', false, '')).toBe('');
  // DNS touché : jamais écrasé, même vide.
  expect(dnsFollowing('8.8.8.8', true, '192.168.1.1')).toBe('8.8.8.8');
  expect(dnsFollowing('', true, '192.168.1.1')).toBe('');
});

test('après une pose, le scan attend que Rust voie l’adresse sur le poste', async () => {
  invoke.mockResolvedValue(undefined);
  await joinReady();
  expect(invoke).toHaveBeenLastCalledWith('cmd_join_ready');
});

test('une attente de pose dépassée par une autre est ignorée', () => {
  const gen = generations();
  const first = gen.next();
  expect(gen.current(first)).toBe(true);
  const second = gen.next();
  expect(gen.current(first)).toBe(false);
  expect(gen.current(second)).toBe(true);
});

test('compte supprimé alors que son IP est posée : il reste dans le sélecteur, marqué', () => {
  const list = [
    { id: 'a', name: 'A', login: 'r', pc_ip: '192.168.1.250/24' },
    { id: 'b', name: 'B', login: 'r' },
  ];
  // Le compte posé existe : la liste habituelle.
  expect(accountChoices(list, joined('en0', 'a'))).toEqual([{ id: 'a', name: 'A', deleted: false }]);
  expect(accountChoices(list, null)).toEqual([{ id: 'a', name: 'A', deleted: false }]);
  // Supprimé : toujours là (l'IP l'est aussi), sans nom.
  expect(accountChoices(list, joined('en0', 'zz'))).toEqual([
    { id: 'a', name: 'A', deleted: false },
    { id: 'zz', name: '', deleted: true },
  ]);
});

test('jamais de scan sans interface ni pendant la pose d’une IP', () => {
  expect(canScan('en0', false)).toBe(true);
  expect(canScan('en0', true)).toBe(false);
  expect(canScan('', false)).toBe(false);
});

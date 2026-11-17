import { expect, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({
  invoke,
  Channel: class {
    onmessage: ((m: unknown) => void) | null = null;
  },
}));
import {
  absent, accountDevices, accountReservations, cancelSurvey, devicesCsvRows, filterDevices, forgetDevice, frameIp, freeAddresses, onAccountNetwork,
  releaseIp, reserveIp, stale, STALE_DAYS, startSurvey,
  type SeenDevice,
} from './siteNet';
import { activeAddress, type Joined } from './net';
import type { NetworkFill } from './accounts';

const dev = (ip: string, kind: SeenDevice['kind'], extra: Partial<SeenDevice> = {}): SeenDevice => ({
  ip, kind, first_seen: 100, last_seen: 200, ...extra,
});
const list: SeenDevice[] = [
  dev('192.168.1.1', 'gateway'),
  dev('192.168.1.20', 'camera', { mac: 'AC:CC:8E:00:00:20', vendor: 'Axis Communications AB', model: 'P3245-LVE' }),
  dev('192.168.1.30', 'switch', { mac: '00:1B:21:00:00:30', vendor: 'Cisco Systems, Inc', last_seen: 100 }),
  dev('192.168.1.40', 'pc', { name: 'POSTE-ACCUEIL' }),
];

test('start_survey_forwards_progress_and_done', async () => {
  invoke.mockResolvedValue(undefined);
  const got: unknown[] = [];
  await startSurvey(7, 'acc', 'eth0', [], (e) => got.push(e));
  const [cmd, args] = invoke.mock.lastCall!;
  expect(cmd).toBe('cmd_site_survey');
  expect(args).toMatchObject({ id: 7, accountId: 'acc', interface: 'eth0', cameras: [] });
  args.channel.onmessage({ kind: 'progress', done: 1, total: 253 });
  args.channel.onmessage({ kind: 'done', devices: list, surveyed_at: 200, fill: null, truncated: false });
  expect(got).toEqual([
    { kind: 'progress', done: 1, total: 253 },
    { kind: 'done', devices: list, surveyed_at: 200, fill: null, truncated: false },
  ]);
  await cancelSurvey(7);
  expect(invoke).toHaveBeenLastCalledWith('cmd_site_survey_cancel', { id: 7 });
  await accountDevices('acc');
  expect(invoke).toHaveBeenLastCalledWith('cmd_account_devices', { id: 'acc' });
  await forgetDevice('acc', '192.168.1.40');
  expect(invoke).toHaveBeenLastCalledWith('cmd_account_forget_device', { id: 'acc', key: '192.168.1.40' });
});

test('filter_by_kinds_and_query_on_ip_mac_vendor_name', () => {
  const ips = (l: SeenDevice[]) => l.map((d) => d.ip);
  expect(ips(filterDevices(list, new Set(), ''))).toEqual(ips(list));
  expect(ips(filterDevices(list, new Set(['camera', 'switch']), ''))).toEqual(['192.168.1.20', '192.168.1.30']);
  expect(ips(filterDevices(list, new Set(), '1.40'))).toEqual(['192.168.1.40']);
  expect(ips(filterDevices(list, new Set(), 'ac-cc-8e'))).toEqual(['192.168.1.20']);
  expect(ips(filterDevices(list, new Set(), 'cisco'))).toEqual(['192.168.1.30']);
  expect(ips(filterDevices(list, new Set(), 'accueil'))).toEqual(['192.168.1.40']);
  expect(ips(filterDevices(list, new Set(), 'p3245'))).toEqual(['192.168.1.20']);
  expect(filterDevices(list, new Set(['pc']), 'cisco')).toEqual([]);
});

test('absent_when_last_seen_before_surveyed_at', () => {
  expect(absent(list[2], 200)).toBe(true);
  expect(absent(list[1], 200)).toBe(false);
  expect(absent(list[2], null)).toBe(false);
});

test('csv_rows_follow_the_filtered_view', () => {
  const t = (k: string) => `«${k}»`;
  const date = (s: number) => `d${s}`;
  const csv = devicesCsvRows(filterDevices(list, new Set(['camera', 'pc']), ''), t, date);
  expect(csv.header).toEqual(['«sitenet.col.ip»', '«sitenet.col.mac»', '«sitenet.col.vendor»', '«sitenet.col.kind»', '«sitenet.col.name»', '«sitenet.col.seen»']);
  expect(csv.rows).toEqual([
    ['192.168.1.20', 'AC:CC:8E:00:00:20', 'Axis Communications AB', '«sitenet.kind.camera»', 'P3245-LVE', 'd200'],
    ['192.168.1.40', '', '', '«sitenet.kind.pc»', 'POSTE-ACCUEIL', 'd200'],
  ]);
});

test('on_account_network_true_for_same_network_or_joined_account_false_otherwise', () => {
  const account = { pc_ip: '192.168.1.250/24' };
  const eth = { ip: '10.0.50.2', subnet: '255.255.255.0' };
  expect(onAccountNetwork(activeAddress('eth0', { ip: '192.168.1.7', subnet: '255.255.255.0' }, null), account)).toBe(true);
  expect(onAccountNetwork(activeAddress('eth0', eth, null), account)).toBe(false);
  const j: Joined = { account_id: 'a', iface: 'eth0', ip: '192.168.1.250', mask: '255.255.255.0', cidr: '192.168.1.250/24' };
  expect(onAccountNetwork(activeAddress('eth0', eth, j), account)).toBe(true);
  // Mode routé : le réseau du compte, à travers le routeur.
  const routed: Joined = { ...j, ip: '192.168.1.0', cidr: '192.168.1.0/24', via: '10.0.50.1' };
  expect(onAccountNetwork(activeAddress('eth0', eth, routed), account)).toBe(true);
  // Posé sur une autre interface : celle-ci reste hors du réseau.
  expect(onAccountNetwork(activeAddress('eth1', eth, j), account)).toBe(false);
  expect(onAccountNetwork(activeAddress('eth0', eth, j), { pc_ip: null })).toBe(false);
  expect(onAccountNetwork({ ip: null, mask: null }, account)).toBe(false);
});

test('frame_ip_only_for_cameras', () => {
  // Seule une caméra s'ouvre au Cadrage ; le NVR, le switch ou l'inconnu, non.
  expect(frameIp(dev('192.168.1.64', 'camera'))).toBe('192.168.1.64');
  expect(frameIp(dev('192.168.1.10', 'nvr'))).toBeNull();
  expect(frameIp(dev('192.168.1.2', 'switch'))).toBeNull();
  expect(frameIp(dev('192.168.1.9', 'unknown'))).toBeNull();
});

test('reservations_call_their_commands', async () => {
  invoke.mockResolvedValue([]);
  await accountReservations('acc');
  expect(invoke).toHaveBeenLastCalledWith('cmd_account_reservations', { id: 'acc' });
  await reserveIp('acc', '192.168.1.110', 'Cam 110');
  expect(invoke).toHaveBeenLastCalledWith('cmd_account_reserve', { id: 'acc', ip: '192.168.1.110', label: 'Cam 110' });
  // Libellé vide : pas de libellé.
  await reserveIp('acc', '192.168.1.111', '  ');
  expect(invoke).toHaveBeenLastCalledWith('cmd_account_reserve', { id: 'acc', ip: '192.168.1.111', label: null });
  await releaseIp('acc', '192.168.1.110');
  expect(invoke).toHaveBeenLastCalledWith('cmd_account_release', { id: 'acc', ip: '192.168.1.110' });
});

const fill = (network: string, size: number, segments: NetworkFill['segments'], free: number): NetworkFill => ({
  network, size, usable: size - 2, gateway: 0, pc: 0, excluded: 0, reserved: 0, cameras: 0, free,
  almost_full: false, segments, devices: 0, used_pct: 0, crowded: false, suggest: null,
});

test('free_addresses_are_the_hosts_outside_every_segment', () => {
  // /29 : hôtes .1 à .6 ; passerelle .1, réservées .3–.4, PC .6.
  const f = fill('10.0.8.0/29', 8, [
    { kind: 'gateway', first: 1, last: 1 }, { kind: 'reserved', first: 3, last: 4 }, { kind: 'pc', first: 6, last: 6 },
  ], 2);
  expect(freeAddresses(f, '', 100)).toEqual({ ips: ['10.0.8.2', '10.0.8.5'], more: false });
  // Recherche dans l'adresse ; plafond : le reste est signalé, pas affiché.
  expect(freeAddresses(f, '.5', 100)).toEqual({ ips: ['10.0.8.5'], more: false });
  expect(freeAddresses(f, '', 1)).toEqual({ ips: ['10.0.8.2'], more: true });
  expect(freeAddresses(fill('pas un réseau', 8, [], 0), '', 10)).toEqual({ ips: [], more: false });
});

test('a_device_unseen_for_over_180_days_is_stale', () => {
  const day = 24 * 3600;
  const now = 1000 * day;
  expect(STALE_DAYS).toBe(180);
  expect(stale(dev('192.168.1.9', 'unknown', { last_seen: now - 181 * day }), now)).toBe(true);
  expect(stale(dev('192.168.1.9', 'unknown', { last_seen: now - 179 * day }), now)).toBe(false);
});

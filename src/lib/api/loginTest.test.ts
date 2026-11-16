import { expect, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({
  invoke,
  Channel: class {
    onmessage: ((m: unknown) => void) | null = null;
  },
}));
import { cancelLoginTest, filterLogin, loginCounts, loginCsvRows, startLoginTest, type LoginResult } from './loginTest';
import type { Camera } from './types';

const cam = (ip: string, mac: string | null, model: string | null): Camera => ({
  ip, mac, model, family: 'axis', brand: 'AXIS', serial: null, firmware: null, activation: 'activated', http_port: 80, sources: ['mdns'],
});
const cams = [cam('10.0.50.11', 'AC:CC:8E:00:00:0B', 'M3106-L'), cam('10.0.50.12', null, 'P3268-LVE'), cam('10.0.50.13', 'AC:CC:8E:00:00:0D', 'Q6135')];
const rows: LoginResult[] = [
  { index: 0, key: 'AC:CC:8E:00:00:0B', ip: '10.0.50.11', code: 'ok' },
  { index: 1, key: '10.0.50.12', ip: '10.0.50.12', code: 'denied' },
  { index: 2, key: 'AC:CC:8E:00:00:0D', ip: '10.0.50.13', code: 'ok' },
];

test('start_sends_cameras_account_and_iface_and_forwards_events', async () => {
  invoke.mockResolvedValue(undefined);
  const got: unknown[] = [];
  await startLoginTest(42, cams, 'acc', 'eth0', (e) => got.push(e));
  const [cmd, args] = invoke.mock.lastCall!;
  expect(cmd).toBe('cmd_login_test');
  expect(args).toMatchObject({ id: 42, cameras: cams, accountId: 'acc', iface: 'eth0' });
  args.channel.onmessage({ kind: 'result', ...rows[0] });
  args.channel.onmessage({ kind: 'done', cancelled: false });
  expect(got).toEqual([{ kind: 'result', ...rows[0] }, { kind: 'done', cancelled: false }]);
});

test('counts_by_code_and_hides_nothing_in_data', () => {
  const c = loginCounts(rows);
  expect(c).toEqual({ ok: 2, denied: 1 });
  // Les lignes ne sont pas touchées.
  expect(rows).toHaveLength(3);
});

test('filter_by_codes_and_query_on_ip_mac_model', () => {
  expect(filterLogin(rows, cams, new Set(), '').map((r) => r.index)).toEqual([0, 1, 2]);
  expect(filterLogin(rows, cams, new Set(['ok']), '').map((r) => r.index)).toEqual([0, 2]);
  expect(filterLogin(rows, cams, new Set(), '10.0.50.12').map((r) => r.index)).toEqual([1]);
  expect(filterLogin(rows, cams, new Set(), 'cc:8e:00:00:0d').map((r) => r.index)).toEqual([2]);
  expect(filterLogin(rows, cams, new Set(), 'p3268').map((r) => r.index)).toEqual([1]);
  expect(filterLogin(rows, cams, new Set(['ok']), 'p3268')).toEqual([]);
});

test('csv_rows_follow_the_filtered_view_and_never_contain_a_password', () => {
  const t = (k: string) => `«${k}»`;
  const shown = filterLogin(rows, cams, new Set(['ok']), '');
  const csv = loginCsvRows(shown, cams, t);
  expect(csv.header).toEqual(['«logintest.col.camera»', '«logintest.col.ip»', '«logintest.col.mac»', '«logintest.col.result»']);
  expect(csv.rows).toEqual([
    ['AXIS M3106-L', '10.0.50.11', 'AC:CC:8E:00:00:0B', '«logintest.code.ok»'],
    ['AXIS Q6135', '10.0.50.13', 'AC:CC:8E:00:00:0D', '«logintest.code.ok»'],
  ]);
  expect(JSON.stringify(csv)).not.toMatch(/password|S3cr3t/i);
});

test('cancel_calls_with_the_run_id', async () => {
  invoke.mockResolvedValue(undefined);
  await cancelLoginTest(42);
  expect(invoke).toHaveBeenLastCalledWith('cmd_login_test_cancel', { id: 42 });
});

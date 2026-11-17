import { describe, expect, it, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));

import type { CredResult, OpRow, StepResult } from './ops';
import { opsXlsx, xlsxName, type OpsRun } from './opsReport';
import { saveXlsx } from './report';
import type { Camera } from './types';

const t = (key: string, values?: Record<string, string | number>) =>
  values && Object.keys(values).length ? `«${key}|${JSON.stringify(values)}»` : `«${key}»`;

const cam = (ip: string, mac: string | null, model: string | null, serial: string | null = null): Camera => ({
  ip, mac, model, serial, family: 'axis', brand: 'AXIS', firmware: null, activation: 'activated', http_port: 80, sources: ['mdns'],
});

const row = (key: string, ip: string, newIp: string | null): OpRow => ({
  key,
  ip,
  before: { addressing: 'static', ip, mask: '255.255.255.0', gateway: '10.0.50.1', dns: ['10.0.50.2'] },
  after: newIp ? { ip: newIp, mask: '255.255.254.0', gateway: '10.0.50.1', dns: ['10.0.50.2', '9.9.9.9'] } : null,
  conflicts: [],
});

const ok = (key: string, reachable: boolean | null = true): StepResult => ({ key, ok: true, error: null, reachable });
const ko = (key: string): StepResult => ({ key, ok: false, error: { code: 'auth_failed' }, reachable: null });

const cams = [
  cam('10.0.50.11', 'AC:CC:8E:00:00:0B', 'M3106-L', 'ACCC8E00000B'),
  cam('10.0.50.12', null, 'P3268-LVE'),
  cam('10.0.50.13', 'AC:CC:8E:00:00:0D', 'Q6135'),
  cam('10.0.50.14', 'AC:CC:8E:00:00:0E', 'M3106-L'),
  cam('10.0.50.15', 'AC:CC:8E:00:00:0F', 'M3106-L'),
];
const at = new Date(2026, 10, 17, 9, 5);
const account = { name: 'Site A', login: 'lenscout' };

const NET_HEADER = ['result', 'detail', 'nvr', 'oldIp', 'newIp', 'mask', 'gateway', 'dns', 'brand', 'model', 'mac', 'serial'].map((c) => `«ops.xlsx.col.${c}»`);

describe('rapport Excel d’une opération', () => {
  const renumber: OpsRun = {
    kind: 'renumber',
    at,
    cams,
    rows: [
      row('k1', '10.0.50.11', '10.0.50.11'), // IP inchangée
      row('k2', '10.0.50.12', '10.0.50.22'), // échec
      row('k3', '10.0.50.13', '10.0.50.23'), // déplacée, joignable
      row('k4', '10.0.50.14', '10.0.50.24'), // déplacée, muette
      row('k5', '10.0.50.15', '10.0.50.25'), // non faite (Arrêter)
    ],
    results: [ok('k1'), ko('k2'), ok('k3'), ok('k4', false)],
  };

  it('renuméroter : colonnes réseau, NVR d’abord, OK/KO et détail à part', () => {
    const x = opsXlsx(renumber, account, t);
    const [sheet, info] = x.sheets;
    expect(sheet.name).toBe('«ops.xlsx.sheet»');
    expect(sheet.header).toEqual(NET_HEADER);
    // « À changer dans le NVR » en premier, puis l'ordre de l'opération.
    expect(sheet.rows.map((r) => r.cells[3])).toEqual(['10.0.50.13', '10.0.50.14', '10.0.50.11', '10.0.50.12', '10.0.50.15']);
    expect(sheet.rows[0]).toEqual({
      cells: ['«ops.xlsx.ok»', '', '«ops.xlsx.yes»', '10.0.50.13', '10.0.50.23', '255.255.254.0', '10.0.50.1', '10.0.50.2, 9.9.9.9', 'AXIS', 'Q6135', 'AC:CC:8E:00:00:0D', ''],
      tone: 'ok',
      highlight: [2],
    });
    // Écrite mais muette à la nouvelle adresse : KO, et quand même à changer dans le NVR.
    expect(sheet.rows[1]).toMatchObject({ tone: 'warn', highlight: [2] });
    expect(sheet.rows[1].cells.slice(0, 3)).toEqual(['«ops.xlsx.ko»', '«ops.state.unreachable»', '«ops.xlsx.yes»']);
    // IP inchangée : réussie, rien à changer.
    expect(sheet.rows[2]).toMatchObject({ tone: 'ok', highlight: [] });
    expect(sheet.rows[2].cells.slice(0, 3)).toEqual(['«ops.xlsx.ok»', '', '«ops.xlsx.no»']);
    expect(sheet.rows[2].cells.slice(8)).toEqual(['AXIS', 'M3106-L', 'AC:CC:8E:00:00:0B', 'ACCC8E00000B']);
    // Échec : la raison en clair, IP non changée.
    expect(sheet.rows[3]).toMatchObject({ tone: 'bad', highlight: [] });
    expect(sheet.rows[3].cells.slice(0, 3)).toEqual(['«ops.xlsx.ko»', '«configure.error.auth_failed»', '«ops.xlsx.no»']);
    // Non faite : KO, sans teinte.
    expect(sheet.rows[4]).toMatchObject({ tone: null, highlight: [] });
    expect(sheet.rows[4].cells.slice(0, 3)).toEqual(['«ops.xlsx.ko»', '«ops.xlsx.notDone»', '«ops.xlsx.no»']);

    expect(info.name).toBe('«ops.xlsx.info»');
    expect(info.header).toEqual([]);
    expect(info.rows.map((r) => r.cells)).toEqual([
      ['«ops.xlsx.infoCol.account»', 'Site A'],
      ['«ops.xlsx.infoCol.operation»', '«ops.kind.renumber»'],
      ['«ops.xlsx.infoCol.date»', '2026-11-17 09:05'],
      ['«ops.xlsx.infoCol.ok»', '2'],
      ['«ops.xlsx.infoCol.failed»', '2'],
      ['«ops.xlsx.infoCol.notDone»', '1'],
      ['«ops.xlsx.infoCol.nvr»', '2'],
    ]);
  });

  it('garder les IP : les mêmes colonnes, rien à changer dans le NVR', () => {
    const x = opsXlsx({ kind: 'keep_ip', at, cams: cams.slice(0, 1), rows: [row('k1', '10.0.50.11', '10.0.50.11')], results: [ok('k1')] }, account, t);
    expect(x.sheets[0].header).toEqual(NET_HEADER);
    expect(x.sheets[0].rows[0].cells[2]).toBe('«ops.xlsx.no»');
  });

  it('l’heure : identification et résultat, sans colonnes réseau', () => {
    const x = opsXlsx({ kind: 'time', at, cams: cams.slice(0, 2), rows: [row('k1', '10.0.50.11', null), row('k2', '10.0.50.12', null)], results: [ko('k1'), ok('k2', null)] }, account, t);
    const [sheet, info] = x.sheets;
    expect(sheet.header).toEqual(['result', 'detail', 'ip', 'brand', 'model', 'mac', 'serial'].map((c) => `«ops.xlsx.col.${c}»`));
    expect(sheet.rows.map((r) => r.cells)).toEqual([
      ['«ops.xlsx.ko»', '«configure.error.auth_failed»', '10.0.50.11', 'AXIS', 'M3106-L', 'AC:CC:8E:00:00:0B', 'ACCC8E00000B'],
      ['«ops.xlsx.ok»', '', '10.0.50.12', 'AXIS', 'P3268-LVE', '', ''],
    ]);
    expect(info.rows.map((r) => r.cells[0])).not.toContain('«ops.xlsx.infoCol.nvr»');
  });

  it('changer les identifiants : le login posé, jamais de mot de passe', () => {
    const results: CredResult[] = [
      { key: 'k1', code: 'posed', login: 'root' },
      { key: 'k2', code: 'already_up_to_date' },
      { key: 'k3', code: 'stopped_by_guard' },
      { key: 'k4', code: 'rejected', detail: 'Refusé par la caméra' },
    ];
    const run: OpsRun = { kind: 'change_credentials', at, cams: cams.slice(0, 4), rows: cams.slice(0, 4).map((c, i) => row(`k${i + 1}`, c.ip, null)), results };
    const x = opsXlsx(run, { ...account, password: 'S3cr3t' } as typeof account, t);
    const [sheet] = x.sheets;
    expect(sheet.header).toEqual(['result', 'detail', 'login', 'ip', 'brand', 'model', 'mac', 'serial'].map((c) => `«ops.xlsx.col.${c}»`));
    expect(sheet.rows.map((r) => [...r.cells.slice(0, 4), r.tone])).toEqual([
      ['«ops.xlsx.ok»', '«ops.cred.posed|{"login":"root"}»', 'lenscout', '10.0.50.11', 'ok'],
      ['«ops.xlsx.ok»', '«ops.cred.already»', 'lenscout', '10.0.50.12', 'ok'],
      ['«ops.xlsx.ko»', '«ops.cred.stopped»', '', '10.0.50.13', 'warn'],
      ['«ops.xlsx.ko»', 'Refusé par la caméra', '', '10.0.50.14', 'bad'],
    ]);
    expect(JSON.stringify(x)).not.toMatch(/password|S3cr3t/i);
  });

  it('nom du fichier : operations_<compte>_<date>.xlsx, sans caractère interdit', () => {
    expect(xlsxName('Site A/B', at)).toBe('operations_Site-A-B_2026-11-17_09-05.xlsx');
    expect(xlsxName('', at)).toBe('operations_2026-11-17_09-05.xlsx');
  });

  it('enregistrer : la commande reçoit le chemin et la description, rend le chemin écrit', async () => {
    invoke.mockResolvedValue('/x/operations.xlsx');
    const report = opsXlsx(renumber, account, t);
    expect(await saveXlsx('/x/operations', report)).toBe('/x/operations.xlsx');
    expect(invoke).toHaveBeenLastCalledWith('cmd_save_xlsx', { path: '/x/operations', report });
  });
});

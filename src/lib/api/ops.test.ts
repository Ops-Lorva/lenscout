import { describe, expect, it } from 'vitest';
import type { Camera } from './types';
import {
  canApply, cells, conflictMessage, credsRequest, credSummarize, isBlocking, isCredResult, movedIps, opRequest, opsFingerprint,
  runSteps, summarize,
  type CredResult, type OpRow, type OpsPreview, type StepResult,
} from './ops';

const row = (over: Partial<OpRow> = {}): OpRow => ({
  key: 'AC:CC:8E:00:00:0B',
  ip: '10.0.50.11',
  before: { addressing: 'static', ip: '10.0.50.11', mask: '255.255.255.0', gateway: '10.0.50.1', dns: ['10.0.50.2'] },
  after: { ip: '10.0.50.11', mask: '255.255.254.0', gateway: '10.0.50.1', dns: ['10.0.50.2'] },
  conflicts: [],
  ...over,
});

const preview = (rows: OpRow[], id: string | null = 'op-1'): OpsPreview => ({ id, rows });

const ok = (key: string, reachable: boolean | null = true): StepResult => ({ key, ok: true, error: null, reachable });
const ko = (key: string): StepResult => ({ key, ok: false, error: { code: 'auth_failed' }, reachable: null });

describe('opérations', () => {
  it('seul « hors du réseau du compte » laisse appliquer', () => {
    expect(isBlocking({ code: 'outside_account', network: '10.0.60.0/24' })).toBe(false);
    expect(isBlocking({ code: 'dhcp' })).toBe(true);
    expect(isBlocking({ code: 'ip_in_use', ip: '10.0.50.12', mac: null })).toBe(true);
  });

  it('Appliquer exige un plan gardé, sans conflit bloquant, rien en cours', () => {
    const p = preview(Array.from({ length: 37 }, () => row()));
    expect(canApply(p, false)).toBe(true);
    expect(canApply(p, true)).toBe(false);
    expect(canApply(null, false)).toBe(false);
    expect(canApply(preview([row()], null), false)).toBe(false);
    expect(canApply(preview([row({ conflicts: [{ code: 'unreadable' }] })]), false)).toBe(false);
    expect(canApply(preview([row({ conflicts: [{ code: 'outside_account', network: 'x' }] })]), false)).toBe(true);
  });

  it('chaque conflit a son message et ses valeurs', () => {
    expect(conflictMessage({ code: 'ip_in_use', ip: '10.0.50.12', mac: 'AA' })).toEqual({ key: 'ops.conflict.ip_in_use', values: { ip: '10.0.50.12' } });
    expect(conflictMessage({ code: 'outside_account', network: '10.0.60.0/24' })).toEqual({ key: 'ops.conflict.outside_account', values: { network: '10.0.60.0/24' } });
    expect(conflictMessage({ code: 'dhcp' })).toEqual({ key: 'ops.conflict.dhcp', values: {} });
  });

  it('« Garder les IP » : un champ vide reste inchangé (null)', () => {
    const f = { kind: 'keep_ip' as const, start: '', mask: ' 255.255.254.0 ', gateway: '', dns: '', ntp: '', timezone: 'UTC' };
    expect(opRequest(f)).toEqual({ kind: 'keep_ip', mask: '255.255.254.0', gateway: null, dns: null });
    expect(opRequest({ ...f, mask: '', dns: '1.1.1.1, 9.9.9.9' })).toEqual({ kind: 'keep_ip', mask: null, gateway: null, dns: ['1.1.1.1', '9.9.9.9'] });
  });

  it('renuméroter et l’heure reprennent les champs du lot et de l’action Heure', () => {
    const f = { kind: 'renumber' as const, start: '10.0.50.11', mask: '255.255.255.0', gateway: '10.0.50.1', dns: '10.0.50.1', ntp: 'pool.ntp.org', timezone: 'Europe/Paris' };
    expect(opRequest(f)).toEqual({ kind: 'renumber', start: '10.0.50.11', mask: '255.255.255.0', gateway: '10.0.50.1', dns: ['10.0.50.1'] });
    expect(opRequest({ ...f, kind: 'time' })).toEqual({ kind: 'time', ntp_servers: ['pool.ntp.org'], timezone: 'Europe/Paris' });
  });

  it('l’empreinte change avec la sélection, l’opération, un champ, l’interface ou le compte', () => {
    const cams = [{ mac: 'A', ip: '10.0.50.11' }, { mac: 'B', ip: '10.0.50.12' }] as Camera[];
    const f = { kind: 'keep_ip' as const, start: '', mask: '255.255.254.0', gateway: '', dns: '', ntp: '', timezone: 'UTC' };
    const base = opsFingerprint(cams, f, 'eth0', 'acc');
    expect(opsFingerprint(cams, { ...f }, 'eth0', 'acc')).toBe(base);
    expect(opsFingerprint(cams.slice(0, 1), f, 'eth0', 'acc')).not.toBe(base);
    expect(opsFingerprint(cams, { ...f, kind: 'time' }, 'eth0', 'acc')).not.toBe(base);
    expect(opsFingerprint(cams, { ...f, gateway: '10.0.50.1' }, 'eth0', 'acc')).not.toBe(base);
    expect(opsFingerprint(cams, f, 'eth1', 'acc')).not.toBe(base);
    expect(opsFingerprint(cams, f, 'eth0', 'other')).not.toBe(base);
  });

  it('avant → après, colonne par colonne ; une valeur inchangée reste seule', () => {
    const c = cells(row());
    expect(c.ip).toEqual({ before: '10.0.50.11', after: '10.0.50.11', changed: false });
    expect(c.mask).toEqual({ before: '255.255.255.0', after: '255.255.254.0', changed: true });
    expect(c.dns).toEqual({ before: '10.0.50.2', after: '10.0.50.2', changed: false });
    // Illisible : l'avant est inconnu.
    const r = cells(row({ before: null, after: { ip: '10.0.50.40', mask: '255.255.255.0', gateway: null, dns: [] } }));
    expect(r.ip).toEqual({ before: '10.0.50.11', after: '10.0.50.40', changed: true });
    expect(r.mask).toEqual({ before: null, after: '255.255.255.0', changed: true });
    expect(r.gateway).toEqual({ before: null, after: '', changed: true });
    // L'heure : pas de colonne réseau.
    expect(cells(row({ before: null, after: null })).mask).toEqual({ before: null, after: null, changed: false });
  });

  it('applique ligne après ligne et s’arrête avant la suivante sur Arrêter', async () => {
    const seen: number[] = [];
    let stop = false;
    const out = await runSteps(
      5,
      async (i) => {
        seen.push(i);
        if (i === 1) stop = true;
        return ok(`k${i}`);
      },
      () => stop,
      () => {},
    );
    expect(seen).toEqual([0, 1]);
    expect(out).toEqual({ stopped: true, done: 2 });
    const all: number[] = [];
    expect(await runSteps(3, async (i) => ok(`k${i}`), () => false, (i) => all.push(i))).toEqual({ stopped: false, done: 3 });
    expect(all).toEqual([0, 1, 2]);
  });

  it('une erreur de commande arrête la série et remonte', async () => {
    const seen: number[] = [];
    await expect(
      runSteps(3, async (i) => { seen.push(i); if (i === 1) throw 'preview_expired'; return ok('k'); }, () => false, () => {}),
    ).rejects.toBe('preview_expired');
    expect(seen).toEqual([0, 1]);
  });

  it('le rapport compte réussies, échouées, injoignables après changement, non faites', () => {
    expect(summarize([ok('a'), ko('b'), ok('c', false), ok('d', null), undefined], 6)).toEqual({ ok: 2, failed: 1, unreachable: 1, skipped: 2 });
  });

  it('nouvelle IP par clé, pour les seules lignes réussies d’un changement d’adresse', () => {
    const rows = [row({ key: 'A', after: { ip: '10.0.50.40', mask: 'm', gateway: null, dns: [] } }), row({ key: 'B' }), row({ key: 'C', after: null })];
    expect(movedIps(rows, [ok('A'), ko('B'), ok('C')])).toEqual({ A: '10.0.50.40' });
  });

  it('« changer les identifiants » : l’aperçu ne porte pas de secret, les secrets partent à part', () => {
    const f = { kind: 'change_credentials' as const, start: '', mask: '', gateway: '', dns: '', ntp: '', timezone: 'UTC' };
    expect(opRequest(f)).toEqual({ kind: 'change_credentials' });
    const req = credsRequest(' root ', 'N3w', [{ login: ' installer ', password: 'old' }, { login: '', password: '' }]);
    expect(req).toEqual({ kind: 'change_credentials', new_login: 'root', new_password: 'N3w', candidates: [{ login: 'installer', password: 'old' }] });
    // Un champ d’identifiant qui change invalide l’aperçu via l’empreinte (sans secret dedans).
    const cams = [{ mac: 'A', ip: '10.0.50.11' }] as Camera[];
    const base = opsFingerprint(cams, f, 'eth0', 'acc', '1');
    expect(opsFingerprint(cams, f, 'eth0', 'acc', '1')).toBe(base);
    expect(opsFingerprint(cams, f, 'eth0', 'acc', '2')).not.toBe(base);
    expect(base.includes('N3w')).toBe(false);
  });

  it('un résultat d’identifiants se distingue d’un pas réseau, et le rapport les compte', () => {
    const posed = (key: string, login: string): CredResult => ({ key, code: 'posed', login });
    expect(isCredResult(posed('a', 'root'))).toBe(true);
    expect(isCredResult(ok('b'))).toBe(false);
    const results: (CredResult | undefined)[] = [
      posed('a', 'root'),
      { key: 'b', code: 'already_up_to_date' },
      { key: 'c', code: 'no_credential' },
      { key: 'd', code: 'stopped_by_guard' },
      { key: 'e', code: 'unsupported' },
      { key: 'f', code: 'unreachable' },
      { key: 'g', code: 'rejected', detail: '# Error' },
      undefined,
    ];
    expect(credSummarize(results, 9)).toEqual({
      posed: 1, alreadyUpToDate: 1, noCredential: 1, stopped: 1, unsupported: 1, unreachable: 1, rejected: 1, skipped: 2,
    });
  });
});

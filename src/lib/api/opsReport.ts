import { resultMessage } from './configure';
import { cameraBrand, shownMac } from './discovery';
import { isCredResult, type AnyResult, type CredResult, type OpKind, type OpRow, type StepResult } from './ops';
import type { XlsxReport, XlsxRow, XlsxTone } from './report';
import type { Camera } from './types';

/** Une opération appliquée, telle que l'écran la garde. */
export interface OpsRun {
  kind: OpKind;
  rows: OpRow[];
  cams: Camera[];
  results: (AnyResult | undefined)[];
  at: Date;
}

type T = (key: string, values?: Record<string, string | number>) => string;

const pad = (n: number) => String(n).padStart(2, '0');
const day = (d: Date) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;

/** `operations_<compte>_<AAAA-MM-JJ>_<HH-MM>.xlsx`, sans caractère interdit dans un nom de fichier. */
export function xlsxName(account: string, d: Date): string {
  const safe = account.replace(/[\s/\\:*?"<>|]+/g, '-').replace(/^-+|-+$/g, '');
  return ['operations', safe, `${day(d)}_${pad(d.getHours())}-${pad(d.getMinutes())}`].filter(Boolean).join('_') + '.xlsx';
}

/** Une ligne : OK / KO (valeur stable, pour filtrer), la raison à part, la teinte. */
interface Outcome {
  ok: boolean;
  done: boolean;
  detail: string;
  tone: XlsxTone | null;
}

function stepOutcome(res: StepResult | undefined, t: T): Outcome {
  if (!res) return { ok: false, done: false, detail: t('ops.xlsx.notDone'), tone: null };
  if (!res.ok) {
    const m = resultMessage(res);
    return { ok: false, done: true, detail: m ? t(m.key, m.values) : '', tone: 'bad' };
  }
  // Écrite, mais muette à sa nouvelle adresse : à vérifier sur place.
  if (res.reachable === false) return { ok: false, done: true, detail: t('ops.state.unreachable'), tone: 'warn' };
  return { ok: true, done: true, detail: '', tone: 'ok' };
}

// Mêmes libellés que la colonne État de l'écran ; jamais de mot de passe.
function credOutcome(res: CredResult | undefined, t: T): Outcome {
  if (!res) return { ok: false, done: false, detail: t('ops.xlsx.notDone'), tone: null };
  const bad = (detail: string): Outcome => ({ ok: false, done: true, detail, tone: 'bad' });
  switch (res.code) {
    case 'posed': return { ok: true, done: true, detail: t('ops.cred.posed', { login: res.login }), tone: 'ok' };
    case 'already_up_to_date': return { ok: true, done: true, detail: t('ops.cred.already'), tone: 'ok' };
    case 'stopped_by_guard': return { ok: false, done: true, detail: t('ops.cred.stopped'), tone: 'warn' };
    case 'no_credential': return bad(t('ops.cred.none'));
    case 'unsupported': return bad(t('ops.conflict.unsupported'));
    case 'unreachable': return bad(t('ops.cred.unreachable'));
    case 'rejected': return bad(res.detail);
  }
}

const identity = (c: Camera | undefined): string[] =>
  c ? [cameraBrand(c) ?? '', c.model ?? '', shownMac(c).mac ?? '', c.serial ?? ''] : ['', '', '', ''];

/**
 * Le classeur d'une opération finie : une ligne par caméra, puis une feuille
 * Infos. Renuméroter / garder les IP : colonnes réseau et « À changer dans le
 * NVR » (Oui si l'IP a changé et que l'écriture a réussi), ces lignes en
 * premier. Changer les identifiants : le login posé (celui du compte),
 * jamais de mot de passe.
 */
export function opsXlsx(run: OpsRun, account: { name: string; login: string }, t: T): XlsxReport {
  const net = run.kind === 'keep_ip' || run.kind === 'renumber';
  const creds = run.kind === 'change_credentials';
  const cols = ['result', 'detail', ...(net ? ['nvr', 'oldIp', 'newIp', 'mask', 'gateway', 'dns'] : creds ? ['login', 'ip'] : ['ip']), 'brand', 'model', 'mac', 'serial'];

  const lines = run.rows.map((r, i) => {
    const res = run.results[i];
    const o = creds ? credOutcome(res as CredResult | undefined, t) : stepOutcome(res as StepResult | undefined, t);
    const head = [t(o.ok ? 'ops.xlsx.ok' : 'ops.xlsx.ko'), o.detail];
    let middle: string[];
    let nvr = false;
    if (net) {
      const b = r.before;
      const a = r.after;
      const oldIp = b?.ip ?? r.ip;
      nvr = !!a && !!res && !isCredResult(res) && res.ok && a.ip !== oldIp;
      const now = a ?? b;
      middle = [
        t(nvr ? 'ops.xlsx.yes' : 'ops.xlsx.no'), oldIp, a?.ip ?? '', now?.mask ?? '', now?.gateway ?? '', now?.dns.join(', ') ?? '',
      ];
    } else if (creds) {
      const posed = !!res && isCredResult(res) && (res.code === 'posed' || res.code === 'already_up_to_date');
      middle = [posed ? account.login : '', r.ip];
    } else {
      middle = [r.ip];
    }
    const row: XlsxRow = { cells: [...head, ...middle, ...identity(run.cams[i])], tone: o.tone, highlight: nvr ? [2] : [] };
    return { row, o, nvr };
  });
  // « À changer dans le NVR » d'abord ; le tri est stable, l'ordre de l'opération reste.
  const sorted = [...lines].sort((a, b) => Number(b.nvr) - Number(a.nvr));

  const count = (f: (l: (typeof lines)[number]) => boolean) => String(lines.filter(f).length);
  const info: [string, string][] = [
    ['account', account.name],
    ['operation', t(`ops.kind.${run.kind}`)],
    ['date', `${day(run.at)} ${pad(run.at.getHours())}:${pad(run.at.getMinutes())}`],
    ['ok', count((l) => l.o.ok)],
    ['failed', count((l) => l.o.done && !l.o.ok)],
    ['notDone', count((l) => !l.o.done)],
    ...(net ? [['nvr', count((l) => l.nvr)] as [string, string]] : []),
  ];

  return {
    sheets: [
      { name: t('ops.xlsx.sheet'), header: cols.map((c) => t(`ops.xlsx.col.${c}`)), rows: sorted.map((l) => l.row) },
      { name: t('ops.xlsx.info'), header: [], rows: info.map(([k, v]) => ({ cells: [t(`ops.xlsx.infoCol.${k}`), v], tone: null, highlight: [] })) },
    ],
  };
}

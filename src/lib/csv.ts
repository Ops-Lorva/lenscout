import type { Lang } from './i18n/index';

/** Excel lit `;` en français et en espagnol, `,` en anglais. */
const separator = (lang: Lang) => (lang === 'en' ? ',' : ';');

/**
 * Une cellule : une valeur qui commence comme une formule (`=`, `+`, `-`, `@`)
 * reçoit une apostrophe — un nom d'appareil vient du réseau et ne doit pas
 * s'exécuter dans un tableur ; puis guillemets si elle porte le séparateur,
 * un guillemet ou un saut de ligne (RFC 4180).
 */
function cell(value: string, sep: string): string {
  const v = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return v.includes(sep) || /["\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

/** CSV RFC 4180, fins de ligne CRLF, BOM UTF-8 (sans lui, Excel lit les accents de travers). */
export function toCsv(header: string[], rows: string[][], lang: Lang): string {
  const sep = separator(lang);
  return '﻿' + [header, ...rows].map((r) => r.map((c) => cell(c, sep)).join(sep) + '\r\n').join('');
}

const pad = (n: number) => String(n).padStart(2, '0');

/** `lenscout-<login|reseau>-<compte>-<AAAA-MM-JJ>.csv`, sans caractère interdit dans un nom de fichier. */
export function csvName(kind: 'login' | 'reseau', account: string, d: Date): string {
  const safe = account.replace(/[\s/\\:*?"<>|]+/g, '-').replace(/^-+|-+$/g, '');
  const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  return ['lenscout', kind, safe, date].filter(Boolean).join('-') + '.csv';
}

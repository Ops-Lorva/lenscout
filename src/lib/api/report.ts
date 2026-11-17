import { invoke } from '@tauri-apps/api/core';

/** Écrit un rapport CSV ; Rust impose l'extension `.csv`. Le chemin vient de la boîte Enregistrer. */
export const saveReport = (path: string, content: string) => invoke<void>('cmd_save_report', { path, content });

/** Miroir de `Tone` (xlsx.rs) : teinte d'une ligne. */
export type XlsxTone = 'ok' | 'bad' | 'warn';

/** Miroir de `Row` : `highlight` = colonnes mises en valeur sur la ligne. */
export interface XlsxRow {
  cells: string[];
  tone: XlsxTone | null;
  highlight: number[];
}

/** Miroir de `Sheet` : en-tête présent = tableau filtrable ; vide = couples libellé / valeur. */
export interface XlsxSheet {
  name: string;
  header: string[];
  rows: XlsxRow[];
}

/** Miroir de `Report` (xlsx.rs). */
export interface XlsxReport {
  sheets: XlsxSheet[];
}

/** Écrit un classeur `.xlsx` (extension imposée par Rust) ; rend le chemin écrit. */
export const saveXlsx = (path: string, report: XlsxReport) => invoke<string>('cmd_save_xlsx', { path, report });

import { invoke } from '@tauri-apps/api/core';

/** Écrit un rapport CSV ; Rust impose l'extension `.csv`. Le chemin vient de la boîte Enregistrer. */
export const saveReport = (path: string, content: string) => invoke<void>('cmd_save_report', { path, content });

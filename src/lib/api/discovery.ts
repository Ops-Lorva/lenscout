import { Channel, invoke } from '@tauri-apps/api/core';
import type { Camera } from './types';

/** Miroir de `ScanEvent` (discovery/scanner.rs). */
export type ScanEvent = { kind: 'upsert'; camera: Camera } | { kind: 'done' };

/** Rend la main à la fin du scan ; rejette si l'interface est inutilisable. */
export function startScan(iface: string, onEvent: (e: ScanEvent) => void): Promise<void> {
  const channel = new Channel<ScanEvent>();
  channel.onmessage = onEvent;
  return invoke<void>('cmd_scan_start', { iface, onEvent: channel });
}

export const cancelScan = () => invoke<void>('cmd_scan_cancel');

export const openCameraWeb = (ip: string, port: number) =>
  invoke<void>('cmd_open_camera_web', { ip, port });

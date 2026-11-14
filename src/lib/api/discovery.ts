import { Channel, invoke } from '@tauri-apps/api/core';
import type { Addressing, Camera } from './types';

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

/** Miroir de `AddressingOut` (commands/discovery.rs). */
export interface AddressingRead {
  ip: string;
  addressing: Addressing;
}

/**
 * Après un scan, avec le compte retenu : l'adressage des Axis, lu par Rust
 * (`Network.BootProto`, authentifié). Sans compte ou sans Axis, rien ne part.
 */
export function readAddressing(list: Camera[], accountId: string): Promise<AddressingRead[]> {
  const cameras = list.filter((c) => c.family === 'axis');
  if (!accountId || cameras.length === 0) return Promise.resolve([]);
  return invoke<AddressingRead[]>('cmd_read_addressing', { cameras, accountId });
}

/** Colonne MAC : celle vue sur le réseau, sinon celle que la caméra déclare (marquée). */
export function shownMac(c: Camera): { mac: string | null; declared: boolean } {
  if (c.mac) return { mac: c.mac, declared: false };
  return c.declared_mac ? { mac: c.declared_mac, declared: true } : { mac: null, declared: false };
}

/**
 * Libellé de la colonne Adressage : la valeur lue (SADP, ou Axis avec le
 * compte), sinon DHCP pour une Axis neuve (réglage d'usine), sinon « — ».
 */
export function addressingKey(c: Camera): string {
  const a = c.addressing ?? (c.family === 'axis' && c.activation === 'new' ? 'dhcp' : null);
  return `network.addressing.${a ?? 'unknown'}`;
}

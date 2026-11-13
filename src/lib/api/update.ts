import { invoke } from '@tauri-apps/api/core';

/** Miroir de `UpdateInfo` (updater.rs). */
export interface UpdateInfo {
  current_version: string;
  latest_version: string | null;
  has_update: boolean;
  asset_url: string | null;
  asset_name: string | null;
  platform_supported: boolean;
  release_notes_url: string | null;
}

export const DISMISS_KEY = 'lenscout.update.dismissed';

export const checkUpdate = () => invoke<UpdateInfo>('cmd_check_update');
export const applyUpdate = (url: string, assetName: string) =>
  invoke<string>('cmd_apply_update', { url, assetName });

/** Le bandeau n'apparaît que pour une version qu'on n'a pas déjà écartée. */
export function shouldShow(info: UpdateInfo | null, dismissed: string | null): info is UpdateInfo {
  return !!info && info.has_update && !!info.latest_version && info.latest_version !== dismissed;
}

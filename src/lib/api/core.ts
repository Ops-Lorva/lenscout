import { invoke } from '@tauri-apps/api/core';
import type { InterfaceDetails } from './types';

export const listInterfaces = () => invoke<string[]>('cmd_list_interfaces');
export const interfaceDetails = (name: string) =>
  invoke<InterfaceDetails>('cmd_interface_details', { name });
export const appVersion = () => invoke<string>('cmd_app_version');

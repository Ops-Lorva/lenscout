import { writable } from 'svelte/store';
import type { Camera } from '$lib/api/types';

export type Page = 'network' | 'framing' | 'accounts';

export const page = writable<Page>('network');

/** Caméra à cadrer, posée par l'onglet Réseau avant de passer à Cadrage. */
export const framingTarget = writable<Camera | null>(null);

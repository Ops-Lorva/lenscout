import { Channel, invoke } from '@tauri-apps/api/core';
import type { Camera } from './types';

/**
 * Démarre le flux : la promesse se résout à l'arrêt (ou au remplacement par un
 * autre flux) et échoue avec un code stable si le flux tombe. Les images
 * arrivent en octets bruts ; le mot de passe reste côté Rust.
 */
export function startStream(camera: Camera, accountId: string, onFrame: (buf: ArrayBuffer) => void): Promise<void> {
  const channel = new Channel<ArrayBuffer>();
  channel.onmessage = onFrame;
  return invoke<void>('cmd_stream_start', { camera, accountId, onFrame: channel });
}

export const stopStream = () => invoke<void>('cmd_stream_stop');

type Schedule = (fn: () => void) => void;

/**
 * Affiche les images une par une : chaque image devient un `Blob` et une URL
 * d'objet, l'URL précédente est révoquée. Si plusieurs images arrivent avant
 * le prochain affichage, seule la plus récente est gardée.
 */
export class FramePresenter {
  private pending: ArrayBuffer | null = null;
  private scheduled = false;
  private current: string | null = null;
  private disposed = false;

  constructor(
    private show: (url: string | null) => void,
    private schedule: Schedule = (fn) => requestAnimationFrame(() => fn()),
    private create: (b: Blob) => string = (b) => URL.createObjectURL(b),
    private revoke: (u: string) => void = (u) => URL.revokeObjectURL(u),
  ) {}

  push(buf: ArrayBuffer) {
    if (this.disposed) return;
    this.pending = buf; // écrase l'image non affichée : la plus ancienne est abandonnée
    if (this.scheduled) return;
    this.scheduled = true;
    this.schedule(() => this.flush());
  }

  private flush() {
    this.scheduled = false;
    const buf = this.pending;
    this.pending = null;
    if (!buf || this.disposed) return;
    const url = this.create(new Blob([buf], { type: 'image/jpeg' }));
    const old = this.current;
    this.current = url;
    this.show(url);
    if (old) this.revoke(old);
  }

  /** Retire l'image affichée (arrêt) sans fermer le présentateur. */
  clear() {
    this.pending = null;
    if (this.current) this.revoke(this.current);
    this.current = null;
    this.show(null);
  }

  dispose() {
    this.disposed = true;
    this.pending = null;
    if (this.current) this.revoke(this.current);
    this.current = null;
  }
}

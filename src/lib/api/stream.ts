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

/** Caméra d'une IP saisie dans Cadrage, identifiée par Rust (même garde de sous-réseau que le flux). */
export const identifyCamera = (ip: string, accountId: string) =>
  invoke<Camera>('cmd_identify_camera', { ip: ip.trim(), accountId });

/** Une image a été traitée (affichée ou abandonnée) : Rust peut en envoyer une autre. */
export const ackFrame = () => invoke<void>('cmd_stream_ack');

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
    // Appelé une fois par image poussée, affichée ou abandonnée : sert d'acquittement.
    private handled: () => void = () => {},
  ) {}

  push(buf: ArrayBuffer) {
    if (this.disposed) return this.handled();
    if (this.pending) this.handled(); // écrase l'image non affichée : la plus ancienne est abandonnée
    this.pending = buf;
    if (this.scheduled) return;
    this.scheduled = true;
    this.schedule(() => this.flush());
  }

  private flush() {
    this.scheduled = false;
    const buf = this.pending;
    this.pending = null;
    if (!buf) return;
    const url = this.create(new Blob([buf], { type: 'image/jpeg' }));
    const old = this.current;
    this.current = url;
    this.show(url);
    if (old) this.revoke(old);
    this.handled();
  }

  /** Retire l'image affichée (arrêt) sans fermer le présentateur. */
  clear() {
    this.dropPending();
    if (this.current) this.revoke(this.current);
    this.current = null;
    this.show(null);
  }

  private dropPending() {
    if (this.pending) this.handled();
    this.pending = null;
  }

  dispose() {
    this.disposed = true;
    this.dropPending();
    if (this.current) this.revoke(this.current);
    this.current = null;
  }
}

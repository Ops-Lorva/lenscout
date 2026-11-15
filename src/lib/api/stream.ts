import { Channel, invoke } from '@tauri-apps/api/core';
import type { Camera } from './types';

/**
 * Démarre le flux : la promesse se résout à l'arrêt (ou au remplacement par un
 * autre flux) et échoue avec un code stable si le flux tombe. Les images
 * arrivent en octets bruts ; le mot de passe reste côté Rust.
 */
export function startStream(
  camera: Camera,
  accountId: string,
  onFrame: (buf: ArrayBuffer) => void,
  view: View | null = null,
): Promise<void> {
  const channel = new Channel<ArrayBuffer>();
  channel.onmessage = onFrame;
  return invoke<void>('cmd_stream_start', {
    camera, accountId, view: view?.n ?? null, resolution: view?.resolution ?? null, onFrame: channel,
  });
}

/** Miroir de `View` (vapix.rs) : `n` = `camera=n` du flux, à partir de 1. */
export interface View {
  n: number;
  name: string | null;
  /** Capteur(s) de la vue (`Image.I<n-1>.Source`) : « 0 », ou « 1,0 » pour une vue groupée. */
  source?: string | null;
  /** Plus petite résolution annoncée pour la vue, demandée au flux. */
  resolution?: string | null;
}

/** Vues d'une Axis multicapteur, lues par Rust avec le compte ; ailleurs, rien ne part. */
export const listViews = (camera: Camera, accountId: string): Promise<View[]> =>
  camera.family === 'axis' && accountId ? invoke<View[]>('cmd_stream_views', { camera, accountId }) : Promise.resolve([]);

/** Option du sélecteur : le nom que la caméra donne à la vue, sinon « Vue N ». */
export const viewLabel = (v: View): { key: string; values: Record<string, string | number> } =>
  v.name ? { key: 'framing.viewNamed', values: { n: v.n, name: v.name } } : { key: 'framing.view', values: { n: v.n } };

export const stopStream = () => invoke<void>('cmd_stream_stop');

/** Caméra d'une IP saisie dans Cadrage, identifiée par Rust (même garde de sous-réseau que le flux). */
export const identifyCamera = (ip: string, accountId: string) =>
  invoke<Camera>('cmd_identify_camera', { ip: ip.trim(), accountId });

/**
 * La caméra posée par « Cadrer » mérite-t-elle d'être relue avec le compte ?
 * Le scan la pose telle qu'il l'a vue. Deux cas valent une relecture :
 * - marque non tranchée (« other »), d'où qu'elle vienne ;
 * - caméra vue au balayage du réseau routé (source « http ») et PAS confirmée
 *   Axis : ce balayage identifie sans compte, et une Axis multicapteur y paraît
 *   parfois Hikvision (basicdeviceinfo illisible à l'anonyme, repli sur une
 *   sonde d'une autre marque) — ni ses vues ni son panneau Axis n'apparaissent.
 * On la ré-identifie alors avec le compte, comme l'ouverture par IP, qui pose la
 * marque de façon autoritaire. `identify` ne rend jamais « other » et sa caméra
 * n'a pas de source (`sources: []`) : une fois reposée, la garde s'arrête (pas
 * de boucle). Une Axis confirmée à l'anonyme, ou une marque de couche 2
 * (ouverture par IP, SADP/mDNS/WSD), passe tout droit.
 */
export const needsIdentify = (cam: Camera): boolean =>
  cam.family === 'other' || (cam.family !== 'axis' && cam.sources.includes('http'));

/**
 * L'identité a-t-elle changé après relecture ? Famille, marque, modèle, série,
 * IP — et la source : `identify` rend une caméra sans source, donc une caméra
 * routée (`['http']`) relue change au moins par là, même à marque égale. On la
 * repose alors pour qu'elle cesse d'être « à relire » et que son flux démarre.
 */
export const identityChanged = (a: Camera, b: Camera): boolean =>
  a.ip !== b.ip || a.family !== b.family || a.brand !== b.brand || a.model !== b.model || a.serial !== b.serial ||
  a.sources.join() !== b.sources.join();

/**
 * Message visible quand l'identification ou la lecture des vues échoue dans
 * Cadrage, au lieu du silence : identifiants refusés d'un côté, tout le reste
 * (caméra injoignable, vues illisibles) de l'autre.
 */
export const noticeKey = (e: unknown): string =>
  e === 'auth_failed' || e === 'auth_insecure' ? 'framing.notice.authRefused' : 'framing.notice.unavailable';

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

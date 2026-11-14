<script lang="ts">
  import { onDestroy, tick, untrack } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { errorKey } from '$lib/api/errors';
  import { ackFrame, FramePresenter, identifyCamera, startStream, stopStream } from '$lib/api/stream';
  import { framingTarget, page, suspendStep } from '$lib/stores/nav';
  import AccountPicker from './AccountPicker.svelte';

  let accountId = $state('');
  let playing = $state(false);
  let src = $state<string | null>(null);
  let error = $state('');
  // Un start remplacé par un autre se résout aussi : seule la dernière
  // génération a le droit de toucher à l'état.
  let generation = 0;
  // Flux coupé parce que l'onglet est passé caché : à reprendre au retour.
  let suspended = false;

  const presenter = new FramePresenter(
    (u) => (src = u),
    undefined,
    undefined,
    undefined,
    () => void ackFrame().catch(() => {}),
  );
  const cam = $derived($framingTarget);

  // IP saisie : Rust identifie la caméra (même garde que le flux), qui
  // devient la cible comme si elle venait de Réseau, puis la lecture part.
  let typedIp = $state('');
  let identifying = $state(false);
  async function openTyped() {
    if (!typedIp.trim() || !accountId || identifying) return;
    identifying = true;
    error = '';
    try {
      const found = await identifyCamera(typedIp, accountId);
      framingTarget.set(found);
      await tick();
      void play();
    } catch (e) {
      error = $_(`framing.${errorKey(e)}`);
    } finally {
      identifying = false;
    }
  }

  async function play() {
    if (!cam || !accountId) return;
    const mine = ++generation;
    error = '';
    playing = true;
    try {
      await startStream(cam, accountId, (buf) => {
        if (mine === generation) presenter.push(buf);
      });
    } catch (e) {
      if (mine === generation) error = $_(`framing.${errorKey(e)}`);
    }
    if (mine === generation) {
      playing = false;
      presenter.clear();
    }
  }

  async function stop() {
    generation++;
    playing = false;
    presenter.clear();
    try { await stopStream(); } catch {}
  }

  // Ratio largeur/hauteur de l'image reçue ; 16/9 tant qu'aucune n'est décodée.
  let ratio = $state(16 / 9);
  function onLoad(e: Event) {
    const img = e.currentTarget as HTMLImageElement;
    if (img.naturalWidth > 0 && img.naturalHeight > 0) ratio = img.naturalWidth / img.naturalHeight;
  }

  function fullscreen(e: MouseEvent) {
    const el = e.currentTarget as HTMLElement;
    if (document.fullscreenElement) void document.exitFullscreen();
    else void el.requestFullscreen?.();
  }

  // Changer de caméra cible coupe le flux de la précédente (et oublie une
  // reprise en attente : c'était l'autre caméra).
  $effect(() => {
    void cam;
    untrack(() => {
      suspended = false;
      if (playing) void stop();
    });
  });

  // Onglet caché (il reste monté) : le flux est coupé, pas de bande
  // passante dans le dos ; il reprend au retour sur l'onglet.
  $effect(() => {
    const visible = $page === 'framing';
    untrack(() => {
      const step = suspendStep(visible, playing, suspended);
      if (step === 'suspend') {
        suspended = true;
        void stop();
      } else if (step === 'resume') {
        suspended = false;
        void play();
      } else if (visible) {
        suspended = false;
      }
    });
  });

  // Démontage (sortie de l'app) : coupe le flux et libère l'image.
  onDestroy(() => {
    generation++;
    presenter.dispose();
    void stopStream().catch(() => {});
  });
</script>

<div class="fbar">
  <form class="byip" onsubmit={(e) => { e.preventDefault(); void openTyped(); }}>
    <input type="text" bind:value={typedIp} placeholder="192.168.1.64" aria-label={$_('framing.ip')}
      inputmode="decimal" autocomplete="off" spellcheck="false" />
    <button class="btn" type="submit" disabled={!typedIp.trim() || !accountId || identifying}>
      {#if identifying}<span class="spin"></span>{/if}{$_('framing.open')}
    </button>
  </form>
  {#if cam}
    <strong>{[cam.brand, cam.model].filter(Boolean).join(' ')}</strong>
    <span class="ip">{cam.ip}</span>
  {/if}
  <span class="sp"></span>
  <label class="acc"><span class="dim-t">{$_('accounts.picker')}</span> <AccountPicker bind:accountId /></label>
  {#if cam}
    {#if playing}
      <button class="btn def" onclick={stop}>{$_('framing.stop')}</button>
    {:else}
      <button class="btn def" onclick={play} disabled={!accountId}>{$_('framing.play')}</button>
    {/if}
  {/if}
</div>
{#if error}<p class="err">{error}</p>{/if}
{#if !cam}
  <div class="none">{$_('framing.none')}</div>
{:else}
  <!-- Sans flux, la zone reste à sa place, vide et claire, pour que la fenêtre ne saute pas. -->
  <div class="view" class:off={!src} ondblclick={fullscreen} role="presentation">
    {#if src}
      <!-- Le cadre a le ratio réel de l'image : la grille des tiers et le
           réticule tombent sur l'image, jamais sur les bandes. -->
      <div class="frame" style:--r={ratio}>
        <img {src} alt={$_('framing.image')} onload={onLoad} />
        <div class="grid"></div>
        <div class="ret"></div>
      </div>
    {/if}
  </div>
{/if}

<style>
  .acc { display: inline-flex; align-items: center; gap: 6px; }
  .byip { display: inline-flex; align-items: center; gap: 6px; margin: 0; }
  .byip input { width: 130px; }
  .view { display: flex; align-items: center; justify-content: center; container-type: size; }
  /* Largeur bornée par la zone et par la hauteur transposée via le ratio (unités de conteneur). */
  .frame { position: relative; width: min(100%, calc(100cqh * var(--r))); aspect-ratio: var(--r); }
  .frame img { display: block; width: 100%; height: 100%; }
  /* Sans unités de conteneur (WebKit < 16) : l'image seule, centrée, sans grille. */
  @supports not (width: 1cqh) {
    .frame { width: 100%; align-self: stretch; aspect-ratio: auto; display: flex; align-items: center; justify-content: center; }
    .frame img { width: auto; height: auto; max-width: 100%; max-height: 100%; object-fit: contain; }
    .frame .grid, .frame .ret { display: none; }
  }
  .view:fullscreen { border-radius: 0; background: #000; }
</style>

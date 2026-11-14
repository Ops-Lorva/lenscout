<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { errorKey } from '$lib/api/errors';
  import { ackFrame, FramePresenter, startStream, stopStream } from '$lib/api/stream';
  import { framingTarget } from '$lib/stores/nav';
  import AccountPicker from './AccountPicker.svelte';

  let accountId = $state('');
  let playing = $state(false);
  let src = $state<string | null>(null);
  let error = $state('');
  // Un start remplacé par un autre se résout aussi : seule la dernière
  // génération a le droit de toucher à l'état.
  let generation = 0;

  const presenter = new FramePresenter(
    (u) => (src = u),
    undefined,
    undefined,
    undefined,
    () => void ackFrame().catch(() => {}),
  );
  const cam = $derived($framingTarget);

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

  function fullscreen(e: MouseEvent) {
    const el = e.currentTarget as HTMLElement;
    if (document.fullscreenElement) void document.exitFullscreen();
    else void el.requestFullscreen?.();
  }

  // Changer de caméra cible coupe le flux de la précédente.
  $effect(() => {
    void cam;
    untrack(() => {
      if (playing) void stop();
    });
  });

  // Quitter l'onglet coupe le flux et libère l'image.
  onDestroy(() => {
    generation++;
    presenter.dispose();
    void stopStream().catch(() => {});
  });
</script>

{#if !cam}
  <div class="none">{$_('framing.none')}</div>
{:else}
  <div class="fbar">
    <strong>{[cam.brand, cam.model].filter(Boolean).join(' ')}</strong>
    <span class="ip">{cam.ip}</span>
    <span class="sp"></span>
    <label class="acc"><span class="dim-t">{$_('accounts.picker')}</span> <AccountPicker bind:accountId /></label>
    {#if playing}
      <button class="btn def" onclick={stop}>{$_('framing.stop')}</button>
    {:else}
      <button class="btn def" onclick={play} disabled={!accountId}>{$_('framing.play')}</button>
    {/if}
  </div>
  {#if error}<p class="err">{error}</p>{/if}
  <!-- Sans flux, la zone reste à sa place, vide et claire, pour que la fenêtre ne saute pas. -->
  <div class="view" class:off={!src} ondblclick={fullscreen} role="presentation">
    {#if src}
      <img {src} alt={$_('framing.image')} />
      <!-- Grille des tiers et réticule du cadrage, par-dessus le flux. -->
      <div class="grid"></div>
      <div class="ret"></div>
    {/if}
  </div>
{/if}

<style>
  .acc { display: inline-flex; align-items: center; gap: 6px; }
  .view { display: flex; align-items: center; justify-content: center; }
  .view img { max-width: 100%; max-height: 100%; object-fit: contain; }
  .view:fullscreen { border-radius: 0; background: #000; }
</style>

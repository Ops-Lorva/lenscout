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
  <div class="muted">{$_('framing.none')}</div>
{:else}
  <div class="bar">
    <strong>{cam.model ?? cam.brand ?? ''}</strong>
    <span class="ip">{cam.ip}</span>
    <AccountPicker bind:accountId />
    {#if playing}
      <button class="primary" onclick={stop}>{$_('framing.stop')}</button>
    {:else}
      <button class="primary" onclick={play} disabled={!accountId}>{$_('framing.play')}</button>
    {/if}
  </div>
  {#if error}<div class="error">{error}</div>{/if}
  <div class="view" ondblclick={fullscreen} role="presentation">
    {#if src}<img {src} alt={$_('framing.image')} />{/if}
  </div>
{/if}

<style>
  .bar { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
  .ip { color: var(--ep-text-muted, inherit); font-variant-numeric: tabular-nums; }
  .error { color: var(--ep-danger); font-size: 12.5px; margin-bottom: 8px; }
  .muted { opacity: 0.7; }
  .view {
    flex: 1;
    min-height: 240px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #000;
    border-radius: 6px;
    overflow: hidden;
  }
  .view img { max-width: 100%; max-height: 100%; object-fit: contain; }
</style>

<script lang="ts">
  import { untrack } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { errorKey } from '#lib/api/errors.ts';
  import {
    readSettings, sendOptics, setBdc, setRotation, showBdc, showOptics, showRotation, toggleBdc, zoomRange,
    type FocusWindow, type ImageSettings, type OpticsCommand,
  } from '#lib/api/imaging.ts';
  import type { View } from '#lib/api/stream.ts';
  import type { Camera } from '#lib/api/types.ts';

  let {
    camera,
    accountId,
    view,
    drawing = $bindable(false),
    onRotated,
  }: {
    camera: Camera;
    accountId: string;
    view: View | null;
    drawing?: boolean;
    onRotated: () => void;
  } = $props();

  let settings = $state<ImageSettings | null>(null);
  let busy = $state(false);
  let error = $state('');
  // Valeurs des curseurs pendant le glissement ; envoyées au relâchement.
  let zoom = $state(1);
  let focus = $state(0);
  // Seule la dernière lecture lancée compte (autre caméra, autre vue, autre compte).
  let run = 0;

  function sync(s: ImageSettings | null) {
    settings = s;
    zoom = s?.optics?.magnification ?? 1;
    focus = s?.optics?.focus ?? 0;
  }

  $effect(() => {
    const c = camera;
    const a = accountId;
    const v = view;
    untrack(() => {
      const mine = ++run;
      sync(null);
      error = '';
      drawing = false;
      readSettings(c, a, v)
        .then((s) => {
          if (mine === run) sync(s);
        })
        .catch(() => {});
    });
  });

  /** Une commande d'optique ; les contrôles restent grisés jusqu'à la fin du mouvement (sondé par Rust). */
  async function optics(cmd: OpticsCommand) {
    if (busy || !settings) return;
    const mine = run;
    busy = true;
    error = '';
    try {
      const o = await sendOptics(camera, accountId, view, cmd);
      if (mine === run && settings) sync({ ...settings, optics: o });
    } catch (e) {
      if (mine === run) {
        error = `framing.${errorKey(e)}`;
        sync(settings);
      }
    } finally {
      busy = false;
    }
  }

  /** Zone tracée sur l'image (Cadrage) : posée, puis autofocus dessus. */
  export async function applyWindow(w: FocusWindow) {
    drawing = false;
    await optics({ kind: 'focus_window', window: w });
    if (!error) await optics({ kind: 'autofocus' });
  }

  async function rotate(degrees: number) {
    if (busy || !settings?.rotation) return;
    busy = true;
    error = '';
    const before = settings.rotation;
    try {
      await setRotation(camera, accountId, view, degrees);
      settings = { ...settings, rotation: { ...before, current: degrees } };
      onRotated();
    } catch (e) {
      error = `framing.${errorKey(e)}`;
      settings = { ...settings, rotation: before };
    } finally {
      busy = false;
    }
  }

  async function bdc(wanted: boolean) {
    if (busy || settings?.bdc == null) return;
    busy = true;
    error = '';
    const r = await toggleBdc(settings.bdc, wanted, (on) => setBdc(camera, accountId, view, on));
    if (settings) settings = { ...settings, bdc: r.on };
    if (r.error) error = `framing.${errorKey(r.error)}`;
    busy = false;
  }

  const o = $derived(settings?.optics ?? null);
  const range = $derived(o ? zoomRange(o) : null);
  const locked = $derived(busy || !!o?.moving);
</script>

{#if settings && (showOptics(settings) || showRotation(settings) || showBdc(settings))}
  <aside class="settings" aria-label={$_('framing.settings.title')}>
    {#if o && showOptics(settings)}
      {#if range}
        <label class="row">
          <span>{$_('framing.settings.zoom')}</span>
          <input type="range" min={range.min} max={range.max} step="0.01" bind:value={zoom} disabled={locked}
            onchange={() => optics({ kind: 'zoom', magnification: zoom })} />
          <span class="ends dim-t"><span>{$_('framing.settings.wide')}</span><span>{$_('framing.settings.tele')}</span></span>
        </label>
      {/if}
      {#if o.can_focus}
        <label class="row">
          <span>{$_('framing.settings.focus')}</span>
          <input type="range" min="0" max="1" step="0.001" bind:value={focus} disabled={locked}
            onchange={() => optics({ kind: 'focus', position: focus })} />
        </label>
        <div class="btns">
          <button class="btn def" disabled={locked} onclick={() => optics({ kind: 'autofocus' })}>{$_('framing.settings.autofocus')}</button>
          <span class="pair">
            <button class="btn" class:on={drawing} aria-pressed={drawing} disabled={locked} onclick={() => (drawing = !drawing)}>{$_('framing.settings.afArea')}</button>
            <button class="btn" disabled={locked} onclick={() => optics({ kind: 'reset_focus' })}>{$_('framing.settings.resetFocus')}</button>
          </span>
        </div>
      {/if}
    {/if}
    {#if settings.rotation && showRotation(settings)}
      <label class="row">
        <span>{$_('framing.settings.rotation')}</span>
        <select value={settings.rotation.current} disabled={busy} onchange={(e) => rotate(Number(e.currentTarget.value))}>
          {#each settings.rotation.allowed as r (r)}<option value={r}>{r}°</option>{/each}
        </select>
      </label>
    {/if}
    {#if settings.bdc != null}
      <label class="check">
        <input type="checkbox" checked={settings.bdc} disabled={busy} onchange={(e) => bdc(e.currentTarget.checked)} />
        {$_('framing.settings.bdc')}
      </label>
    {/if}
    {#if locked}<span class="spin"></span>{/if}
    {#if error}<p class="err">{$_(error)}</p>{/if}
  </aside>
{/if}

<style>
  /* Panneau de la maquette : collé à droite de l'image, groupes séparés par un filet. */
  .settings {
    width: 288px; flex: none; display: flex; flex-direction: column; overflow-y: auto;
    padding: 8px 24px 24px; border-left: 1px solid var(--line); background: var(--page);
  }
  .settings > * { padding: 16px 0; border-bottom: 1px solid var(--line); }
  .settings > :last-child { border-bottom: 0; }
  /* Curseur de mise au point et ses boutons : un seul groupe. */
  .settings > .row:has(+ .btns) { border-bottom: 0; padding-bottom: 8px; }
  .settings > .btns { padding-top: 0; }
  .row { display: flex; flex-direction: column; gap: 8px; }
  .row > span:first-child { color: var(--text-2); font-size: 13px; font-weight: 500; }
  .row input[type='range'] { width: 100%; }
  .ends { display: flex; justify-content: space-between; font-size: 12px; }
  .btns { display: flex; flex-direction: column; gap: 4px; align-items: stretch; }
  /* Libellés longs (« Réinitialiser la mise au point ») : l'un sous l'autre, pas en paire. */
  .pair { display: flex; flex-direction: column; gap: 4px; }
  .btns .btn.on { border-color: var(--act); background: var(--act-soft); color: var(--text); }
  .check { display: flex; align-items: center; gap: 8px; }
  .settings > .spin { padding: 0; border-bottom: 1.5px solid var(--line-2); align-self: flex-start; margin-top: 16px; }
  .settings > .err { padding: 0; border-bottom: 0; margin-top: 12px; }
</style>

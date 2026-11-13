<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { get } from 'svelte/store';
  import { _ } from 'svelte-i18n';
  import { listInterfaces } from '$lib/api/core';
  import { cancelScan, openCameraWeb, startScan } from '$lib/api/discovery';
  import type { Camera } from '$lib/api/types';
  import { errorKey } from '$lib/api/errors';
  import { cameraKey, cameras, clear, clearCameras, query, selection, shouldAutoScan, upsert, visibleCameras } from '$lib/stores/cameras';
  import { framingTarget, page } from '$lib/stores/nav';
  import ActionBar from './ActionBar.svelte';
  import CameraRow from './CameraRow.svelte';
  import { actionResults, resultFor } from '$lib/api/configure';

  const IFACE_KEY = 'lenscout.iface';
  const RESCAN_DELAYS_MS = [3000, 15000];

  let interfaces = $state<string[]>([]);
  let iface = $state('');
  let scanning = $state(false);
  let error = $state('');
  // Un scan annulé par le suivant peut encore livrer ses derniers événements :
  // chaque scan porte un numéro, les événements d'un ancien numéro sont ignorés.
  let run = 0;

  const shown = $derived($visibleCameras);
  const allSelected = $derived(shown.length > 0 && shown.every((c) => $selection.has(cameraKey(c))));

  // `keepSelection` : rescan différé d'une action IP, la sélection suit les MAC.
  async function scan(keepSelection = false) {
    if (!iface) return;
    const mine = ++run;
    error = '';
    scanning = true;
    if (keepSelection) clearCameras();
    else clear();
    try {
      await startScan(iface, (e) => {
        if (mine !== run) return;
        if (e.kind === 'upsert') upsert(e.camera);
      });
    } catch (e) {
      if (mine === run) error = $_(`network.${errorKey(e)}`);
    } finally {
      if (mine === run) scanning = false;
    }
  }

  function stop() {
    run++;
    scanning = false;
    void cancelScan();
  }

  function onIface(e: Event) {
    iface = (e.currentTarget as HTMLSelectElement).value;
    try { localStorage.setItem(IFACE_KEY, iface); } catch {}
    void scan();
  }

  function toggle(c: Camera) {
    selection.update((s) => {
      const next = new Set(s);
      const k = cameraKey(c);
      if (!next.delete(k)) next.add(k);
      return next;
    });
  }

  function toggleAll() {
    selection.update((s) => {
      const next = new Set(s);
      for (const c of shown) allSelected ? next.delete(cameraKey(c)) : next.add(cameraKey(c));
      return next;
    });
  }

  async function openWeb(c: Camera) {
    try {
      await openCameraWeb(c.ip, c.http_port);
    } catch (e) {
      error = $_(`network.${errorKey(e)}`);
    }
  }

  function frame(c: Camera) {
    framingTarget.set(c);
    page.set('framing');
  }

  onMount(async () => {
    try {
      interfaces = await listInterfaces();
    } catch (e) {
      error = $_(`network.${errorKey(e)}`);
      return;
    }
    let saved = '';
    try { saved = localStorage.getItem(IFACE_KEY) ?? ''; } catch {}
    iface = interfaces.includes(saved) ? saved : (interfaces[0] ?? '');
    // Retour sur la page : la liste et la sélection existantes restent ; « Rescanner » relance.
    if (shouldAutoScan(get(cameras))) void scan();
  });

  // Une caméra dont l'IP vient de changer met un instant à reparaître : on
  // rescanne après ce délai, sauf si la page a été quittée entre-temps.
  // Un second passage rattrape un bail DHCP lent.
  let rescanTimers: ReturnType<typeof setTimeout>[] = [];
  function rescanSoon() {
    rescanTimers.forEach(clearTimeout);
    rescanTimers = RESCAN_DELAYS_MS.map((d) => setTimeout(() => void scan(true), d));
  }

  onDestroy(() => {
    rescanTimers.forEach(clearTimeout);
    if (scanning) stop();
  });
</script>

<div class="bar">
  <select value={iface} onchange={onIface} disabled={interfaces.length === 0} aria-label={$_('common.interface.label')}>
    {#if interfaces.length === 0}<option value="">{$_('common.interface.none')}</option>{/if}
    {#each interfaces as name}<option value={name}>{name}</option>{/each}
  </select>
  {#if scanning}
    <button class="primary" onclick={stop}><span class="spinner"></span>{$_('network.stop')}</button>
  {:else}
    <button class="primary" onclick={() => scan()} disabled={!iface}>{$_('network.rescan')}</button>
  {/if}
  <input type="search" bind:value={$query} placeholder={$_('network.search')} />
</div>

{#if error}<div class="error">{error}</div>{/if}

<ActionBar {iface} onDone={rescanSoon} />

<table>
  <thead>
    <tr>
      <th><input type="checkbox" checked={allSelected} onchange={toggleAll} aria-label={$_('network.selectAll')} /></th>
      <th>{$_('network.col.camera')}</th>
      <th>{$_('network.col.ip')}</th>
      <th>{$_('network.col.mac')}</th>
      <th>{$_('network.col.serial')}</th>
      <th>{$_('network.col.firmware')}</th>
      <th>{$_('network.col.state')}</th>
      <th></th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    {#each shown as c (cameraKey(c))}
      <CameraRow
        camera={c}
        result={resultFor($actionResults, c)}
        selected={$selection.has(cameraKey(c))}
        onToggle={() => toggle(c)}
        onOpenWeb={() => openWeb(c)}
        onFrame={() => frame(c)}
      />
    {/each}
  </tbody>
</table>
{#if shown.length === 0 && !scanning}<div class="none">{$_('network.none')}</div>{/if}

<style>
  .bar { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; }
  .bar input[type='search'] {
    flex: 1; min-width: 0; padding: 5px 10px; font-size: 13px;
    background: var(--ep-bg-secondary); border: 1px solid var(--ep-border);
    border-radius: var(--ep-radius-md); color: var(--ep-text-primary);
  }
  .bar input[type='search']:focus { outline: none; border-color: var(--ep-accent); }
  .primary {
    display: inline-flex; align-items: center; gap: 6px; padding: 5px 14px; font-size: 13px; cursor: pointer;
    background: var(--ep-accent-dim); border: 1px solid var(--ep-accent-glow);
    border-radius: var(--ep-radius-md); color: var(--ep-accent-bright); font-weight: 600;
  }
  .primary:disabled { opacity: 0.55; cursor: not-allowed; }
  .spinner {
    width: 11px; height: 11px; border-radius: 50%;
    border: 2px solid var(--ep-accent-glow); border-top-color: var(--ep-accent-bright);
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .error { color: var(--ep-danger); font-size: 12.5px; margin-bottom: 10px; }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left; padding: 6px 10px; font-size: 11px; font-weight: 600; text-transform: uppercase;
    color: var(--ep-text-muted); border-bottom: 1px solid var(--ep-border-strong);
  }
  .none { color: var(--ep-text-muted); font-size: 12.5px; padding: 14px 10px; }
</style>

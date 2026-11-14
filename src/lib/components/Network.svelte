<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { get } from 'svelte/store';
  import { _ } from 'svelte-i18n';
  import { interfaceDetails, listInterfaces } from '$lib/api/core';
  import { cancelScan, openCameraWeb, startScan } from '$lib/api/discovery';
  import type { Camera } from '$lib/api/types';
  import { errorKey } from '$lib/api/errors';
  import { cameraKey, cameras, clear, clearCameras, query, selection, shouldAutoScan, upsert, visibleCameras } from '$lib/stores/cameras';
  import { clearStatusIf, framingTarget, page, status, type Status } from '$lib/stores/nav';
  import ActionBar from './ActionBar.svelte';
  import CameraRow from './CameraRow.svelte';
  import { actionResults, resultFor } from '$lib/api/configure';

  const IFACE_KEY = 'lenscout.iface';
  const RESCAN_DELAYS_MS = [3000, 15000];

  let interfaces = $state<string[]>([]);
  let iface = $state('');
  // Adresse de l'interface choisie, « 192.168.1.20/24 », à côté du select.
  let ifaceAddr = $state('');
  let scanning = $state(false);
  let error = $state('');
  // Un scan annulé par le suivant peut encore livrer ses derniers événements :
  // chaque scan porte un numéro, les événements d'un ancien numéro sont ignorés.
  let run = 0;

  const shown = $derived($visibleCameras);
  const allSelected = $derived(shown.length > 0 && shown.every((c) => $selection.has(cameraKey(c))));

  /** `255.255.255.0` → 24 ; masque absent ou illisible → l'adresse seule. */
  function cidr(ip: string | null, mask: string | null): string {
    if (!ip) return '';
    const bits = (mask ?? '').split('.').reduce((n, x) => n + ((Number(x) >>> 0).toString(2).match(/1/g)?.length ?? 0), 0);
    return bits > 0 ? `${ip}/${bits}` : ip;
  }

  async function loadAddr(name: string) {
    ifaceAddr = '';
    if (!name) return;
    try {
      const d = await interfaceDetails(name);
      if (name === iface) ifaceAddr = cidr(d.ip, d.subnet);
    } catch {}
  }

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
    void loadAddr(iface);
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

  // La barre d'état porte la recherche en cours : interface et compte de caméras.
  // On ne retire que son propre message : un autre écran a pu poser le sien.
  let scanStatus: Status | null = null;
  $effect(() => {
    if (scanning) {
      scanStatus = { text: $_('network.scanning', { values: { iface, count: $cameras.length } }) };
      status.set(scanStatus);
    } else {
      clearStatusIf(scanStatus);
      scanStatus = null;
    }
  });

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
    void loadAddr(iface);
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
    clearStatusIf(scanStatus);
  });
</script>

<div class="tools">
  <select value={iface} onchange={onIface} disabled={interfaces.length === 0} aria-label={$_('common.interface.label')}>
    {#if interfaces.length === 0}<option value="">{$_('common.interface.none')}</option>{/if}
    {#each interfaces as name}<option value={name}>{name}</option>{/each}
  </select>
  {#if ifaceAddr}<span class="iface">{ifaceAddr}</span>{/if}
  {#if scanning}
    <button class="btn" onclick={stop}><span class="spin"></span>{$_('network.stop')}</button>
  {:else}
    <button class="btn def" onclick={() => scan()} disabled={!iface}>{$_('network.rescan')}</button>
  {/if}
  <input type="search" bind:value={$query} placeholder={$_('network.search')} aria-label={$_('network.search')} />
</div>

{#if error}<p class="err">{error}</p>{/if}

<ActionBar {iface} onDone={rescanSoon} />

<div class="scroll">
  <table>
    <thead>
      <tr>
        <th class="chk"><input type="checkbox" checked={allSelected} onchange={toggleAll} aria-label={$_('network.selectAll')} /></th>
        <th>{$_('network.col.camera')}</th>
        <th>{$_('network.col.ip')}</th>
        <th>{$_('network.col.mac')}</th>
        <th>{$_('network.col.serial')}</th>
        <th>{$_('network.col.firmware')}</th>
        <th>{$_('network.col.state')}</th>
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
</div>

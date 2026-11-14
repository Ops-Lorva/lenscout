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
  import { joinable, listAccounts, type Account } from '$lib/api/accounts';
  import { createJoinSwitch, joined, joinedNetwork, joinNetwork, joinReady, leaveNetwork, type JoinChoice } from '$lib/api/net';

  const IFACE_KEY = 'lenscout.iface';
  const RESCAN_DELAYS_MS = [3000, 15000];

  let interfaces = $state<string[]>([]);
  let iface = $state('');
  // Adresse de l'interface choisie, « 192.168.1.20/24 », à côté du select.
  let ifaceAddr = $state('');
  let scanning = $state(false);
  // Sélecteur de compte : `''` = DHCP (aucune IP ajoutée), sinon l'id du compte
  // dont l'IP du PC est posée sur l'interface. Un choix vaut validation.
  let accounts = $state<Account[]>([]);
  let account = $state('');
  let switching = $state(false);
  // L'IP du compte vient d'être posée : on attend de la voir sur le poste avant de scanner.
  let posing = $state(false);
  const choices = $derived(joinable(accounts));
  // DHCP : l'adresse actuelle de l'interface ; compte : l'IP réellement posée.
  const shownAddr = $derived(account ? ($joined?.account_id === account ? $joined.cidr : '') : ifaceAddr);
  const sw = createJoinSwitch({ join: joinNetwork, leave: leaveNetwork });
  let failStatus: Status | null = null;
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

  /**
   * Un changement d'interface ou de compte : l'IP du compte est posée (la
   * précédente retirée d'abord) ou retirée (DHCP), puis l'adresse affichée et
   * le scan sont remis à jour. Les sélecteurs sont grisés pendant l'opération.
   * Échec : le choix revient à l'état réel du cœur, message dans la barre d'état.
   */
  async function choose(wanted: JoinChoice) {
    if (switching) return;
    switching = true;
    clearStatusIf(failStatus);
    const r = await sw.change(wanted);
    if (r.kind === 'failed') {
      // Le cœur a pu retirer l'IP précédente avant d'échouer : on se recale sur lui.
      let j = null;
      try { j = await joinedNetwork(); } catch {}
      sw.init(r.applied.iface, j);
      joined.set(j);
      failStatus = { text: $_(`network.${errorKey(r.code)}`), tone: 'warn' };
      status.set(failStatus);
    } else if (r.kind === 'done') {
      joined.set(r.applied.account ? (r.joined ?? $joined) : null);
    }
    ({ iface, account } = sw.applied);
    switching = false;
    try { localStorage.setItem(IFACE_KEY, iface); } catch {}
    void loadAddr(iface);
    if (r.kind === 'done' && r.applied.account && !(await ready())) return;
    if (r.kind === 'done' || iface !== wanted.iface || account !== r.applied.account) void scan();
  }

  /** L'adresse posée est-elle sur le poste ? Sinon message clair, et pas de scan. */
  async function ready(): Promise<boolean> {
    posing = true;
    error = '';
    try {
      await joinReady();
      return true;
    } catch (e) {
      error = $_(`network.${errorKey(e)}`);
      return false;
    } finally {
      posing = false;
    }
  }

  function onIface(e: Event) {
    const next = (e.currentTarget as HTMLSelectElement).value;
    iface = next;
    void choose({ iface: next, account });
  }

  function onAccount(e: Event) {
    const next = (e.currentTarget as HTMLSelectElement).value;
    account = next;
    void choose({ iface, account: next });
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
    try { accounts = await listAccounts(); } catch {}
    // Retour sur l'écran : un compte déjà posé reste choisi, sur son interface.
    let j = null;
    try { j = await joinedNetwork(); } catch {}
    sw.init(iface, j && interfaces.includes(j.iface) ? j : null);
    ({ iface, account } = sw.applied);
    joined.set(j);
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
    clearStatusIf(failStatus);
  });
</script>

<div class="tools">
  <select value={iface} onchange={onIface} disabled={interfaces.length === 0 || switching} aria-label={$_('common.interface.label')}>
    {#if interfaces.length === 0}<option value="">{$_('common.interface.none')}</option>{/if}
    {#each interfaces as name}<option value={name}>{name}</option>{/each}
  </select>
  <select value={account} onchange={onAccount} disabled={!iface || switching} aria-label={$_('network.account')}>
    <option value="">{$_('network.dhcp')}</option>
    {#each choices as a (a.id)}<option value={a.id}>{a.name}</option>{/each}
  </select>
  {#if switching}<span class="spin"></span>{:else if shownAddr}<span class="iface">{shownAddr}</span>{/if}
  {#if scanning}
    <button class="btn" onclick={stop}><span class="spin"></span>{$_('network.stop')}</button>
  {:else if posing}
    <button class="btn def" disabled><span class="spin"></span>{$_('network.posing')}</button>
  {:else}
    <button class="btn def" onclick={() => scan()} disabled={!iface || switching}>{$_('network.rescan')}</button>
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

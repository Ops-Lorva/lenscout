<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { get } from 'svelte/store';
  import { _ } from 'svelte-i18n';
  import { interfaceDetails, listInterfaces } from '#lib/api/core.ts';
  import { cancelScan, openCameraWeb, readAddressing, startScan } from '#lib/api/discovery.ts';
  import type { Camera } from '#lib/api/types.ts';
  import { errorKey } from '#lib/api/errors.ts';
  import { cameraCounts, cameraKey, cameras, clear, filter, query, selection, setAddressing, shouldAutoScan, sort, type SortColumn, toggleSort, upsert, visibleCameras } from '#lib/stores/cameras.ts';
  import { clearStatusIf, framingTarget, page, scanIface, status, type Status } from '#lib/stores/nav.ts';
  import ActionBar from './ActionBar.svelte';
  import CameraRow from './CameraRow.svelte';
  import { actionResults, resultFor } from '#lib/api/configure.ts';
  import { accountList, ensureAccounts } from '#lib/stores/accounts.ts';
  import {
    accountChoices, canScan, createJoinSwitch, generations, joined, joinedNetwork, joinNetwork, joinReady, leaveNetwork, shownAddress, type JoinChoice,
  } from '#lib/api/net.ts';

  const IFACE_KEY = 'lenscout.iface';

  let interfaces = $state<string[]>([]);
  let iface = $state('');
  // Adresse de l'interface choisie, « 192.168.1.20/24 », à côté du select.
  let ifaceAddr = $state('');
  let scanning = $state(false);
  // Sélecteur de compte : `''` = DHCP (aucune IP ajoutée), sinon l'id du compte
  // dont l'IP du PC est posée sur l'interface. Un choix vaut validation.
  let account = $state('');
  let switching = $state(false);
  // L'IP du compte vient d'être posée : on attend de la voir sur le poste avant de scanner.
  let posing = $state(false);
  // Seule la dernière attente de pose compte (une plus ancienne ne touche à rien).
  const poses = generations();
  // Liste partagée : un compte ajouté ou importé apparaît sans quitter l'onglet ;
  // un compte supprimé alors que son IP est posée reste, marqué.
  const choices = $derived($accountList ? accountChoices($accountList, $joined) : []);
  // DHCP : l'adresse actuelle de l'interface ; compte : l'IP réellement posée ;
  // mode routé : celle de l'interface, et la passerelle du routeur.
  const shown_ = $derived(shownAddress(account, $joined, ifaceAddr));
  const shownAddr = $derived(shown_.addr);
  const sw = createJoinSwitch({ join: joinNetwork, leave: leaveNetwork });
  let failStatus: Status | null = null;
  let error = $state('');
  // Un scan annulé par le suivant peut encore livrer ses derniers événements :
  // chaque scan porte un numéro, les événements d'un ancien numéro sont ignorés.
  let run = 0;

  const shown = $derived($visibleCameras);
  const filterTabs = $derived([
    { key: 'all' as const, n: $cameraCounts.all },
    { key: 'new' as const, n: $cameraCounts.new },
    { key: 'activated' as const, n: $cameraCounts.activated },
  ]);
  const allSelected = $derived(shown.length > 0 && shown.every((c) => $selection.has(cameraKey(c))));

  // En-têtes triables : l'état du tri vit dans le store, l'en-tête actif porte
  // la flèche (▲/▼) et `aria-sort`.
  const ariaSort = (col: SortColumn): 'ascending' | 'descending' | 'none' =>
    $sort.col === col ? ($sort.dir === 'asc' ? 'ascending' : 'descending') : 'none';
  const arrow = (col: SortColumn): string => ($sort.col === col ? ($sort.dir === 'asc' ? '▲' : '▼') : '');

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

  async function scan() {
    // Premier affichage ou Rescanner : rien pendant la pose d'une IP.
    if (!canScan(iface, posing)) return;
    const mine = ++run;
    error = '';
    scanning = true;
    clear();
    try {
      await startScan(iface, account, (e) => {
        if (mine !== run) return;
        if (e.kind === 'upsert') upsert(e.camera);
      });
      // Après la découverte, sans la ralentir : l'adressage des Axis avec le
      // compte du réseau retenu. Un échec laisse « — ».
      if (mine === run && account) {
        const forAccount = account;
        void readAddressing(get(cameras), forAccount)
          .then((r) => { if (mine === run && account === forAccount) setAddressing(r); })
          .catch(() => {});
      }
    } catch (e) {
      if (mine === run) error = `network.${errorKey(e)}`;
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
      failStatus = { text: { key: `network.${errorKey(r.code)}` }, tone: 'warn' };
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

  /**
   * L'adresse posée est-elle sur le poste ? Sinon message clair, pas de scan,
   * et plus de caméras du réseau précédent à l'écran.
   */
  async function ready(): Promise<boolean> {
    const mine = poses.next();
    posing = true;
    error = '';
    // Plus rien de l'ancien réseau : le scan en cours est arrêté (ses derniers
    // événements sont ignorés, il ne re-remplit pas la liste).
    if (scanning) stop();
    try {
      await joinReady();
      return poses.current(mine);
    } catch (e) {
      if (poses.current(mine)) {
        error = `network.${errorKey(e)}`;
        clear();
      }
      return false;
    } finally {
      if (poses.current(mine)) posing = false;
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
      error = `network.${errorKey(e)}`;
    }
  }

  function frame(c: Camera) {
    framingTarget.set(c);
    page.set('framing');
  }

  // La barre d'état porte la recherche en cours : interface et compte de caméras.
  // On ne retire que son propre message : un autre écran a pu poser le sien.
  // Onglet caché (il reste monté, le scan continue) : la barre est à l'écran visible.
  let scanStatus: Status | null = null;
  const visible = $derived($page === 'network');
  $effect(() => {
    if (!visible) clearStatusIf(failStatus);
  });
  $effect(() => {
    if (scanning && visible) {
      scanStatus = { text: { key: 'network.scanning', values: { iface, count: $cameras.length } } };
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
      error = `network.${errorKey(e)}`;
      return;
    }
    let saved = '';
    try { saved = localStorage.getItem(IFACE_KEY) ?? ''; } catch {}
    iface = interfaces.includes(saved) ? saved : (interfaces[0] ?? '');
    try { await ensureAccounts(); } catch {}
    // Retour sur l'écran : un compte déjà posé reste choisi, sur son interface.
    let j = null;
    try { j = await joinedNetwork(); } catch {}
    sw.init(iface, j && interfaces.includes(j.iface) ? j : null);
    ({ iface, account } = sw.applied);
    joined.set(j);
    void loadAddr(iface);
    // L'écran reste monté : le premier scan part au premier affichage, ensuite
    // seuls Rescanner et un changement d'interface ou de compte en relancent.
    if (shouldAutoScan(get(cameras))) {
      if (visible) void scan();
      else firstScanPending = true;
    }
  });

  let firstScanPending = false;
  $effect(() => {
    if (visible && firstScanPending) {
      firstScanPending = false;
      void scan();
    }
  });

  // Pas de rescan automatique : après une action la ligne se met à jour sur
  // place (nouvelle IP, « IP fixe »…), et le technicien rafraîchit quand il
  // veut avec le bouton Rescanner. Après une réinitialisation d'usine, la
  // caméra redémarre (~1 min) ; il rescanne une fois qu'elle est revenue.

  // Opérations écrit par l'interface du scan : elle doit la connaître.
  $effect(() => scanIface.set(iface));

  let barOpen = $state<'activate' | 'network' | 'batch' | 'time' | 'reset' | null>(null);

  onDestroy(() => {
    if (scanning) stop();
    clearStatusIf(scanStatus);
    clearStatusIf(failStatus);
  });
</script>

<div class="tools bar">
  <span class="title">{$_('common.nav.network')}</span>
  <label class="field">{$_('common.interface.label')}
    <select value={iface} onchange={onIface} disabled={interfaces.length === 0 || switching || posing} aria-label={$_('common.interface.label')}>
      {#if interfaces.length === 0}<option value="">{$_('common.interface.none')}</option>{/if}
      {#each interfaces as name}<option value={name}>{name}</option>{/each}
    </select>
  </label>
  <label class="field">{$_('accounts.picker')}
    <select value={account} onchange={onAccount} disabled={!iface || switching || posing} aria-label={$_('network.account')}>
      <option value="">{$_('network.dhcp')}</option>
      {#each choices as a (a.id)}<option value={a.id}>{a.deleted ? $_('network.deletedAccount') : a.name}</option>{/each}
    </select>
  </label>
  {#if switching}<span class="spin"></span>{:else if shownAddr}<span class="iface">{shownAddr}{#if shown_.via}<span class="via">{$_('network.via', { values: { gateway: shown_.via } })}</span>{/if}</span>{/if}
  <input type="search" bind:value={$query} placeholder={$_('network.search')} aria-label={$_('network.search')} />
  {#if scanning}
    <button class="btn" onclick={stop}><span class="spin"></span>{$_('network.stop')}</button>
  {:else if posing}
    <button class="btn" disabled><span class="spin"></span>{$_('network.posing')}</button>
  {:else}
    <button class="btn" onclick={() => scan()} disabled={!iface || switching}>{$_('network.rescan')}</button>
  {/if}
</div>

<!-- Onglets d'état : filtrent la liste, avec le compte par onglet. -->
<div class="tabs">
  {#each filterTabs as t (t.key)}
    <button class="tab" class:on={$filter === t.key} onclick={() => filter.set(t.key)}>
      {$_(`network.filter.${t.key}`)} <span class="n">{t.n}</span>
    </button>
  {/each}
</div>

{#if error}<p class="err">{$_(error)}</p>{/if}

<ActionBar {iface} bind:open={barOpen} />

<style>
  .tabs { display: flex; gap: 2px; padding: 10px 24px 2px; }
  .tab { display: inline-flex; align-items: center; gap: 6px; padding: 5px 12px; border: 0; border-radius: 6px; background: none; color: var(--text-2); font: inherit; font-weight: 500; cursor: pointer; }
  .tab:hover { background: var(--hover); color: var(--text); }
  .tab.on { background: var(--sel); color: var(--text); }
  .tab .n { font-variant-numeric: tabular-nums; font-size: 12px; color: var(--text-2); }
  .tab.on .n { color: var(--act); }

  /* En-tête triable : le bouton remplit la cellule, hérite de la typo de `th`. */
  .sort { display: inline-flex; align-items: center; gap: 4px; padding: 0; border: 0; background: none; font: inherit; color: inherit; cursor: pointer; }
  .sort:hover { color: var(--text); }
  .sort.on { color: var(--text); }
  .sort .arr { font-size: 9px; color: var(--act); }
</style>

<div class="scroll">
  <table>
    <thead>
      <tr>
        <th class="chk"><input type="checkbox" checked={allSelected} onchange={toggleAll} aria-label={$_('network.selectAll')} /></th>
        <th aria-sort={ariaSort('camera')}><button class="sort" class:on={$sort.col === 'camera'} onclick={() => toggleSort('camera')}>{$_('network.col.camera')}<span class="arr" aria-hidden="true">{arrow('camera')}</span></button></th>
        <th style="width:128px" aria-sort={ariaSort('ip')}><button class="sort" class:on={$sort.col === 'ip'} onclick={() => toggleSort('ip')}>{$_('network.col.ip')}<span class="arr" aria-hidden="true">{arrow('ip')}</span></button></th>
        <th style="width:164px" aria-sort={ariaSort('mac')}><button class="sort" class:on={$sort.col === 'mac'} onclick={() => toggleSort('mac')}>{$_('network.col.mac')}<span class="arr" aria-hidden="true">{arrow('mac')}</span></button></th>
        <th style="width:128px" aria-sort={ariaSort('serial')}><button class="sort" class:on={$sort.col === 'serial'} onclick={() => toggleSort('serial')}>{$_('network.col.serial')}<span class="arr" aria-hidden="true">{arrow('serial')}</span></button></th>
        <th style="width:96px" aria-sort={ariaSort('firmware')}><button class="sort" class:on={$sort.col === 'firmware'} onclick={() => toggleSort('firmware')}>{$_('network.col.firmware')}<span class="arr" aria-hidden="true">{arrow('firmware')}</span></button></th>
        <th style="width:112px" aria-sort={ariaSort('addressing')}><button class="sort" class:on={$sort.col === 'addressing'} onclick={() => toggleSort('addressing')}>{$_('network.col.addressing')}<span class="arr" aria-hidden="true">{arrow('addressing')}</span></button></th>
        <th style="width:112px" aria-sort={ariaSort('state')}><button class="sort" class:on={$sort.col === 'state'} onclick={() => toggleSort('state')}>{$_('network.col.state')}<span class="arr" aria-hidden="true">{arrow('state')}</span></button></th>
        <th class="acts"></th>
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

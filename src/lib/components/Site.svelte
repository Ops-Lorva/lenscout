<script lang="ts">
  import { untrack } from 'svelte';
  import { _, locale } from 'svelte-i18n';
  import {
    accountCameras, accountFill, fillLabel, forgetCamera, knownKey, networkEnds, segmentBox, sortKnown,
    type Account, type KnownCamera, type KnownSortColumn, type NetworkFill,
  } from '#lib/api/accounts.ts';
  import { errorKey } from '#lib/api/errors.ts';
  import { maskOf } from '#lib/api/net.ts';
  import { accountReservations, type ReservedIp } from '#lib/api/siteNet.ts';
  import { openFraming, scanIface, siteRequest } from '#lib/stores/nav.ts';
  import AccountPicker from './AccountPicker.svelte';
  import Dialog from './Dialog.svelte';
  import SiteSurvey from './SiteSurvey.svelte';
  import SiteFree from './SiteFree.svelte';

  // Le site d'un client = le réseau de son compte : occupation, caméras
  // connues, relevé et inventaire. Sorti de la fiche du compte pour avoir
  // la place ; la fiche n'y garde qu'un lien (« Voir le site »).
  let accountId = $state('');
  let account = $state<Account | null>(null);
  let error = $state('');

  // « Voir le site » d'une fiche : ce compte-là, comme un choix dans le sélecteur.
  $effect(() => {
    const req = $siteRequest;
    if (!req) return;
    untrack(() => {
      accountId = req;
      siteRequest.set(null);
    });
  });

  // Réseau du compte choisi, tel qu'enregistré : remplissage et caméras connues.
  let fill = $state<NetworkFill | null>(null);
  let known = $state<KnownCamera[]>([]);
  let reservations = $state<ReservedIp[]>([]);
  // Sous-onglet sous la barre : l'inventaire relevé, ou les IP libres et réservées.
  let view = $state<'devices' | 'free'>('devices');
  // Clé de la caméra dont l'oubli attend sa confirmation.
  let forgetting = $state('');
  // Liste des caméras connues ouverte en grand, pour tout voir à l'aise.
  let expanded = $state(false);
  // Tri de la modale (local, par IP croissante au départ) : clic sur un en-tête
  // trie, re-clic inverse le sens.
  let knownSort = $state<{ col: KnownSortColumn; dir: 'asc' | 'desc' }>({ col: 'ip', dir: 'asc' });
  const sortedKnown = $derived(sortKnown(known, knownSort));
  const toggleKnownSort = (col: KnownSortColumn) =>
    (knownSort = knownSort.col === col ? { col, dir: knownSort.dir === 'asc' ? 'desc' : 'asc' } : { col, dir: 'asc' });
  const knownAria = (col: KnownSortColumn): 'ascending' | 'descending' | 'none' =>
    knownSort.col === col ? (knownSort.dir === 'asc' ? 'ascending' : 'descending') : 'none';
  const knownArrow = (col: KnownSortColumn): string => (knownSort.col === col ? (knownSort.dir === 'asc' ? '▲' : '▼') : '');
  const ends = $derived(fill ? networkEnds(fill.network) : null);
  const counts = $derived(fill ? fillLabel(fill) : null);
  const seenOn = (c: KnownCamera) => new Date(c.last_seen * 1000).toLocaleDateString($locale ?? undefined);
  // Type d'identité affiché : numéro de série sinon adresse MAC, comme `knownKey`.
  const idType = (c: KnownCamera) => $_(c.serial ? 'accounts.net.serial' : 'accounts.net.mac');

  /** Remplissage et caméras du compte ; ignoré si le compte a changé entre-temps. Un échec laisse le bloc caché. */
  async function loadNet(id: string) {
    try {
      const [f, k, r] = await Promise.all([accountFill(id), accountCameras(id), accountReservations(id)]);
      if (accountId !== id) return;
      fill = f;
      known = [...k].sort((a, b) => b.last_seen - a.last_seen);
      reservations = r;
    } catch {}
  }

  // Autre compte, ou le même enregistré à nouveau (IP du PC, exclusions) : on relit.
  $effect(() => {
    const a = account;
    untrack(() => {
      fill = null;
      known = [];
      reservations = [];
      forgetting = '';
      expanded = false;
      error = '';
      if (a) void loadNet(a.id);
    });
  });

  /** Deux clics, comme Supprimer : le premier demande confirmation. */
  async function forget(c: KnownCamera) {
    const key = knownKey(c);
    if (forgetting !== key) {
      forgetting = key;
      return;
    }
    forgetting = '';
    const id = accountId;
    if (!id) return;
    try {
      await forgetCamera(id, key);
    } catch (e) {
      error = `accounts.${errorKey(e)}`;
    }
    await loadNet(id);
  }
</script>

<div class="tools bar">
  <span class="title">{$_('common.nav.site')}</span>
  <label class="field">{$_('accounts.picker')} <AccountPicker bind:accountId bind:account /></label>
</div>

{#if error}<p class="err">{$_(error)}</p>{/if}

{#if account}
  <div class="site">
    {#if fill || known.length > 0}
      <section class="subnet">
        <div class="sh">
          <span>{$_('accounts.net.title')}</span>
          {#if fill?.almost_full}<span class="warn">{$_('accounts.net.almostFull')}</span>{/if}
        </div>
        {#if fill}
          <div class="strip" role="img" aria-label={fill.network}>
            {#each fill.segments as seg (`${seg.kind}-${seg.first}`)}
              {@const b = segmentBox(seg, fill.size)}
              <span class="k-{seg.kind}" style="left:{b.left}%;width:{b.width}%"></span>
            {/each}
          </div>
          {#if ends}<div class="ends"><span class="m">{ends[0]}</span><span class="m">{ends[1]}</span></div>{/if}
          <ul class="legend">
            {#if fill.gateway}<li><i class="k-gateway"></i>{$_('accounts.net.gateway')}</li>{/if}
            <li><i class="k-pc"></i>{$_('accounts.net.pc')}</li>
            {#if fill.excluded}<li><i class="k-excluded"></i>{$_('accounts.net.excluded')} {fill.excluded}</li>{/if}
            {#if fill.reserved}<li><i class="k-reserved"></i>{$_('accounts.net.reserved')} {fill.reserved}</li>{/if}
            <li><i class="k-camera"></i>{$_('accounts.net.cameras')}{#if fill.cameras}{' '}{fill.cameras}{/if}</li>
            {#if fill.devices}<li><i class="k-device"></i>{$_('accounts.net.devices')} {fill.devices}</li>{/if}
            <!-- Avec des appareils relevés, la ligne d'occupation dit tout (pourcentage compris). -->
            {#if counts && !(fill.devices || fill.crowded)}<li class="count">{$_('accounts.net.summary', { values: counts })}</li>{/if}
          </ul>
          {#if fill.devices || fill.crowded}
            <div class="used" class:warn={fill.crowded}>
              <span>{$_('accounts.net.used', { values: { pct: fill.used_pct, free: fill.free, usable: fill.usable } })}</span>
              {#if fill.suggest}<span>{$_('accounts.net.crowded', { values: { prefix: fill.suggest.split('/')[1], mask: maskOf(fill.suggest) } })}</span>{/if}
            </div>
          {/if}
        {/if}
        {#if known.length > 0}
          <details>
            <summary>
              <span>{$_('accounts.net.known', { values: { count: known.length } })}</span>
              <button class="expand" type="button" aria-label={$_('accounts.net.expand')} title={$_('accounts.net.expand')}
                onclick={(e) => { e.preventDefault(); e.stopPropagation(); knownSort = { col: 'ip', dir: 'asc' }; expanded = true; }}>
                <svg viewBox="0 0 16 16" aria-hidden="true">
                  <path d="M6 2H2v4M10 2h4v4M6 14H2v-4M10 14h4v-4" />
                </svg>
              </button>
            </summary>
            <div class="known">
              <table>
                <tbody>
                  {#each known as c (knownKey(c))}
                    <tr>
                      <td class="mono">{c.ip}</td>
                      <td class="grow" title={c.model ?? ''}>{c.model ?? ''}</td>
                      <td class="mono dim-t" title={knownKey(c)}>{knownKey(c)}</td>
                      <td class="dim-t">{$_('accounts.net.seen', { values: { date: seenOn(c) } })}</td>
                      <td class="ra">
                        <button class="mini" type="button" class:danger={forgetting === knownKey(c)} onclick={() => forget(c)}>
                          {forgetting === knownKey(c) ? $_('accounts.net.confirmForget') : $_('accounts.net.forget')}
                        </button>
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          </details>
        {/if}
      </section>
    {/if}
    <!-- IP libres : seulement avec un réseau (IP du PC) à mesurer. -->
    {#if fill}
      <div class="tabs">
        <button class="tab" type="button" class:on={view === 'devices'} onclick={() => (view = 'devices')}>{$_('sitenet.tab.devices')}</button>
        <button class="tab" type="button" class:on={view === 'free'} onclick={() => (view = 'free')}>
          {$_('sitenet.tab.free')} <span class="n">{fill.free}</span>
        </button>
      </div>
    {/if}
    <!-- Relevé et inventaire : visibles même sans IP du PC (le relevé dit alors « hors du réseau »).
         Caché, pas démonté : un relevé en cours continue pendant qu'on regarde les IP libres. -->
    <section class="survey" hidden={!!fill && view !== 'devices'}>
      <SiteSurvey accountId={account.id} accountName={account.name} pcIp={account.pc_ip ?? null} iface={$scanIface}
        onDone={() => { if (account) void loadNet(account.id); }}
        onFrame={(ip) => { if (account) openFraming(ip, account.id); }} />
    </section>
    {#if fill && view === 'free'}
      <section class="survey">
        <SiteFree accountId={account.id} {fill} {reservations} onChange={async () => { if (account) await loadNet(account.id); }} />
      </section>
    {/if}
  </div>
{/if}

{#if expanded && account}
  <Dialog title={$_('accounts.net.known', { values: { count: known.length } })} subtitle={account.name} width={720} onClose={() => (expanded = false)}>
    <div class="bigknown">
      <table>
        <thead>
          <tr>
            <th aria-sort={knownAria('ip')}><button class="sort" class:on={knownSort.col === 'ip'} onclick={() => toggleKnownSort('ip')}>{$_('accounts.net.colIp')}<span class="arr" aria-hidden="true">{knownArrow('ip')}</span></button></th>
            <th aria-sort={knownAria('id')}><button class="sort" class:on={knownSort.col === 'id'} onclick={() => toggleKnownSort('id')}>{$_('accounts.net.colId')}<span class="arr" aria-hidden="true">{knownArrow('id')}</span></button></th>
            <th aria-sort={knownAria('type')}><button class="sort" class:on={knownSort.col === 'type'} onclick={() => toggleKnownSort('type')}>{$_('accounts.net.colType')}<span class="arr" aria-hidden="true">{knownArrow('type')}</span></button></th>
            <th class="grow" aria-sort={knownAria('model')}><button class="sort" class:on={knownSort.col === 'model'} onclick={() => toggleKnownSort('model')}>{$_('accounts.net.colModel')}<span class="arr" aria-hidden="true">{knownArrow('model')}</span></button></th>
            <th aria-sort={knownAria('seen')}><button class="sort" class:on={knownSort.col === 'seen'} onclick={() => toggleKnownSort('seen')}>{$_('accounts.net.colSeen')}<span class="arr" aria-hidden="true">{knownArrow('seen')}</span></button></th>
            <th class="acts"></th>
          </tr>
        </thead>
        <tbody>
          {#each sortedKnown as c (knownKey(c))}
            <tr>
              <td class="mono">{c.ip}</td>
              <td class="mono dim-t" title={knownKey(c)}>{knownKey(c)}</td>
              <td class="dim-t">{idType(c)}</td>
              <td class="grow" title={c.model ?? ''}>{c.model ?? ''}</td>
              <td class="dim-t">{seenOn(c)}</td>
              <td class="ra">
                <button class="mini" type="button" class:danger={forgetting === knownKey(c)} onclick={() => forget(c)}>
                  {forgetting === knownKey(c) ? $_('accounts.net.confirmForget') : $_('accounts.net.forget')}
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <div class="foot">
      <span class="sum"></span>
      <button class="btn def" type="button" onclick={() => (expanded = false)}>{$_('accounts.net.close')}</button>
    </div>
  </Dialog>
{/if}

<style>
  .tools .title { flex: none; margin-right: 6px; }
  .site { display: flex; flex-direction: column; gap: 16px; padding: 16px 24px 0; }
  .survey { display: flex; flex-direction: column; gap: 12px; }
  .survey[hidden] { display: none; }
  .tabs { display: flex; gap: 2px; margin-bottom: -4px; }
  .tab { display: inline-flex; align-items: center; gap: 6px; padding: 5px 12px; border: 0; border-radius: 6px; background: none; color: var(--text-2); font: inherit; font-weight: 500; cursor: pointer; }
  .tab:hover { background: var(--hover); color: var(--text); }
  .tab.on { background: var(--sel); color: var(--text); }
  .tab .n { font-variant-numeric: tabular-nums; font-size: 12px; color: var(--text-2); }
  .tab.on .n { color: var(--act); }
  .tab:focus-visible { outline: 2px solid var(--act); outline-offset: 1px; }
  /* Le réseau du compte : barre à l'échelle du réseau, libres = le fond.
     Passerelle en bleu froid (mesurée), PC en ambre (posé par la personne). */
  .subnet { display: flex; flex-direction: column; gap: 8px; padding: 16px; border: 1px solid var(--line); border-radius: 10px; background: var(--win); }
  .subnet .sh { display: flex; justify-content: space-between; gap: 8px; font-weight: 500; font-size: 14px; }
  .subnet .sh .warn { color: var(--warn); font-weight: 500; }
  /* En grand dans la page : la barre gagne en hauteur. */
  .strip { position: relative; height: 36px; border-radius: 4px; background: var(--page); border: 1px solid var(--line); overflow: hidden; }
  .strip span { position: absolute; top: 0; bottom: 0; min-width: 3px; }
  .k-gateway { background: var(--cool); }
  .k-pc { background: var(--act); }
  .k-camera { background: var(--ok); }
  .k-device { background: var(--text-2); }
  .used { display: flex; justify-content: space-between; gap: 8px; flex-wrap: wrap; color: var(--text-ink2); font-size: 13px; }
  .used.warn { color: var(--warn); }
  .k-excluded { background: repeating-linear-gradient(135deg, var(--line-2) 0 2px, transparent 2px 5px); }
  .legend .k-excluded { border: 1px solid var(--line-2); }
  /* Réservée : une caméra à venir, hachurée dans la couleur des caméras. */
  .k-reserved { background: repeating-linear-gradient(135deg, var(--ok) 0 2px, transparent 2px 5px); }
  .legend .k-reserved { border: 1px solid var(--ok); }
  .ends { display: flex; justify-content: space-between; color: var(--text-2); font-size: 12px; }
  .legend { display: flex; flex-wrap: wrap; gap: 4px 16px; margin: 0; padding: 0; list-style: none; color: var(--text-ink2); font-size: 13px; }
  .legend li { display: inline-flex; align-items: center; gap: 8px; }
  .legend i { width: 12px; height: 12px; border-radius: 2px; }
  .legend .count { margin-left: auto; color: var(--text-2); }
  .subnet summary { cursor: pointer; color: var(--text-2); font-size: 13px; }
  /* Titre « N caméras connues » et bouton Agrandir sur la même ligne. */
  .subnet summary { display: flex; align-items: center; gap: 8px; }
  .subnet summary > span { flex: 1; }
  .expand {
    flex: none; width: 24px; height: 22px; padding: 0; border: 0; border-radius: 5px;
    background: transparent; color: var(--text-2); cursor: pointer;
    display: inline-flex; align-items: center; justify-content: center;
  }
  .expand:hover { color: var(--text); }
  .expand:focus-visible { outline: 2px solid var(--act); outline-offset: 1px; }
  .expand svg { width: 14px; height: 14px; fill: none; stroke: currentColor; stroke-width: 1.3; stroke-linecap: round; stroke-linejoin: round; }
  .known { max-height: 240px; overflow-y: auto; margin-top: 4px; }
  .known td { height: 36px; }
  .known tbody tr:last-child td { border-bottom: 0; }
  /* Liste en grand : toute la largeur de la feuille, hauteur plafonnée et défilante. */
  .bigknown { max-height: 60vh; overflow-y: auto; }
  .bigknown td { height: 36px; }
  .bigknown tbody tr:last-child td { border-bottom: 0; }
  /* En-tête triable de la modale : le bouton hérite de la typo de `th`. */
  .bigknown .sort { display: inline-flex; align-items: center; gap: 4px; padding: 0; border: 0; background: none; font: inherit; color: inherit; cursor: pointer; }
  .bigknown .sort:hover, .bigknown .sort.on { color: var(--text); }
  .bigknown .sort .arr { font-size: 9px; color: var(--act); }
</style>

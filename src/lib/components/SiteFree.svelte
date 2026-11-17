<script lang="ts">
  import { _, locale } from 'svelte-i18n';
  import type { NetworkFill } from '#lib/api/accounts.ts';
  import { errorKey } from '#lib/api/errors.ts';
  import { freeAddresses, releaseIp, reserveIp, type ReservedIp } from '#lib/api/siteNet.ts';

  // IP libres du réseau du compte, d'après la barre, et IP réservées : une
  // caméra posée sur une adresse mais pas encore joignable (switch pas prêt)
  // n'apparaît dans aucun relevé ; la réserver l'ôte des adresses proposées
  // partout (feuilles, recherche d'IP libres). Un relevé qui l'entend la
  // libère seul (Rust). `onChange` : réservées ou barre à relire.
  let {
    accountId,
    fill,
    reservations,
    onChange,
  }: { accountId: string; fill: NetworkFill; reservations: ReservedIp[]; onChange: () => Promise<void> | void } = $props();

  // Plafond d'affichage : un /16 compte des dizaines de milliers d'adresses ;
  // la recherche retrouve celles au-delà.
  const CAP = 512;
  let query = $state('');
  const free = $derived(freeAddresses(fill, query, CAP));
  // Adresse en cours de réservation (saisie du libellé) et ce libellé.
  let picking = $state('');
  let label = $state('');
  let releasing = $state('');
  let busy = $state(false);
  let error = $state('');
  const reservedOn = (r: ReservedIp) => new Date(r.at * 1000).toLocaleDateString($locale ?? undefined);

  function pick(ip: string) {
    picking = ip;
    label = '';
    error = '';
  }

  async function reserve() {
    if (!picking || busy) return;
    busy = true;
    error = '';
    try {
      await reserveIp(accountId, picking, label);
      picking = '';
      label = '';
      await onChange();
    } catch (e) {
      error = `accounts.${errorKey(e)}`;
    } finally {
      busy = false;
    }
  }

  /** Deux clics, comme Oublier : le premier demande confirmation. */
  async function release(r: ReservedIp) {
    if (releasing !== r.ip) {
      releasing = r.ip;
      return;
    }
    releasing = '';
    error = '';
    try {
      await releaseIp(accountId, r.ip);
    } catch (e) {
      error = `accounts.${errorKey(e)}`;
    }
    await onChange();
  }
</script>

{#if error}<p class="err">{$_(error)}</p>{/if}

{#if reservations.length > 0}
  <div class="sh">{$_('sitenet.free.reserved', { values: { count: reservations.length } })}</div>
  <table class="list">
    <thead>
      <tr>
        <th style="width:134px">{$_('sitenet.col.ip')}</th>
        <th>{$_('sitenet.free.label')}</th>
        <th style="width:120px">{$_('sitenet.free.at')}</th>
        <th style="width:110px"></th>
      </tr>
    </thead>
    <tbody>
      {#each reservations as r (r.ip)}
        <tr>
          <td class="mono">{r.ip}</td>
          <td class="cut" title={r.label ?? ''}>{r.label ?? ''}</td>
          <td class="dim-t">{reservedOn(r)}</td>
          <td class="ra">
            <button class="mini" type="button" class:danger={releasing === r.ip} onclick={() => release(r)}>
              {releasing === r.ip ? $_('sitenet.confirmForget') : $_('sitenet.free.release')}
            </button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

<div class="bar">
  <input type="search" bind:value={query} placeholder={$_('sitenet.free.search')} aria-label={$_('sitenet.free.search')}
    inputmode="decimal" spellcheck="false" />
</div>
<table class="list">
  <thead>
    <tr>
      <th style="width:134px">{$_('sitenet.col.ip')}</th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    {#each free.ips as ip (ip)}
      <tr>
        <td class="mono">{ip}</td>
        <td class="ra">
          {#if picking === ip}
            <form class="pick" onsubmit={(e) => { e.preventDefault(); void reserve(); }}>
              <!-- svelte-ignore a11y_autofocus -->
              <input type="text" bind:value={label} placeholder={$_('sitenet.free.label')} aria-label={$_('sitenet.free.label')}
                maxlength="64" autocomplete="off" spellcheck="false" autofocus
                onkeydown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); picking = ''; } }} />
              <button class="mini" type="button" onclick={() => (picking = '')}>{$_('sitenet.free.cancel')}</button>
              <button class="mini" type="submit" disabled={busy}>{$_('sitenet.free.reserve')}</button>
            </form>
          {:else}
            <button class="mini" type="button" onclick={() => pick(ip)}>{$_('sitenet.free.reserve')}</button>
          {/if}
        </td>
      </tr>
    {/each}
    {#if free.more}<tr><td class="dim-t" colspan="2">…</td></tr>{/if}
  </tbody>
</table>
{#if free.ips.length === 0}<div class="none">{$_('sitenet.free.none')}</div>{/if}

<style>
  .sh { font-weight: 500; font-size: 14px; }
  .bar { display: flex; align-items: center; gap: 10px; }
  .bar input { flex: 1; min-width: 180px; max-width: 320px; }
  .list { table-layout: fixed; width: 100%; }
  .list td { height: 34px; }
  .list .mono { font-size: 12.5px; }
  .list tbody tr:last-child td { border-bottom: 0; }
  .cut { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .pick { display: inline-flex; align-items: center; gap: 4px; margin: 0; }
  .pick input { width: 200px; height: 26px; }
  .none { padding: 16px 0; color: var(--text-2); text-align: center; }
  .err { margin: 0; color: var(--err); font-size: 12.5px; }
</style>

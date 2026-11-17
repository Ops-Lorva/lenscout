<script lang="ts">
  import { _, locale } from 'svelte-i18n';
  import { save as saveFile } from '@tauri-apps/plugin-dialog';
  import { errorKey } from '#lib/api/errors.ts';
  import { saveReport } from '#lib/api/report.ts';
  import {
    absent, DEVICE_KINDS, deviceKey, deviceName, devicesCsvRows, filterDevices, forgetDevice, frameIp, stale, type DeviceKind, type SeenDevice,
  } from '#lib/api/siteNet.ts';
  import { csvLang, csvName, toCsv } from '#lib/csv.ts';

  // Inventaire du réseau du compte, dans la page Site : filtre par type,
  // recherche, export de la vue, Oublier en deux clics (comme les caméras
  // connues). `onFrame` : une caméra (ligne cliquée ou Cadrer) part au Cadrage.
  let {
    accountId,
    accountName = '',
    devices,
    surveyedAt,
    onForgot,
    onFrame,
  }: {
    accountId: string;
    accountName?: string;
    devices: SeenDevice[];
    surveyedAt: number | null;
    onForgot: () => Promise<void> | void;
    onFrame: (ip: string) => void;
  } = $props();

  let kinds = $state<Set<DeviceKind>>(new Set());
  let query = $state('');
  let forgetting = $state('');
  let error = $state('');
  let exported = $state('');

  const ipNum = (ip: string) => ip.split('.').reduce((n, x) => n * 256 + (Number(x) || 0), 0);
  const sorted = $derived([...devices].sort((a, b) => ipNum(a.ip) - ipNum(b.ip)));
  const shown = $derived(filterDevices(sorted, kinds, query));
  const counts = $derived(devices.reduce<Partial<Record<DeviceKind, number>>>((m, d) => ((m[d.kind] = (m[d.kind] ?? 0) + 1), m), {}));
  // Vu il y a plus de six mois : ne compte plus pris, atténué comme un absent.
  const now = Date.now() / 1000;
  const seenOn = (unix: number) => new Date(unix * 1000).toLocaleDateString($locale ?? undefined);

  function toggle(k: DeviceKind) {
    const next = new Set(kinds);
    if (!next.delete(k)) next.add(k);
    kinds = next;
  }

  async function forget(d: SeenDevice) {
    const key = deviceKey(d);
    if (forgetting !== key) {
      forgetting = key;
      return;
    }
    forgetting = '';
    error = '';
    try {
      await forgetDevice(accountId, key);
    } catch (e) {
      error = `free.${errorKey(e)}`;
    }
    await onForgot();
  }

  async function doExport() {
    error = '';
    exported = '';
    try {
      const path = await saveFile({ defaultPath: csvName('reseau', accountName, new Date()), filters: [{ name: 'CSV', extensions: ['csv'] }] });
      if (!path) return;
      const csv = devicesCsvRows(shown, (k) => $_(k), seenOn);
      await saveReport(path, toCsv(csv.header, csv.rows, csvLang($locale)));
      exported = path;
    } catch (e) {
      error = `free.${errorKey(e)}`;
    }
  }
</script>

<div class="devices">
  <div class="bar">
    <div class="tabs">
      <button class="tab" type="button" class:on={kinds.size === 0} onclick={() => (kinds = new Set())}>
        {$_('sitenet.all')} <span class="n">{devices.length}</span>
      </button>
      {#each DEVICE_KINDS as k (k)}
        {#if counts[k]}
          <button class="tab" type="button" class:on={kinds.has(k)} onclick={() => toggle(k)} aria-pressed={kinds.has(k)}>
            {$_(`sitenet.kind.${k}`)} <span class="n">{counts[k]}</span>
          </button>
        {/if}
      {/each}
    </div>
    <input type="search" bind:value={query} placeholder={$_('sitenet.search')} aria-label={$_('sitenet.search')} spellcheck="false" />
    <button class="btn" type="button" onclick={doExport} disabled={shown.length === 0}>{$_('sitenet.export')}</button>
  </div>
  {#if error || exported}
    <p class="sum" class:e={!!error}>{#if error}{$_(error)}{:else}{$_('sitenet.exported')} : <span class="m">{exported}</span>{/if}</p>
  {/if}
  <div class="big">
    <table>
      <thead>
        <tr>
          <th style="width:134px">{$_('sitenet.col.ip')}</th>
          <th style="width:170px">{$_('sitenet.col.mac')}</th>
          <th>{$_('sitenet.col.vendor')}</th>
          <th style="width:96px">{$_('sitenet.col.kind')}</th>
          <th>{$_('sitenet.col.name')}</th>
          <th style="width:120px">{$_('sitenet.col.seen')}</th>
          <th style="width:176px"></th>
        </tr>
      </thead>
      <tbody>
        {#each shown as d (deviceKey(d))}
          {@const gone = absent(d, surveyedAt)}
          {@const ip = frameIp(d)}
          <!-- Clic sur la ligne d'une caméra : le Cadrage. Au clavier, le bouton Cadrer de la ligne. -->
          <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
          <tr class:gone={gone || stale(d, now)} class:frame={ip !== null} onclick={() => { if (ip !== null) onFrame(ip); }}>
            <td class="mono cut">{d.ip}</td>
            <td class="mono cut" class:dim-t={!d.mac}>{d.mac ?? '—'}</td>
            <td class="cut" title={d.vendor ?? ''}>{d.vendor ?? ''}</td>
            <td class="cut">{$_(`sitenet.kind.${d.kind}`)}</td>
            <td class="cut" title={deviceName(d)}>{deviceName(d)}</td>
            <td class="dim-t cut" title={gone ? $_('sitenet.absent') : undefined}>{#if gone}<i class="absent" aria-label={$_('sitenet.absent')}></i>{/if}{seenOn(d.last_seen)}</td>
            <td class="ra">
              {#if ip !== null}<button class="mini" type="button" onclick={(e) => { e.stopPropagation(); onFrame(ip); }}>{$_('network.frame')}</button>{/if}
              <button class="mini" type="button" class:danger={forgetting === deviceKey(d)} onclick={(e) => { e.stopPropagation(); void forget(d); }}>
                {forgetting === deviceKey(d) ? $_('sitenet.confirmForget') : $_('sitenet.forget')}
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if shown.length === 0}<div class="none">{$_('sitenet.none')}</div>{/if}
  </div>
</div>

<style>
  .devices { display: flex; flex-direction: column; min-height: 0; }
  .bar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin: 0 0 8px; }
  .bar input { flex: 1; min-width: 180px; }
  .tabs { display: flex; flex-wrap: wrap; gap: 2px; }
  .tab { display: inline-flex; align-items: center; gap: 6px; padding: 5px 10px; border: 0; border-radius: 6px; background: none; color: var(--text-2); font: inherit; font-weight: 500; cursor: pointer; }
  .tab:hover { background: var(--hover); color: var(--text); }
  .tab.on { background: var(--sel); color: var(--text); }
  .tab .n { font-variant-numeric: tabular-nums; font-size: 12px; color: var(--text-2); }
  .tab.on .n { color: var(--act); }
  .tab:focus-visible { outline: 2px solid var(--act); outline-offset: 1px; }
  .big table { table-layout: fixed; width: 100%; }
  .big td { height: 34px; }
  .big .mono { font-size: 12.5px; }
  .big tbody tr:last-child td { border-bottom: 0; }
  .cut { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  tr.gone td:not(:last-child) { color: var(--text-2); }
  tr.frame { cursor: pointer; }
  .sum { margin: 0 0 8px; color: var(--text-2); font-size: 13px; }
  .sum.e { color: var(--err); }
  .absent { display: inline-block; width: 7px; height: 7px; margin-right: 6px; border-radius: 50%; border: 1px solid var(--warn); vertical-align: 1px; }
  .none { padding: 16px 0; color: var(--text-2); text-align: center; }
</style>

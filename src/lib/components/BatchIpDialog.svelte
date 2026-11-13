<script lang="ts">
  import { onMount } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { interfaceDetails } from '$lib/api/core';
  import {
    batchApply, batchErrorMessage, batchFingerprint, batchPreview, orNull, outsideSubnet, splitList,
    type ActionResult, type BatchPreview,
  } from '$lib/api/configure';
  import type { Camera } from '$lib/api/types';
  import AccountPicker from './AccountPicker.svelte';
  import Dialog from './Dialog.svelte';

  // `cams` : la sélection dans l'ordre affiché ; `others` : toutes les autres
  // caméras connues. `onApplied` reçoit les résultats par caméra.
  let {
    accountId = $bindable(''),
    iface,
    cams,
    others,
    onApplied,
    onClose,
  }: {
    accountId?: string;
    iface: string;
    cams: Camera[];
    others: Camera[];
    onApplied: (r: ActionResult[]) => void;
    onClose: () => void;
  } = $props();

  let start = $state('');
  let mask = $state('255.255.255.0');
  let gateway = $state('');
  let dns = $state('');
  let busy = $state(false);
  let error = $state('');
  // L'aperçu garde l'empreinte des champs et de la sélection qui l'ont produit.
  let preview = $state<{ data: BatchPreview; fingerprint: string } | null>(null);

  const fingerprint = $derived(batchFingerprint(cams, { iface, start, mask, gateway, dns }));
  // Un champ ou la sélection qui change retire l'aperçu : Appliquer se désactive.
  const shown = $derived(preview && preview.fingerprint === fingerprint ? preview.data : null);
  const ready = $derived(!busy && start.trim() !== '' && mask.trim() !== '');

  let ifaceIp = $state<string | null>(null);
  let ifaceMask = $state<string | null>(null);
  const off = $derived(outsideSubnet(start, ifaceIp, ifaceMask));

  onMount(async () => {
    try {
      const d = await interfaceDetails(iface);
      ifaceIp = d.ip;
      ifaceMask = d.subnet;
    } catch {}
  });

  function show(e: unknown) {
    const m = batchErrorMessage(e);
    error = $_(m.key, { values: m.values });
  }

  async function runPreview() {
    busy = true;
    error = '';
    preview = null;
    const fp = fingerprint;
    try {
      const data = await batchPreview(
        cams,
        others,
        { start: start.trim(), mask: mask.trim(), gateway: orNull(gateway), dns: splitList(dns) },
        iface,
      );
      preview = { data, fingerprint: fp };
    } catch (e) {
      show(e);
    } finally {
      busy = false;
    }
  }

  async function runApply() {
    if (!shown) return;
    busy = true;
    error = '';
    const id = shown.id;
    // L'identifiant ne sert qu'une fois : l'aperçu part, quoi qu'il arrive.
    preview = null;
    try {
      onApplied(await batchApply(id, accountId, iface));
    } catch (e) {
      show(e);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={$_('batch.title')} {onClose}>
  <label>{$_('accounts.picker')}<AccountPicker bind:accountId /></label>
  <label>{$_('batch.start')}<input bind:value={start} inputmode="decimal" autocomplete="off" /></label>
  {#if off}<div class="warn">{$_('configure.off_subnet', { values: { iface } })}</div>{/if}
  <label>{$_('configure.mask')}<input bind:value={mask} inputmode="decimal" autocomplete="off" /></label>
  <label>{$_('configure.gateway')}<input bind:value={gateway} inputmode="decimal" autocomplete="off" /></label>
  <label>{$_('configure.dns')}<input bind:value={dns} autocomplete="off" /></label>
  {#if error}<div class="error">{error}</div>{/if}
  {#if shown}
    <table>
      <thead>
        <tr>
          <th>{$_('batch.col.mac')}</th>
          <th>{$_('batch.col.serial')}</th>
          <th>{$_('batch.col.change')}</th>
        </tr>
      </thead>
      <tbody>
        {#each shown.rows as r (r.mac)}
          <tr>
            <td>{r.mac}</td>
            <td>{r.serial ?? ''}</td>
            <td>{r.current_ip} → {r.new_ip}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
  <div class="row">
    <button onclick={onClose}>{$_('configure.cancel')}</button>
    <button onclick={runPreview} disabled={!ready}>{$_('batch.preview')}</button>
    <button class="primary" onclick={runApply} disabled={busy || !accountId || !shown}>{$_('batch.apply')}</button>
  </div>
</Dialog>

<style>
  .warn { color: var(--ep-warning); font-size: 12px; }
  .error { color: var(--ep-danger); font-size: 12.5px; }
  table { border-collapse: collapse; font-size: 12.5px; }
  th { text-align: left; padding: 3px 8px; font-size: 11px; color: var(--ep-text-muted); border-bottom: 1px solid var(--ep-border-strong); }
  td { padding: 3px 8px; font-variant-numeric: tabular-nums; }
</style>

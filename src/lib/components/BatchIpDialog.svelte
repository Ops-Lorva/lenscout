<script lang="ts">
  import { onMount } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { interfaceDetails } from '$lib/api/core';
  import {
    batchApply, batchErrorMessage, batchFingerprint, batchPreview, orNull, outsideSubnet, splitList,
    type ActionResult, type BatchPreview,
  } from '$lib/api/configure';
  import { firstFit, type FreeRange } from '$lib/api/freeIps';
  import type { Camera } from '$lib/api/types';
  import AccountPicker from './AccountPicker.svelte';
  import Dialog from './Dialog.svelte';
  import FreeIps from './FreeIps.svelte';

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

  // La première plage assez grande pour les caméras cochées est proposée, sauf si l'IP de départ est déjà saisie.
  function proposeStart(ranges: FreeRange[]) {
    if (start.trim() !== '') return;
    start = firstFit(ranges, cams.length) ?? '';
  }

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

<Dialog title={$_('batch.title')} width={560} {onClose}>
  <div class="form">
    <label for="b-account">{$_('accounts.picker')}</label><AccountPicker id="b-account" bind:accountId />
    <FreeIps {iface} {ifaceIp} {ifaceMask} value={start} onPick={(a) => (start = a)} onFound={proposeStart} />
    <label for="b-start">{$_('batch.start')}</label><input id="b-start" type="text" bind:value={start} inputmode="decimal" autocomplete="off" />
    {#if off}<span class="note warn">{$_('configure.off_subnet', { values: { iface } })}</span>{/if}
    <label for="b-mask">{$_('configure.mask')}</label><input id="b-mask" type="text" bind:value={mask} inputmode="decimal" autocomplete="off" />
    <label for="b-gw">{$_('configure.gateway')}</label><input id="b-gw" type="text" bind:value={gateway} inputmode="decimal" autocomplete="off" />
    <label for="b-dns">{$_('configure.dns')}</label><input id="b-dns" type="text" bind:value={dns} autocomplete="off" />
  </div>
  <!-- L'aperçu : MAC, n° de série et passage d'adresse, dans l'ordre de la liste. -->
  {#if shown}
    <div class="scroll ptable">
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
              <td class="mac">{r.mac}</td>
              <td class="mac ser" title={r.serial ?? ''}>{r.serial ?? ''}</td>
              <td>{r.current_ip} → {r.new_ip}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  <div class="foot">
    <span class="sum" class:e={!!error}>{error}</span>
    <button class="btn" onclick={onClose}>{$_('configure.cancel')}</button>
    <button class="btn" onclick={runPreview} disabled={!ready}>{$_('batch.preview')}</button>
    <button class="btn def" onclick={runApply} disabled={busy || !accountId || !shown}>
      {#if busy}<span class="spin"></span>{/if}{$_('batch.apply')}
    </button>
  </div>
</Dialog>

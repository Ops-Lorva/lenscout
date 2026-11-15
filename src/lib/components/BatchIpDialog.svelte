<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { accountFill, type Account, type NetworkFill } from '#lib/api/accounts.ts';
  import { activeAddress, dnsFollowing, INITIAL_PREFILL, joined, prefillFields } from '#lib/api/net.ts';
  import { _ } from 'svelte-i18n';
  import { interfaceDetails } from '#lib/api/core.ts';
  import {
    batchApply, batchErrorMessage, batchFingerprint, batchPreview, orNull, outsideSubnet, splitList,
    type ActionResult, type BatchPreview,
  } from '#lib/api/configure.ts';
  import { firstFit, type FreeRange } from '#lib/api/freeIps.ts';
  import type { Camera } from '#lib/api/types.ts';
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
  let mask = $state(INITIAL_PREFILL.mask);
  let gateway = $state('');
  let dns = $state('');
  let busy = $state(false);
  let error = $state<{ key: string; values?: Record<string, string | number> } | null>(null);
  // L'aperçu garde l'empreinte des champs et de la sélection qui l'ont produit.
  let preview = $state<{ data: BatchPreview; fingerprint: string } | null>(null);

  const fingerprint = $derived(batchFingerprint(cams, { iface, start, mask, gateway, dns, accountId }));
  // Un champ ou la sélection qui change retire l'aperçu : Appliquer se désactive.
  const shown = $derived(preview && preview.fingerprint === fingerprint ? preview.data : null);
  const ready = $derived(!busy && start.trim() !== '' && mask.trim() !== '');

  // Adresse du poste : celle posée pour un compte sur cette interface, sinon celle de l'interface.
  let details = $state<{ ip: string | null; subnet: string | null } | null>(null);
  const addr = $derived(activeAddress(iface, details, $joined));
  const ifaceIp = $derived(addr.ip);
  const ifaceMask = $derived(addr.mask);

  onMount(async () => {
    try {
      details = await interfaceDetails(iface);
    } catch {}
  });

  // Le compte retenu remplit masque et passerelle ; un champ touché (saisi) n'est jamais écrasé.
  let account = $state<Account | null>(null);
  const touched = { mask: false, gateway: false };
  $effect(() => {
    const a = account;
    untrack(() => ({ mask, gateway } = prefillFields({ mask, gateway }, touched, a)));
  });
  // Le DNS suit la passerelle (préremplie ou saisie) tant qu'il n'est pas touché.
  let dnsTouched = false;
  $effect(() => {
    const g = gateway;
    untrack(() => (dns = dnsFollowing(dns, dnsTouched, g)));
  });
  const off = $derived(outsideSubnet(start, ifaceIp, ifaceMask));

  // Réseau du compte retenu presque plein : dit avant l'aperçu. Le refus d'un
  // lot trop grand vient de Rust (`not_enough_free`), à l'aperçu.
  let fill = $state<NetworkFill | null>(null);
  $effect(() => {
    const id = accountId;
    fill = null;
    if (!id) return;
    accountFill(id).then((f) => { if (accountId === id) fill = f; }).catch(() => {});
  });

  // La première plage assez grande pour les caméras cochées est proposée, sauf si l'IP de départ est déjà saisie.
  function proposeStart(ranges: FreeRange[]) {
    if (start.trim() !== '') return;
    start = firstFit(ranges, cams.length) ?? '';
  }

  function show(e: unknown) {
    const m = batchErrorMessage(e);
    error = m;
  }

  async function runPreview() {
    busy = true;
    error = null;
    preview = null;
    const fp = fingerprint;
    try {
      const data = await batchPreview(
        cams,
        others,
        { start: start.trim(), mask: mask.trim(), gateway: orNull(gateway), dns: splitList(dns) },
        iface,
        accountId,
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
    error = null;
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
    <label for="b-account">{$_('accounts.picker')}</label><AccountPicker id="b-account" bind:accountId bind:account />
    <FreeIps {iface} {accountId} own={cams.map((c) => c.ip)} {ifaceIp} {ifaceMask} value={start} onPick={(a) => (start = a)} onFound={proposeStart} />
    {#if fill?.almost_full}<span class="note warn">{$_('batch.almostFull', { values: { free: fill.free } })}</span>{/if}
    <label for="b-start">{$_('batch.start')}</label><input id="b-start" type="text" bind:value={start} inputmode="decimal" autocomplete="off" />
    {#if off}<span class="note warn">{$_('configure.off_subnet', { values: { iface } })}</span>{/if}
    <label for="b-mask">{$_('configure.mask')}</label><input id="b-mask" type="text" bind:value={mask} oninput={() => (touched.mask = true)} inputmode="decimal" autocomplete="off" />
    <label for="b-gw">{$_('configure.gateway')}</label><input id="b-gw" type="text" bind:value={gateway} oninput={() => (touched.gateway = true)} inputmode="decimal" autocomplete="off" />
    <label for="b-dns">{$_('configure.dns')}</label><input id="b-dns" class="m" type="text" bind:value={dns} oninput={() => (dnsTouched = true)} autocomplete="off" />
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
              <td class="m">{r.current_ip} → <span class="cool">{r.new_ip}</span></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  <div class="foot">
    <span class="sum" class:e={!!error}>{error ? $_(error.key, { values: error.values }) : ''}</span>
    <button class="btn" onclick={onClose}>{$_('configure.cancel')}</button>
    <button class="btn" onclick={runPreview} disabled={!ready}>{$_('batch.preview')}</button>
    <button class="btn def" onclick={runApply} disabled={busy || !accountId || !shown}>
      {#if busy}<span class="spin"></span>{/if}{$_('batch.apply')}
    </button>
  </div>
</Dialog>

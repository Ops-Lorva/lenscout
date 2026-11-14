<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import type { Account } from '#lib/api/accounts.ts';
  import { activeAddress, INITIAL_PREFILL, joined, prefillFields } from '#lib/api/net.ts';
  import { _ } from 'svelte-i18n';
  import { interfaceDetails } from '#lib/api/core.ts';
  import type { ActionDto } from '#lib/api/configure.ts';
  import { orNull, outsideSubnet, splitList } from '#lib/api/configure.ts';
  import AccountPicker from './AccountPicker.svelte';
  import Dialog from './Dialog.svelte';
  import FreeIps from './FreeIps.svelte';

  let {
    accountId = $bindable(''),
    subtitle = '',
    iface,
    busy,
    onSubmit,
    onClose,
  }: { accountId?: string; subtitle?: string; iface: string; busy: boolean; onSubmit: (a: ActionDto) => void; onClose: () => void } = $props();

  let dhcp = $state(false);
  let ip = $state('');
  let mask = $state(INITIAL_PREFILL.mask);
  let gateway = $state('');
  let dns = $state('');

  // Avertissement seulement : le sous-réseau du poste vient de l'interface du scan.
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
  const off = $derived(!dhcp && outsideSubnet(ip, ifaceIp, ifaceMask));

  // Les adresses sont validées par Rust (type `Ipv4Addr` puis règles de la caméra) :
  // ici on ne fait qu'exiger les champs obligatoires.
  const ready = $derived(!busy && !!accountId && (dhcp || (ip.trim() !== '' && mask.trim() !== '')));

  function submit() {
    onSubmit(
      dhcp
        ? { kind: 'network_dhcp' }
        : { kind: 'network_static', ip: ip.trim(), mask: mask.trim(), gateway: orNull(gateway), dns: splitList(dns) },
    );
  }
</script>

<Dialog title={$_('configure.ip')} {subtitle} width={560} {onClose}>
  <div class="form">
    <label for="ip-account">{$_('accounts.picker')}</label><AccountPicker id="ip-account" bind:accountId bind:account />
    <label for="ip-mode">{$_('configure.mode')}</label>
    <select id="ip-mode" bind:value={dhcp}>
      <option value={false}>{$_('configure.static')}</option>
      <option value={true}>{$_('configure.dhcp')}</option>
    </select>
    <!-- Au-dessus du champ : on choisit une plage, le champ se remplit. -->
    <FreeIps {iface} {ifaceIp} {ifaceMask} value={ip} hidden={dhcp} onPick={(a) => (ip = a)} />
    {#if !dhcp}
      <label for="ip-ip">{$_('configure.ipaddr')}</label><input id="ip-ip" type="text" bind:value={ip} inputmode="decimal" autocomplete="off" />
      {#if off}<span class="note warn">{$_('configure.off_subnet', { values: { iface } })}</span>{/if}
      <label for="ip-mask">{$_('configure.mask')}</label><input id="ip-mask" type="text" bind:value={mask} oninput={() => (touched.mask = true)} inputmode="decimal" autocomplete="off" />
      <label for="ip-gw">{$_('configure.gateway')}</label><input id="ip-gw" type="text" bind:value={gateway} oninput={() => (touched.gateway = true)} inputmode="decimal" autocomplete="off" />
      <label for="ip-dns">{$_('configure.dns')}</label><input id="ip-dns" type="text" bind:value={dns} autocomplete="off" />
    {/if}
  </div>
  <div class="foot">
    <span class="sum"></span>
    <button class="btn" onclick={onClose}>{$_('configure.cancel')}</button>
    <button class="btn def" onclick={submit} disabled={!ready}>
      {#if busy}<span class="spin"></span>{/if}{$_('configure.apply')}
    </button>
  </div>
</Dialog>

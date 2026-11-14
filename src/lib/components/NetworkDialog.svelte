<script lang="ts">
  import { onMount } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { interfaceDetails } from '$lib/api/core';
  import type { ActionDto } from '$lib/api/configure';
  import { orNull, outsideSubnet, splitList } from '$lib/api/configure';
  import AccountPicker from './AccountPicker.svelte';
  import Dialog from './Dialog.svelte';

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
  let mask = $state('255.255.255.0');
  let gateway = $state('');
  let dns = $state('');

  // Avertissement seulement : le sous-réseau du poste vient de l'interface du scan.
  let ifaceIp = $state<string | null>(null);
  let ifaceMask = $state<string | null>(null);
  const off = $derived(!dhcp && outsideSubnet(ip, ifaceIp, ifaceMask));

  onMount(async () => {
    try {
      const d = await interfaceDetails(iface);
      ifaceIp = d.ip;
      ifaceMask = d.subnet;
    } catch {}
  });

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

<Dialog title={$_('configure.ip')} {subtitle} {onClose}>
  <div class="form">
    <label for="ip-account">{$_('accounts.picker')}</label><AccountPicker id="ip-account" bind:accountId />
    <label for="ip-mode">{$_('configure.mode')}</label>
    <select id="ip-mode" bind:value={dhcp}>
      <option value={false}>{$_('configure.static')}</option>
      <option value={true}>{$_('configure.dhcp')}</option>
    </select>
    {#if !dhcp}
      <label for="ip-ip">{$_('configure.ipaddr')}</label><input id="ip-ip" type="text" bind:value={ip} inputmode="decimal" autocomplete="off" />
      {#if off}<span class="note warn">{$_('configure.off_subnet', { values: { iface } })}</span>{/if}
      <label for="ip-mask">{$_('configure.mask')}</label><input id="ip-mask" type="text" bind:value={mask} inputmode="decimal" autocomplete="off" />
      <label for="ip-gw">{$_('configure.gateway')}</label><input id="ip-gw" type="text" bind:value={gateway} inputmode="decimal" autocomplete="off" />
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

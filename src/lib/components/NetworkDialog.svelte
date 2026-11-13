<script lang="ts">
  import { _ } from 'svelte-i18n';
  import type { ActionDto } from '$lib/api/configure';
  import { orNull, splitList } from '$lib/api/configure';
  import AccountPicker from './AccountPicker.svelte';
  import Dialog from './Dialog.svelte';

  let {
    accountId = $bindable(''),
    busy,
    onSubmit,
    onClose,
  }: { accountId?: string; busy: boolean; onSubmit: (a: ActionDto) => void; onClose: () => void } = $props();

  let dhcp = $state(false);
  let ip = $state('');
  let mask = $state('255.255.255.0');
  let gateway = $state('');
  let dns = $state('');

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

<Dialog title={$_('configure.ip')} {onClose}>
  <label>{$_('accounts.picker')}<AccountPicker bind:accountId /></label>
  <label>{$_('configure.mode')}
    <select bind:value={dhcp}>
      <option value={false}>{$_('configure.static')}</option>
      <option value={true}>{$_('configure.dhcp')}</option>
    </select>
  </label>
  {#if !dhcp}
    <label>{$_('configure.ipaddr')}<input bind:value={ip} inputmode="decimal" autocomplete="off" /></label>
    <label>{$_('configure.mask')}<input bind:value={mask} inputmode="decimal" autocomplete="off" /></label>
    <label>{$_('configure.gateway')}<input bind:value={gateway} inputmode="decimal" autocomplete="off" /></label>
    <label>{$_('configure.dns')}<input bind:value={dns} autocomplete="off" /></label>
  {/if}
  <div class="row">
    <button onclick={onClose}>{$_('configure.cancel')}</button>
    <button class="primary" onclick={submit} disabled={!ready}>{$_('configure.apply')}</button>
  </div>
</Dialog>

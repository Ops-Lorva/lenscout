<script lang="ts">
  import { _ } from 'svelte-i18n';
  import type { ActionDto } from '$lib/api/configure';
  import { defaultTimeZone, splitList, timeZones } from '$lib/api/configure';
  import AccountPicker from './AccountPicker.svelte';
  import Dialog from './Dialog.svelte';

  let {
    accountId = $bindable(''),
    busy,
    onSubmit,
    onClose,
  }: { accountId?: string; busy: boolean; onSubmit: (a: ActionDto) => void; onClose: () => void } = $props();

  const zones = timeZones();
  let ntp = $state('');
  let timezone = $state(defaultTimeZone(zones));

  const ready = $derived(!busy && !!accountId);
</script>

<Dialog title={$_('configure.time')} {onClose}>
  <div class="form">
    <label for="t-account">{$_('accounts.picker')}</label><AccountPicker id="t-account" bind:accountId />
    <label for="t-ntp">{$_('configure.ntp')}</label><input id="t-ntp" type="text" bind:value={ntp} autocomplete="off" spellcheck="false" />
    <label for="t-tz">{$_('configure.timezone')}</label>
    <select id="t-tz" bind:value={timezone}>{#each zones as z}<option value={z}>{z}</option>{/each}</select>
  </div>
  <div class="foot">
    <span class="sum"></span>
    <button class="btn" onclick={onClose}>{$_('configure.cancel')}</button>
    <button class="btn def" onclick={() => onSubmit({ kind: 'time', ntp_servers: splitList(ntp), timezone })} disabled={!ready}>
      {#if busy}<span class="spin"></span>{/if}{$_('configure.apply')}
    </button>
  </div>
</Dialog>

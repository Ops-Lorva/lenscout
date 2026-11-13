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
  <label>{$_('accounts.picker')}<AccountPicker bind:accountId /></label>
  <label>{$_('configure.ntp')}<input bind:value={ntp} autocomplete="off" spellcheck="false" /></label>
  <label>{$_('configure.timezone')}
    <select bind:value={timezone}>{#each zones as z}<option value={z}>{z}</option>{/each}</select>
  </label>
  <div class="row">
    <button onclick={onClose}>{$_('configure.cancel')}</button>
    <button class="primary" onclick={() => onSubmit({ kind: 'time', ntp_servers: splitList(ntp), timezone })} disabled={!ready}>
      {$_('configure.apply')}
    </button>
  </div>
</Dialog>

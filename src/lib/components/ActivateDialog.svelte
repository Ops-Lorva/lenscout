<script lang="ts">
  import { _ } from 'svelte-i18n';
  import AccountPicker from './AccountPicker.svelte';
  import Dialog from './Dialog.svelte';

  let {
    count,
    accountId = $bindable(''),
    busy,
    onSubmit,
    onClose,
  }: { count: number; accountId?: string; busy: boolean; onSubmit: () => void; onClose: () => void } = $props();
</script>

<Dialog title={$_('configure.activate')} {onClose}>
  <div>{$_('configure.cameras', { values: { count } })}</div>
  <label>{$_('accounts.picker')}<AccountPicker bind:accountId /></label>
  <div class="row">
    <button onclick={onClose}>{$_('configure.cancel')}</button>
    <button class="primary" onclick={onSubmit} disabled={busy || !accountId}>{$_('configure.apply')}</button>
  </div>
</Dialog>

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

<Dialog title={$_('configure.activate')} width={420} {onClose}>
  <div class="form">
    <span class="lbl">{$_('network.col.camera')}</span><span>{$_('configure.cameras', { values: { count } })}</span>
    <label for="act-account">{$_('accounts.picker')}</label><AccountPicker id="act-account" bind:accountId />
    <span class="note">{$_('configure.activate_note')}</span>
  </div>
  <div class="foot">
    <span class="sum"></span>
    <button class="btn" onclick={onClose}>{$_('configure.cancel')}</button>
    <button class="btn def" onclick={onSubmit} disabled={busy || !accountId}>
      {#if busy}<span class="spin"></span>{/if}{$_('configure.apply')}
    </button>
  </div>
</Dialog>

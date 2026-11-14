<script lang="ts">
  import { _ } from 'svelte-i18n';
  import type { Camera } from '#lib/api/types.ts';
  import AccountPicker from './AccountPicker.svelte';
  import Dialog from './Dialog.svelte';

  // `pending` : caméras dont l'https ne répond pas ; chacune se confirme seule
  // (`onConfirm`), jamais toutes d'un coup.
  let {
    count,
    accountId = $bindable(''),
    busy,
    pending = [],
    onSubmit,
    onConfirm,
    onClose,
  }: {
    count: number;
    accountId?: string;
    busy: boolean;
    pending?: Camera[];
    onSubmit: () => void;
    onConfirm: (cam: Camera) => void;
    onClose: () => void;
  } = $props();
</script>

<Dialog title={$_('configure.activate')} width={420} {onClose}>
  {#if pending.length > 0}
    <div class="clear">
      {#each pending as cam (cam.mac ?? cam.ip)}
        <div class="row">
          <span class="ask">{$_('configure.cleartext_confirm', { values: { ip: cam.ip } })}</span>
          <button class="btn" onclick={() => onConfirm(cam)} disabled={busy}>{$_('configure.cleartext_send')}</button>
        </div>
      {/each}
    </div>
    <div class="foot">
      <span class="sum"></span>
      <button class="btn def" onclick={onClose}>{$_('configure.cancel')}</button>
    </div>
  {:else}
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
  {/if}
</Dialog>

<style>
  .clear { display: flex; flex-direction: column; gap: 8px; margin-bottom: 12px; }
  .row { display: flex; align-items: center; gap: 10px; }
  .ask { flex: 1; }
</style>

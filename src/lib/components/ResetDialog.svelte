<script lang="ts">
  import { _ } from 'svelte-i18n';
  import { resetLine, type ActionDto, type ResetMode } from '#lib/api/configure.ts';
  import type { Camera } from '#lib/api/types.ts';
  import AccountPicker from './AccountPicker.svelte';
  import Dialog from './Dialog.svelte';

  // `cams` : la sélection figée à l'ouverture. Rien ne part sans le second
  // clic (« Confirmer »), qui suit la liste nom / IP / MAC affichée.
  let {
    accountId = $bindable(''),
    cams,
    busy,
    onSubmit,
    onClose,
  }: { accountId?: string; cams: Camera[]; busy: boolean; onSubmit: (a: ActionDto) => void; onClose: () => void } = $props();

  let mode = $state<ResetMode>('keep_ip');
  let confirming = $state(false);
  const lines = $derived(cams.map(resetLine));
  const ready = $derived(!busy && !!accountId && cams.length > 0);

  function submit() {
    if (!confirming) {
      confirming = true;
      return;
    }
    onSubmit({ kind: 'factory_reset', mode });
  }
</script>

<Dialog title={$_('configure.reset.title')} width={560} {onClose}>
  <div class="form">
    <label for="r-account">{$_('accounts.picker')}</label><AccountPicker id="r-account" bind:accountId />
    <label for="r-mode">{$_('configure.reset.mode')}</label>
    <select id="r-mode" bind:value={mode} onchange={() => (confirming = false)}>
      <option value="keep_ip">{$_('configure.reset.keep_ip')}</option>
      <option value="full">{$_('configure.reset.full')}</option>
    </select>
    {#if mode === 'full'}<span class="note warn">{$_('configure.reset.full_note')}</span>{/if}
  </div>
  <div class="scroll ptable">
    <table>
      <thead>
        <tr>
          <th>{$_('network.col.camera')}</th>
          <th>{$_('network.col.ip')}</th>
          <th>{$_('network.col.mac')}</th>
        </tr>
      </thead>
      <tbody>
        {#each lines as l, i (i)}
          <tr><td>{l.name}</td><td class="m">{l.ip}</td><td class="mac">{l.mac}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
  <div class="foot">
    <span class="sum e">{confirming ? $_('configure.reset.sure', { values: { count: cams.length } }) : ''}</span>
    <button class="btn" onclick={onClose}>{$_('configure.cancel')}</button>
    <button class="btn danger" class:armed={confirming} onclick={submit} disabled={!ready}>
      {#if busy}<span class="spin"></span>{/if}{$_(confirming ? 'configure.reset.confirm' : 'configure.reset.apply')}
    </button>
  </div>
</Dialog>

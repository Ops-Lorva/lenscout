<script lang="ts">
  import { onMount } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { errorKey } from '$lib/api/errors';
  import { ACCOUNT_KEY, listAccounts, pickAccount, type Account } from '$lib/api/accounts';

  // `id` : pour le `<label for>` d'une feuille ; `account` : le compte retenu
  // (champs réseau compris), pour le préremplissage.
  let {
    accountId = $bindable(''),
    account = $bindable(null),
    id = undefined,
  }: { accountId?: string; account?: Account | null; id?: string } = $props();

  let accounts = $state<Account[]>([]);
  let error = $state('');
  // Le select reste focalisable pendant le chargement (premier champ d'une
  // feuille) ; il ne se grise que si la liste revient vide.
  let loaded = $state(false);

  function onChange(e: Event) {
    accountId = (e.currentTarget as HTMLSelectElement).value;
    try { localStorage.setItem(ACCOUNT_KEY, accountId); } catch {}
  }

  $effect(() => {
    account = accounts.find((a) => a.id === accountId) ?? null;
  });

  onMount(async () => {
    try {
      accounts = await listAccounts();
    } catch (e) {
      error = $_(`accounts.${errorKey(e)}`);
      return;
    } finally {
      loaded = true;
    }
    let saved = '';
    try { saved = localStorage.getItem(ACCOUNT_KEY) ?? ''; } catch {}
    accountId = pickAccount(accounts, accountId || saved);
  });
</script>

<span class="picker">
  <select {id} value={accountId} onchange={onChange} disabled={loaded && accounts.length === 0} aria-label={$_('accounts.picker')}>
    {#if accounts.length === 0 && !error}<option value="">{$_('accounts.none')}</option>{/if}
    {#each accounts as a (a.id)}<option value={a.id}>{a.name} ({a.login})</option>{/each}
  </select>
  {#if error}<span class="err">{error}</span>{/if}
</span>

<style>
  .picker { display: inline-flex; flex-direction: column; gap: 3px; min-width: 0; }
  .picker select { max-width: 100%; }
  .err { margin: 0; }
</style>

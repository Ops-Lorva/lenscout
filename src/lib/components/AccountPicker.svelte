<script lang="ts">
  import { onMount } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { ACCOUNT_KEY, listAccounts, pickAccount, type Account } from '$lib/api/accounts';

  let { accountId = $bindable('') }: { accountId?: string } = $props();

  let accounts = $state<Account[]>([]);

  function onChange(e: Event) {
    accountId = (e.currentTarget as HTMLSelectElement).value;
    try { localStorage.setItem(ACCOUNT_KEY, accountId); } catch {}
  }

  onMount(async () => {
    try {
      accounts = await listAccounts();
    } catch {
      return;
    }
    let saved = '';
    try { saved = localStorage.getItem(ACCOUNT_KEY) ?? ''; } catch {}
    accountId = pickAccount(accounts, accountId || saved);
  });
</script>

<select value={accountId} onchange={onChange} disabled={accounts.length === 0} aria-label={$_('accounts.picker')}>
  {#if accounts.length === 0}<option value="">{$_('accounts.none')}</option>{/if}
  {#each accounts as a (a.id)}<option value={a.id}>{a.name} ({a.login})</option>{/each}
</select>

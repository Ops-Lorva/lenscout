<script lang="ts">
  import { onMount } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { createAccount, listAccounts, removeAccount, updateAccount, type Account } from '$lib/api/accounts';
  import { errorKey } from '$lib/api/errors';

  let accounts = $state<Account[]>([]);
  let error = $state('');
  // `null` : pas de formulaire ; `''` : création ; sinon l'id du compte modifié.
  let editing = $state<string | null>(null);
  let name = $state('');
  let login = $state('');
  let password = $state('');
  let confirming = $state('');

  const fail = (e: unknown) => (error = $_(`accounts.${errorKey(e)}`));

  async function refresh() {
    try {
      accounts = await listAccounts();
    } catch (e) {
      fail(e);
    }
  }

  function open(a: Account | null) {
    error = '';
    confirming = '';
    editing = a?.id ?? '';
    name = a?.name ?? '';
    login = a?.login ?? '';
    password = '';
  }

  function close() {
    editing = null;
    password = '';
  }

  async function save() {
    error = '';
    try {
      if (editing) await updateAccount(editing, name, login, password === '' ? null : password);
      else await createAccount(name, login, password);
    } catch (e) {
      fail(e);
      return;
    } finally {
      // Le mot de passe ne reste pas dans le champ, succès ou non.
      password = '';
    }
    close();
    await refresh();
  }

  async function remove(a: Account) {
    if (confirming !== a.id) {
      confirming = a.id;
      return;
    }
    confirming = '';
    error = '';
    try {
      await removeAccount(a.id);
    } catch (e) {
      fail(e);
    }
    await refresh();
  }

  onMount(refresh);
</script>

<div class="bar">
  <h1>{$_('common.nav.accounts')}</h1>
  <button class="primary" onclick={() => open(null)}>{$_('accounts.add')}</button>
</div>

{#if error}<div class="error">{error}</div>{/if}

{#if editing !== null}
  <form onsubmit={(e) => { e.preventDefault(); void save(); }}>
    <input bind:value={name} placeholder={$_('accounts.field.name')} aria-label={$_('accounts.field.name')} autocomplete="off" />
    <input bind:value={login} placeholder={$_('accounts.field.login')} aria-label={$_('accounts.field.login')} autocomplete="off" />
    <input type="password" bind:value={password} placeholder={$_('accounts.field.password')} aria-label={$_('accounts.field.password')} autocomplete="new-password" />
    <button class="primary" type="submit">{$_('accounts.save')}</button>
    <button type="button" onclick={close}>{$_('accounts.cancel')}</button>
  </form>
{/if}

<table>
  <thead>
    <tr><th>{$_('accounts.col.name')}</th><th>{$_('accounts.col.login')}</th><th></th></tr>
  </thead>
  <tbody>
    {#each accounts as a (a.id)}
      <tr>
        <td>{a.name}</td>
        <td class="mono">{a.login}</td>
        <td class="actions">
          <button onclick={() => open(a)}>{$_('accounts.edit')}</button>
          <button class:danger={confirming === a.id} onclick={() => remove(a)}>
            {confirming === a.id ? $_('accounts.confirmRemove') : $_('accounts.remove')}
          </button>
        </td>
      </tr>
    {/each}
  </tbody>
</table>
{#if accounts.length === 0}<div class="none">{$_('accounts.none')}</div>{/if}

<style>
  .bar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
  h1 { font-size: 15px; font-weight: 600; margin: 0; }
  form { display: flex; gap: 8px; margin-bottom: 14px; }
  form input {
    flex: 1; min-width: 0; padding: 5px 10px; font-size: 13px;
    background: var(--ep-bg-secondary); border: 1px solid var(--ep-border);
    border-radius: var(--ep-radius-md); color: var(--ep-text-primary);
  }
  form input:focus { outline: none; border-color: var(--ep-accent); }
  button {
    padding: 4px 10px; font-size: 12px; cursor: pointer;
    background: var(--ep-glass-bg-md); border: 1px solid var(--ep-glass-border);
    border-radius: var(--ep-radius-md); color: var(--ep-text-primary);
  }
  button:hover { border-color: var(--ep-accent); }
  .primary {
    padding: 5px 14px; font-size: 13px; font-weight: 600;
    background: var(--ep-accent-dim); border-color: var(--ep-accent-glow); color: var(--ep-accent-bright);
  }
  .danger { border-color: var(--ep-danger); color: var(--ep-danger); }
  .error { color: var(--ep-danger); font-size: 12.5px; margin-bottom: 10px; }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left; padding: 6px 10px; font-size: 11px; font-weight: 600; text-transform: uppercase;
    color: var(--ep-text-muted); border-bottom: 1px solid var(--ep-border-strong);
  }
  td { padding: 7px 10px; border-bottom: 1px solid var(--ep-border); font-size: 12.5px; }
  .mono { font-family: var(--ep-font-mono, monospace); font-size: 12px; }
  .actions { text-align: right; }
  .actions button { margin-left: 6px; }
  .none { color: var(--ep-text-muted); font-size: 12.5px; padding: 14px 10px; }
</style>

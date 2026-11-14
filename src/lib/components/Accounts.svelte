<script lang="ts">
  import { onMount } from 'svelte';
  import { _ } from 'svelte-i18n';
  import {
    accountsStartup, createAccount, listAccounts, noticeKey, passwordRequired, removeAccount, updateAccount,
    type AccountEntry,
  } from '$lib/api/accounts';
  import { errorKey } from '$lib/api/errors';
  import Dialog from './Dialog.svelte';

  let accounts = $state<AccountEntry[]>([]);
  let error = $state('');
  // Clé de l'erreur en cours : « Nom déjà utilisé » se place sous le champ Nom.
  let errorCode = $state('');
  // `null` : pas de feuille ; `''` : création ; sinon l'id du compte modifié.
  let editing = $state<string | null>(null);
  let name = $state('');
  let login = $state('');
  let password = $state('');
  let confirming = $state('');
  let needPassword = $state(true);

  const nameError = $derived(errorCode === 'error.duplicate_name' ? error : '');
  const otherError = $derived(nameError ? '' : error);
  // Enregistrer reste grisé tant qu'un champ obligatoire est vide.
  const ready = $derived(name.trim() !== '' && login.trim() !== '' && (!needPassword || password !== ''));

  const fail = (e: unknown) => {
    errorCode = errorKey(e);
    error = $_(`accounts.${errorCode}`);
  };

  async function refresh() {
    try {
      accounts = await listAccounts();
    } catch (e) {
      fail(e);
    }
  }

  function open(a: AccountEntry | null) {
    error = '';
    errorCode = '';
    confirming = '';
    editing = a?.id ?? '';
    needPassword = passwordRequired(a);
    name = a?.name ?? '';
    login = a?.login ?? '';
    password = '';
  }

  function close() {
    editing = null;
    password = '';
    error = '';
    errorCode = '';
  }

  async function save() {
    error = '';
    errorCode = '';
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

  async function remove(a: AccountEntry) {
    if (confirming !== a.id) {
      confirming = a.id;
      return;
    }
    confirming = '';
    error = '';
    errorCode = '';
    try {
      await removeAccount(a.id);
    } catch (e) {
      fail(e);
    }
    await refresh();
  }

  onMount(async () => {
    try {
      const key = noticeKey(await accountsStartup());
      if (key) {
        errorCode = key;
        error = $_(`accounts.${key}`);
      }
    } catch {}
    await refresh();
  });
</script>

<div class="tools">
  <span class="title">{$_('common.nav.accounts')}</span>
  <button class="btn def" onclick={() => open(null)}>{$_('accounts.add')}</button>
</div>

{#if error && editing === null}<p class="err">{error}</p>{/if}

<table>
  <thead>
    <tr>
      <th style="width:44%">{$_('accounts.col.name')}</th>
      <th style="width:22%">{$_('accounts.col.login')}</th>
      <th>{$_('accounts.field.password')}</th>
      <th style="width:1%"></th>
    </tr>
  </thead>
  <tbody>
    {#each accounts as a (a.id)}
      <tr>
        <td>{a.name}</td>
        <td>{a.login}</td>
        <td>{#if a.has_secret}••••••••{:else}<span class="warn">{$_('accounts.resecret')}</span>{/if}</td>
        <td class="ra">
          <button class="mini" onclick={() => open(a)}>{$_('accounts.edit')}</button>
          <button class="mini" class:danger={confirming === a.id} onclick={() => remove(a)}>
            {confirming === a.id ? $_('accounts.confirmRemove') : $_('accounts.remove')}
          </button>
        </td>
      </tr>
    {/each}
  </tbody>
</table>
{#if accounts.length === 0}<div class="none">{$_('accounts.none')}</div>{/if}

{#if editing !== null}
  <Dialog title={$_(editing ? 'accounts.edit' : 'accounts.add')} width={520} onClose={close}>
    <form onsubmit={(e) => { e.preventDefault(); if (ready) void save(); }}>
      <div class="form">
        <label for="a-name">{$_('accounts.field.name')}</label>
        <input id="a-name" type="text" bind:value={name} autocomplete="off" aria-invalid={nameError ? 'true' : undefined} />
        {#if nameError}<span class="note bad">{nameError}</span>{/if}
        <label for="a-login">{$_('accounts.field.login')}</label>
        <input id="a-login" type="text" bind:value={login} autocomplete="off" />
        <label for="a-password">{$_('accounts.field.password')}</label>
        <input id="a-password" type="password" bind:value={password} required={needPassword} autocomplete="new-password" />
      </div>
      <div class="foot">
        <span class="sum" class:e={!!otherError}>{otherError}</span>
        <button class="btn" type="button" onclick={close}>{$_('accounts.cancel')}</button>
        <button class="btn def" type="submit" disabled={!ready}>{$_('accounts.save')}</button>
      </div>
    </form>
  </Dialog>
{/if}

<style>
  form { margin: 0; }
</style>

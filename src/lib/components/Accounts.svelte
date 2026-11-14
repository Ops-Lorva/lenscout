<script lang="ts">
  import { onMount } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { open as openFile, save as saveFile } from '@tauri-apps/plugin-dialog';
  import {
    accountPassword, accountsStartup, createAccount, EXPORT_EXT, EXPORT_NAME, exportAccounts, importPlan, listAccounts, netIn, noticeKey,
    passwordRequired, passwordToSend, pcIpError, removeAccount, updateAccount, withExtension, type AccountEntry, type ImportPlan, type ImportSummary,
  } from '$lib/api/accounts';
  import { errorKey } from '$lib/api/errors';
  import { clearStatusIf, status, type Status } from '$lib/stores/nav';
  import Dialog from './Dialog.svelte';
  import ImportSheet from './ImportSheet.svelte';

  let accounts = $state<AccountEntry[]>([]);
  let error = $state('');
  // Clé de l'erreur en cours : « Nom déjà utilisé » se place sous le champ Nom.
  let errorCode = $state('');
  // `null` : pas de feuille ; `''` : création ; sinon l'id du compte modifié.
  let editing = $state<string | null>(null);
  let name = $state('');
  let login = $state('');
  let password = $state('');
  // Masqué par défaut, remasqué à chaque ouverture et fermeture.
  let showPassword = $state(false);
  // Mot de passe prérempli en Modifier : sans changement, il n'est pas renvoyé.
  // Vidé à la fermeture de la fiche, comme le champ.
  let prefilled = '';
  let pcIp = $state('');
  let gateway = $state('');
  let confirming = $state('');
  let needPassword = $state(true);

  const nameError = $derived(errorCode === 'error.duplicate_name' ? error : '');
  // Masque manquant : vu dès la saisie, ou rendu par Rust (même clé).
  const pcIpKey = $derived(pcIpError(pcIp) || (errorCode === 'error.missing_mask' ? errorCode : ''));
  const pcIpMessage = $derived(pcIpKey ? $_(`accounts.${pcIpKey}`) : '');
  const otherError = $derived(nameError || errorCode === 'error.missing_mask' ? '' : error);
  // Enregistrer reste grisé tant qu'un champ obligatoire est vide ou que l'IP du PC n'a pas de masque.
  const ready = $derived(name.trim() !== '' && login.trim() !== '' && (!needPassword || password !== '') && !pcIpError(pcIp));

  // Import en cours : le fichier choisi et son plan (la feuille s'ouvre dessus).
  let importing = $state<{ path: string; plan: ImportPlan } | null>(null);
  // Message posé dans la barre d'état : retiré à la sortie de la page, sans toucher celui d'un autre écran.
  let ownStatus: Status | null = null;
  const say = (s: Status) => {
    ownStatus = s;
    status.set(s);
  };

  const filters = [{ name: 'LenScout', extensions: [EXPORT_EXT] }];

  async function doExport() {
    error = '';
    errorCode = '';
    try {
      const chosen = await saveFile({ defaultPath: EXPORT_NAME, filters });
      if (!chosen) return;
      const path = withExtension(chosen);
      const count = await exportAccounts(path);
      say({ text: $_('accounts.exported', { values: { count } }), detail: $_('accounts.exportedIn', { values: { path } }) });
    } catch (e) {
      fail(e);
    }
  }

  async function doImport() {
    error = '';
    errorCode = '';
    try {
      const path = await openFile({ multiple: false, directory: false, filters });
      if (!path) return;
      importing = { path, plan: await importPlan(path) };
    } catch (e) {
      fail(e);
    }
  }

  async function imported(summary: ImportSummary) {
    importing = null;
    const count = summary.added + summary.replaced + summary.kept_both;
    say({ text: $_(count ? 'accounts.imported' : 'accounts.importedNone', { values: { count } }) });
    await refresh();
  }

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
    prefilled = '';
    showPassword = false;
    pcIp = a?.pc_ip ?? '';
    gateway = a?.gateway ?? '';
    if (a?.has_secret) void reveal(a.id);
  }

  /** Préremplit le mot de passe (masqué) ; ignoré si la fiche a changé ou a été fermée entre-temps, ou déjà saisi. */
  async function reveal(id: string) {
    try {
      const p = await accountPassword(id);
      if (editing !== id || password !== '' || !p) return;
      password = p;
      prefilled = p;
    } catch {
      // Champ vide : on peut toujours ressaisir, ou garder l'actuel.
    }
  }

  function close() {
    editing = null;
    password = '';
    prefilled = '';
    showPassword = false;
    error = '';
    errorCode = '';
  }

  async function save() {
    error = '';
    errorCode = '';
    try {
      const net = netIn(pcIp, gateway);
      if (editing) await updateAccount(editing, name, login, passwordToSend(password, prefilled), net);
      else await createAccount(name, login, password, net);
    } catch (e) {
      fail(e);
      return;
    } finally {
      // Le mot de passe ne reste pas dans le champ, succès ou non.
      password = '';
      prefilled = '';
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

  onMount(() => () => clearStatusIf(ownStatus));

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
  <button class="btn" onclick={doImport}>{$_('accounts.import')}</button>
  <button class="btn" onclick={doExport} disabled={accounts.length === 0}>{$_('accounts.export')}</button>
  <span class="gap"></span>
  <button class="btn def" onclick={() => open(null)}>{$_('accounts.add')}</button>
</div>

{#if error && editing === null}<p class="err">{error}</p>{/if}

<table>
  <thead>
    <tr>
      <th style="width:34%">{$_('accounts.col.name')}</th>
      <th style="width:22%">{$_('accounts.col.login')}</th>
      <th>{$_('accounts.field.pc_ip')}</th>
      <th>{$_('accounts.field.password')}</th>
      <th style="width:1%"></th>
    </tr>
  </thead>
  <tbody>
    {#each accounts as a (a.id)}
      <tr>
        <td>{a.name}</td>
        <td>{a.login}</td>
        <td class="dim-t">{a.pc_ip ?? ''}</td>
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

{#if importing}
  <ImportSheet path={importing.path} plan={importing.plan} existing={accounts.map((a) => a.name)} onClose={() => (importing = null)} onDone={imported} />
{/if}

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
        <span class="pw">
          <input id="a-password" type={showPassword ? 'text' : 'password'} bind:value={password} required={needPassword} autocomplete="new-password" spellcheck="false" />
          <button class="eye" type="button" onclick={() => (showPassword = !showPassword)}
            aria-label={$_(showPassword ? 'accounts.hidePassword' : 'accounts.showPassword')} aria-pressed={showPassword}>
            <svg viewBox="0 0 16 16" aria-hidden="true">
              <path d="M1.5 8S4 3.5 8 3.5 14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8z" />
              <circle cx="8" cy="8" r="2" />
              {#if showPassword}<path d="M2.5 13.5l11-11" />{/if}
            </svg>
          </button>
        </span>
        <label for="a-pcip">{$_('accounts.field.pc_ip')}</label>
        <input id="a-pcip" type="text" bind:value={pcIp} oninput={() => { if (errorCode === 'error.missing_mask') { error = ''; errorCode = ''; } }}
          placeholder="192.168.1.250/24" inputmode="decimal" autocomplete="off" spellcheck="false"
          aria-invalid={pcIpMessage ? 'true' : undefined} aria-describedby={pcIpMessage ? 'a-pcip-err' : undefined} />
        {#if pcIpMessage}<span class="note bad" id="a-pcip-err">{pcIpMessage}</span>{/if}
        <label for="a-gw">{$_('accounts.field.gateway')}</label>
        <input id="a-gw" type="text" bind:value={gateway} placeholder="192.168.1.1" inputmode="decimal" autocomplete="off" spellcheck="false" />
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
  /* Importer / Exporter à côté du titre, Ajouter à l'autre bout. */
  .tools .title { flex: none; margin-right: 6px; }
  .gap { flex: 1; }
  /* Œil du mot de passe, dans le champ à droite. */
  .pw { position: relative; display: block; }
  .pw input { padding-right: 30px; }
  .eye {
    position: absolute; right: 3px; top: 50%; transform: translateY(-50%);
    width: 24px; height: 22px; padding: 0; border: 0; border-radius: 5px;
    background: transparent; color: var(--text-2); cursor: pointer;
    display: inline-flex; align-items: center; justify-content: center;
  }
  .eye:hover { color: var(--text); }
  .eye:focus-visible { outline: 2px solid var(--act); outline-offset: 1px; }
  .eye svg { width: 16px; height: 16px; fill: none; stroke: currentColor; stroke-width: 1.3; stroke-linecap: round; stroke-linejoin: round; }
</style>

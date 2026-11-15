<script lang="ts">
  import { onMount } from 'svelte';
  import { _, locale } from 'svelte-i18n';
  import { open as openFile, save as saveFile } from '@tauri-apps/plugin-dialog';
  import {
    accountCameras, accountFill, accountPassword, accountsStartup, createAccount, EXPORT_EXT, EXPORT_NAME, exportAccounts, fillLabel, forgetCamera,
    importPlan, knownKey, netIn, networkEnds, noticeKey, passwordRequired, passwordToSend, pcIpError, removeAccount, segmentBox, updateAccount,
    withExtension, type AccountEntry, type ImportPlan, type ImportSummary, type KnownCamera, type NetworkFill,
  } from '#lib/api/accounts.ts';
  import { errorKey } from '#lib/api/errors.ts';
  import { accountList, refreshAccounts } from '#lib/stores/accounts.ts';
  import { clearStatusIf, page, status, type Status } from '#lib/stores/nav.ts';
  import ImportSheet from './ImportSheet.svelte';

  // Liste partagée avec les sélecteurs des autres écrans.
  const accounts = $derived<AccountEntry[]>($accountList ?? []);
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
  let exclusions = $state('');
  let confirming = $state('');
  let needPassword = $state(true);
  // Réseau du compte modifié, tel qu'enregistré : remplissage et caméras connues.
  let fill = $state<NetworkFill | null>(null);
  let known = $state<KnownCamera[]>([]);
  // Clé de la caméra dont l'oubli attend sa confirmation.
  let forgetting = $state('');
  const ends = $derived(fill ? networkEnds(fill.network) : null);
  const counts = $derived(fill ? fillLabel(fill) : null);
  const seenOn = (c: KnownCamera) => new Date(c.last_seen * 1000).toLocaleDateString($locale ?? undefined);

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
      say({ text: { key: 'accounts.exported', values: { count } }, detail: { key: 'accounts.exportedIn', values: { path } } });
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
    say({ text: { key: count ? 'accounts.imported' : 'accounts.importedNone', values: { count } } });
    await refresh();
  }

  const fail = (e: unknown) => {
    errorCode = errorKey(e);
    error = `accounts.${errorCode}`;
  };

  // IP libres par compte, pour la colonne « Libres » du tableau.
  let fills = $state<Record<string, { free: number; almost: boolean }>>({});
  async function loadFills() {
    const entries = await Promise.all(
      accounts.map(async (a) => {
        try {
          const f = await accountFill(a.id);
          return [a.id, f ? { free: f.free, almost: f.almost_full } : null] as const;
        } catch {
          return [a.id, null] as const;
        }
      }),
    );
    fills = Object.fromEntries(entries.filter((e): e is [string, { free: number; almost: boolean }] => e[1] !== null));
  }

  async function refresh() {
    try {
      await refreshAccounts();
      await loadFills();
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
    exclusions = a?.exclusions ?? '';
    fill = null;
    known = [];
    forgetting = '';
    if (a?.has_secret) void reveal(a.id);
    if (a) void loadNet(a.id);
  }

  /** Remplissage et caméras du compte ; ignoré si la fiche a changé entre-temps. Un échec laisse le bloc caché. */
  async function loadNet(id: string) {
    try {
      const [f, k] = await Promise.all([accountFill(id), accountCameras(id)]);
      if (editing !== id) return;
      fill = f;
      known = [...k].sort((a, b) => b.last_seen - a.last_seen);
    } catch {}
  }

  /** Deux clics, comme Supprimer : le premier demande confirmation. */
  async function forget(c: KnownCamera) {
    const key = knownKey(c);
    if (forgetting !== key) {
      forgetting = key;
      return;
    }
    forgetting = '';
    const id = editing;
    if (!id) return;
    try {
      await forgetCamera(id, key);
    } catch (e) {
      fail(e);
    }
    await loadNet(id);
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
      const net = netIn(pcIp, gateway, exclusions);
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

  // Onglet quitté (il reste monté) : son message quitte la barre d'état.
  $effect(() => {
    if ($page !== 'accounts') clearStatusIf(ownStatus);
  });
  onMount(() => () => clearStatusIf(ownStatus));

  onMount(async () => {
    try {
      const key = noticeKey(await accountsStartup());
      if (key) {
        errorCode = key;
        error = `accounts.${key}`;
      }
    } catch {}
    await refresh();
  });
</script>

<div class="tools bar">
  <span class="title">{$_('common.nav.accounts')}</span>
  <button class="btn" onclick={doImport}>{$_('accounts.import')}</button>
  <button class="btn" onclick={doExport} disabled={accounts.length === 0}>{$_('accounts.export')}</button>
  <button class="btn def" onclick={() => open(null)}>{$_('accounts.add')}</button>
</div>

{#if error && editing === null}<p class="err">{$_(error)}</p>{/if}

<div class="cols">
  <div class="list">
<table>
  <thead>
    <tr>
      <th>{$_('accounts.col.name')}</th>
      <th style="width:150px">{$_('accounts.col.login')}</th>
      <th style="width:150px">{$_('accounts.field.pc_ip')}</th>
      <th style="width:96px">{$_('accounts.col.free')}</th>
      <th style="width:110px">{$_('accounts.field.password')}</th>
      <th class="acts"></th>
    </tr>
  </thead>
  <tbody>
    {#each accounts as a (a.id)}
      <tr>
        <td class="grow" title={a.name}>{a.name}</td>
        <td>{a.login}</td>
        <td class="m">{a.pc_ip ?? ''}</td>
        <td class="m" class:warn={fills[a.id]?.almost}>{fills[a.id] ? fills[a.id].free : '—'}</td>
        <td>{#if a.has_secret}••••••••{:else}<span class="warn">{$_('accounts.resecret')}</span>{/if}</td>
        <td class="ra acts">
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
  </div>

  {#if editing !== null}
    <aside class="editpanel">
      <div class=" phead"><h2>{editing ? (name.trim() || $_('accounts.edit')) : $_('accounts.add')}</h2></div>
    <form onsubmit={(e) => { e.preventDefault(); if (ready) void save(); }}>
      <div class="form">
        <label for="a-name">{$_('accounts.field.name')}</label>
        <input id="a-name" type="text" bind:value={name} autocomplete="off" aria-invalid={nameError ? 'true' : undefined} />
        {#if nameError}<span class="note bad">{$_(nameError)}</span>{/if}
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
        <label for="a-excl">{$_('accounts.field.exclusions')}</label>
        <input id="a-excl" class="m" type="text" bind:value={exclusions} placeholder="192.168.1.2-192.168.1.9, 192.168.1.100" autocomplete="off" spellcheck="false" />
      </div>
      {#if editing && (fill || known.length > 0)}
        <section class="subnet">
          <div class="sh">
            <span>{$_('accounts.net.title')}</span>
            {#if fill?.almost_full}<span class="warn">{$_('accounts.net.almostFull')}</span>{/if}
          </div>
          {#if fill}
            <div class="strip" role="img" aria-label={fill.network}>
              {#each fill.segments as seg (`${seg.kind}-${seg.first}`)}
                {@const b = segmentBox(seg, fill.size)}
                <span class="k-{seg.kind}" style="left:{b.left}%;width:{b.width}%"></span>
              {/each}
            </div>
            {#if ends}<div class="ends"><span class="m">{ends[0]}</span><span class="m">{ends[1]}</span></div>{/if}
            <ul class="legend">
              {#if fill.gateway}<li><i class="k-gateway"></i>{$_('accounts.net.gateway')}</li>{/if}
              <li><i class="k-pc"></i>{$_('accounts.net.pc')}</li>
              {#if fill.excluded}<li><i class="k-excluded"></i>{$_('accounts.net.excluded')} {fill.excluded}</li>{/if}
              <li><i class="k-camera"></i>{$_('accounts.net.cameras')}</li>
              {#if counts}<li class="count">{$_('accounts.net.summary', { values: counts })}</li>{/if}
            </ul>
          {/if}
          {#if known.length > 0}
            <details>
              <summary>{$_('accounts.net.known', { values: { count: known.length } })}</summary>
              <div class="known">
                <table>
                  <tbody>
                    {#each known as c (knownKey(c))}
                      <tr>
                        <td class="mono">{c.ip}</td>
                        <td class="grow" title={c.model ?? ''}>{c.model ?? ''}</td>
                        <td class="mono dim-t" title={knownKey(c)}>{knownKey(c)}</td>
                        <td class="dim-t">{$_('accounts.net.seen', { values: { date: seenOn(c) } })}</td>
                        <td class="ra">
                          <button class="mini" type="button" class:danger={forgetting === knownKey(c)} onclick={() => forget(c)}>
                            {forgetting === knownKey(c) ? $_('accounts.net.confirmForget') : $_('accounts.net.forget')}
                          </button>
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            </details>
          {/if}
        </section>
      {/if}
      <div class="foot">
        <span class="sum" class:e={!!otherError}>{otherError ? $_(otherError) : ''}</span>
        <button class="btn" type="button" onclick={close}>{$_('accounts.cancel')}</button>
        <button class="btn def" type="submit" disabled={!ready}>{$_('accounts.save')}</button>
      </div>
    </form>
    </aside>
  {/if}
</div>

{#if importing}
  <ImportSheet path={importing.path} plan={importing.plan} existing={accounts.map((a) => a.name)} onClose={() => (importing = null)} onDone={imported} />
{/if}

<style>
  /* Le tableau à gauche, le panneau d'édition ancré à droite (comme la maquette). */
  /* Le panneau prend toute la hauteur disponible, le tableau à côté. */
  .cols { display: flex; align-items: stretch; gap: 16px; padding: 0 24px; min-height: calc(100vh - 150px); }
  .list { flex: 1; min-width: 0; }
  /* Le tableau garde ses gouttières via le conteneur, pas via .page. */
  .list table td:first-child, .list table th:first-child { padding-left: 0; }
  .list table td:last-child, .list table th:last-child { padding-right: 0; }
  .editpanel { flex: none; width: 360px; display: flex; flex-direction: column; padding: 16px; border: 1px solid var(--line); border-radius: 10px; background: var(--win); overflow: auto; }
  .editpanel .phead h2 { margin: 0 0 14px; font-size: 16px; font-weight: 600; color: var(--text); }
  form { margin: 0; }
  /* Boutons groupés à côté du titre : ils ne suivent pas le bord de la fenêtre. */
  .tools .title { flex: none; margin-right: 6px; }
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
  /* Le réseau du compte : barre à l'échelle du réseau, libres = le fond.
     Passerelle en bleu froid (mesurée), PC en ambre (posé par la personne). */
  .subnet { display: flex; flex-direction: column; gap: 8px; margin-top: 16px; padding: 16px; border: 1px solid var(--line); border-radius: 10px; background: var(--win); }
  .subnet .sh { display: flex; justify-content: space-between; gap: 8px; font-weight: 500; font-size: 14px; }
  .subnet .sh .warn { color: var(--warn); font-weight: 500; }
  .strip { position: relative; height: 28px; border-radius: 4px; background: var(--page); border: 1px solid var(--line); overflow: hidden; }
  .strip span { position: absolute; top: 0; bottom: 0; min-width: 3px; }
  .k-gateway { background: var(--cool); }
  .k-pc { background: var(--act); }
  .k-camera { background: var(--ok); }
  .k-excluded { background: repeating-linear-gradient(135deg, var(--line-2) 0 2px, transparent 2px 5px); }
  .legend .k-excluded { border: 1px solid var(--line-2); }
  .ends { display: flex; justify-content: space-between; color: var(--text-2); font-size: 12px; }
  .legend { display: flex; flex-wrap: wrap; gap: 4px 16px; margin: 0; padding: 0; list-style: none; color: var(--text-ink2); font-size: 13px; }
  .legend li { display: inline-flex; align-items: center; gap: 8px; }
  .legend i { width: 12px; height: 12px; border-radius: 2px; }
  .legend .count { margin-left: auto; color: var(--text-2); }
  .subnet summary { cursor: pointer; color: var(--text-2); font-size: 13px; }
  .known { max-height: 180px; overflow-y: auto; margin-top: 4px; }
  .known td { height: 36px; }
  .known tbody tr:last-child td { border-bottom: 0; }
  .eye svg { width: 16px; height: 16px; fill: none; stroke: currentColor; stroke-width: 1.3; stroke-linecap: round; stroke-linejoin: round; }
</style>

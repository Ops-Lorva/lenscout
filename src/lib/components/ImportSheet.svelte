<script lang="ts">
  import { _ } from 'svelte-i18n';
  import {
    applyImport, CHOICES, defaultChoices, groupPlan, suffixedName,
    type Choice, type ImportItem, type ImportPlan, type ImportSummary,
  } from '$lib/api/accounts';
  import { errorKey } from '$lib/api/errors';
  import Dialog from './Dialog.svelte';

  // Feuille d'import : ce que contient le fichier, en trois groupes. On ne
  // choisit que pour les noms déjà présents qui diffèrent.
  let {
    path,
    plan,
    existing,
    onClose,
    onDone,
  }: {
    path: string;
    plan: ImportPlan;
    /** Noms des comptes déjà dans le carnet (pour annoncer le suffixe de « Garder les deux »). */
    existing: string[];
    onClose: () => void;
    onDone: (summary: ImportSummary) => void;
  } = $props();

  const groups = $derived(groupPlan(plan));
  // svelte-ignore state_referenced_locally
  let choices = $state<Record<string, Choice>>(defaultChoices(plan));
  let error = $state('');
  let busy = $state(false);

  const file = $derived(path.split(/[\\/]/).pop() ?? path);

  const why = (i: ImportItem) =>
    $_(`accounts.why.${i.login_differs && i.password_differs ? 'both' : i.login_differs ? 'login' : 'password'}`);

  // « Garder les deux » crée des noms nouveaux : on les annonce, deux « Mairie » du fichier ne se heurtent pas.
  const keepNote = $derived.by(() => {
    const taken = [...existing, ...groups.added.map((i) => i.name)];
    const names: string[] = [];
    for (const i of groups.differs) {
      if (choices[i.name] !== 'keep_both') continue;
      const n = suffixedName(i.name, taken);
      taken.push(n);
      names.push(n);
    }
    return names.length ? $_('accounts.keepNote', { values: { names: names.join('», «') } }) : '';
  });

  async function run() {
    busy = true;
    error = '';
    try {
      onDone(await applyImport(path, choices));
    } catch (e) {
      error = $_(`accounts.${errorKey(e)}`);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={$_('accounts.importTitle', { values: { count: plan.items.length } })} width={520} {onClose}>
  <div class="file">{file}</div>
  {#if groups.differs.length}
    <div class="grp">{$_('accounts.grp.differs')}</div>
    <div class="list">
      {#each groups.differs as i (i.name)}
        <div class="it">
          <div class="who">{i.name}<div class="why">{why(i)}</div></div>
          <select aria-label={i.name} bind:value={choices[i.name]}>
            {#each CHOICES as c}<option value={c}>{$_(`accounts.choice.${c}`)}</option>{/each}
          </select>
        </div>
      {/each}
    </div>
  {/if}
  {#if groups.added.length}
    <div class="grp">{$_('accounts.grp.new')}</div>
    <div class="list">
      {#each groups.added as i (i.name)}
        <div class="it"><div class="who">{i.name}</div><span class="st new">{$_('accounts.st.new')}</span></div>
      {/each}
    </div>
  {/if}
  {#if groups.identical.length}
    <div class="grp">{$_('accounts.grp.identical')}</div>
    <div class="list">
      {#each groups.identical as i (i.name)}
        <div class="it"><div class="who">{i.name}</div><span class="st">{$_('accounts.st.identical')}</span></div>
      {/each}
    </div>
  {/if}
  <div class="foot">
    <span class="sum" class:e={!!error}>{error || keepNote}</span>
    <button class="btn" type="button" onclick={onClose}>{$_('accounts.cancel')}</button>
    <button class="btn def" type="button" onclick={run} disabled={busy}>{$_('accounts.doImport')}</button>
  </div>
</Dialog>

<style>
  .file { color: var(--text-2); font-size: 12px; margin: -8px 0 12px; overflow-wrap: anywhere; }
  .grp { font-size: 12px; color: var(--text-2); margin: 12px 0 5px; }
  .file + .grp { margin-top: 0; }
  .list { border: 1px solid var(--line); border-radius: 8px; background: var(--field); overflow: hidden; max-height: 220px; overflow-y: auto; }
  .it { display: flex; align-items: center; gap: 10px; padding: 6px 10px; border-top: 1px solid var(--line-soft); }
  .it:first-child { border-top: 0; }
  .who { flex: 1; min-width: 0; overflow-wrap: anywhere; }
  .why { color: var(--warn); font-size: 12px; }
  .st { color: var(--text-2); font-size: 12px; }
  .st.new { color: var(--ok); }
</style>

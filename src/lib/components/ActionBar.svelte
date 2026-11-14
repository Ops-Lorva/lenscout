<script lang="ts">
  import { _ } from 'svelte-i18n';
  import { activateCleartext, applyAction, canActivate, cleartextPending, dialogAfterSelection, canAct, canChangeIp, canBatchIp, clearResults, mergeResults, setResults, type ActionDto, type ActionResult } from '#lib/api/configure.ts';
  import type { Camera } from '#lib/api/types.ts';
  import { errorKey } from '#lib/api/errors.ts';
  import { cameraKey, cameras, selectedCameras } from '#lib/stores/cameras.ts';
  import BatchIpDialog from './BatchIpDialog.svelte';
  import ActivateDialog from './ActivateDialog.svelte';
  import NetworkDialog from './NetworkDialog.svelte';
  import TimeDialog from './TimeDialog.svelte';

  // `iface` : l'interface du scan en cours. `onDone` : appelé après une action
  // qui change l'IP, pour que la page rescanne.
  let { iface, onDone }: { iface: string; onDone: () => void } = $props();

  let open = $state<'activate' | 'network' | 'batch' | 'time' | null>(null);
  let accountId = $state('');
  let busy = $state(false);
  let error = $state('');
  // HTTPS injoignable à l'activation : caméras qui attendent une confirmation
  // d'envoi en clair, une par une, avec le compte de l'activation.
  let pending = $state<Camera[]>([]);
  let pendingAccount = '';

  const cams = $derived($selectedCameras);
  const allowed = $derived(canAct(cams));
  const activatable = $derived(canActivate(cams));
  const ipAllowed = $derived(canChangeIp(cams));
  const batchAllowed = $derived(canBatchIp(cams));
  // Les caméras non cochées (même masquées par la recherche) : leurs adresses sont à protéger.
  const others = $derived($cameras.filter((c) => !cams.some((s) => cameraKey(s) === cameraKey(c))));
  // La feuille IP vise une caméra : son nom et son adresse dans le titre.
  const one = $derived(cams.length === 1 ? cams[0] : null);
  const oneLabel = $derived(one ? `${[one.brand, one.model].filter(Boolean).join(' ') || '—'}, ${one.ip}` : '');

  // Sélection vidée (décochée, recherche, rescan) : pas de dialogue sur rien.
  $effect(() => {
    open = dialogAfterSelection(open, cams);
  });

  // Résultats d'un lot : même texte par ligne, puis rescan comme après une IP.
  function batchDone(results: ActionResult[]) {
    clearResults();
    setResults(results);
    open = null;
    onDone();
  }

  function closeDialog() {
    open = null;
    pending = [];
  }

  async function run(action: ActionDto) {
    // La sélection est figée au clic : ce qui part est ce que le dialogue annonçait.
    const targets = cams;
    if (targets.length === 0) return;
    busy = true;
    error = '';
    clearResults();
    try {
      const results = await applyAction(targets, accountId, action, iface);
      setResults(results);
      pending = action.kind === 'activate' ? cleartextPending(results, targets) : [];
      pendingAccount = accountId;
      if (pending.length === 0) open = null;
      if (action.kind === 'network_dhcp' || action.kind === 'network_static') onDone();
    } catch (e) {
      closeDialog();
      error = `configure.${errorKey(e)}`;
    } finally {
      busy = false;
    }
  }

  // Confirmation pour UNE caméra : le mot de passe part en clair vers elle seule.
  async function confirmCleartext(cam: Camera) {
    busy = true;
    error = '';
    try {
      mergeResults(await activateCleartext(cam, pendingAccount, iface));
      pending = pending.filter((c) => c !== cam);
      if (pending.length === 0) open = null;
    } catch (e) {
      closeDialog();
      error = `configure.${errorKey(e)}`;
    } finally {
      busy = false;
    }
  }
</script>

{#if cams.length > 0}
  <div class="tools">
    <button class="btn" disabled={!activatable} onclick={() => (open = 'activate')}>{$_('configure.activate')}</button>
    <button class="btn" disabled={!ipAllowed} onclick={() => (open = 'network')}>{$_('configure.ip')}</button>
    <button class="btn" disabled={!batchAllowed} onclick={() => (open = 'batch')}>{$_('batch.title')}</button>
    <button class="btn" disabled={!allowed} onclick={() => (open = 'time')}>{$_('configure.time')}</button>
    <span class="count">{$_('configure.cameras', { values: { count: cams.length } })}</span>
    {#if busy}<span class="spin" aria-label={$_('configure.busy')}></span>{/if}
    {#if error}<span class="err inline">{$_(error)}</span>{/if}
  </div>
{/if}

{#if open === 'activate'}
  <ActivateDialog count={cams.length} bind:accountId {busy} {pending} onSubmit={() => run({ kind: 'activate' })} onConfirm={confirmCleartext} onClose={closeDialog} />
{:else if open === 'network'}
  <NetworkDialog subtitle={oneLabel} bind:accountId {busy} {iface} onSubmit={run} onClose={() => (open = null)} />
{:else if open === 'batch'}
  <BatchIpDialog bind:accountId {iface} {cams} {others} onApplied={batchDone} onClose={() => (open = null)} />
{:else if open === 'time'}
  <TimeDialog bind:accountId {busy} onSubmit={run} onClose={() => (open = null)} />
{/if}

<style>
  .err.inline { margin: 0; }
</style>

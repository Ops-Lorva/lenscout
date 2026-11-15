<script lang="ts">
  import { _ } from 'svelte-i18n';
  import { activateCleartext, applyAction, canActivate, pendingAfterConfirm, pendingAfterRun, dialogAfterSelection, canAct, canChangeIp, canBatchIp, canReset, clearResults, mergeResults, setResults, type ActionDto, type ActionResult } from '#lib/api/configure.ts';
  import type { Camera } from '#lib/api/types.ts';
  import { cameraName } from '#lib/api/discovery.ts';
  import { errorKey } from '#lib/api/errors.ts';
  import { cameraKey, cameras, markActivated, markAddressing, selectedCameras } from '#lib/stores/cameras.ts';
  import { openOperations } from '#lib/stores/nav.ts';
  import BatchIpDialog from './BatchIpDialog.svelte';
  import ActivateDialog from './ActivateDialog.svelte';
  import NetworkDialog from './NetworkDialog.svelte';
  import ResetDialog from './ResetDialog.svelte';
  import TimeDialog from './TimeDialog.svelte';

  // `iface` : l'interface du scan en cours. `open` : la page ouvre la
  // réinitialisation depuis le menu « … » d'une ligne. Pas de rescan
  // automatique après une action : la ligne se met à jour sur place, le
  // technicien rafraîchit avec le bouton Rescanner quand il veut.
  type Open = 'activate' | 'network' | 'batch' | 'time' | 'reset';
  let {
    iface,
    open = $bindable(null),
  }: { iface: string; open?: Open | null } = $props();
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
  const resetAllowed = $derived(canReset(cams));
  // Les caméras non cochées (même masquées par la recherche) : leurs adresses sont à protéger.
  const others = $derived($cameras.filter((c) => !cams.some((s) => cameraKey(s) === cameraKey(c))));
  // La feuille IP vise une caméra : son nom et son adresse dans le titre.
  const one = $derived(cams.length === 1 ? cams[0] : null);
  const oneLabel = $derived(one ? `${cameraName(one)}, ${one.ip}` : '');

  // Sélection vidée (décochée, recherche, rescan) : pas de dialogue sur rien.
  $effect(() => {
    open = dialogAfterSelection(open, cams);
  });

  // Résultats d'un lot : même texte par ligne, l'adressage posé se voit sur place.
  function batchDone(results: ActionResult[]) {
    clearResults();
    setResults(results);
    markAddressing(results, 'static');
    open = null;
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
      if (action.kind === 'activate') markActivated(results);
      // L'adressage posé se voit tout de suite, sans attendre une lecture.
      if (action.kind === 'network_static') markAddressing(results, 'static', Object.fromEntries(targets.map((c) => [cameraKey(c), action.ip])));
      if (action.kind === 'network_dhcp') markAddressing(results, 'dhcp');
      pending = pendingAfterRun(action, results, targets);
      pendingAccount = accountId;
      if (pending.length === 0) open = null;
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
      const done = await activateCleartext(cam, pendingAccount, iface);
      mergeResults(done);
      markActivated(done);
      pending = pendingAfterConfirm(pending, cam);
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
  <!-- Barre de la sélection (maquette) : le compte d'abord, Activer en principal, la réinitialisation en rouge. -->
  <div class="tools selbar">
    <span class="count">{$_('configure.cameras', { values: { count: cams.length } })}</span>
    <button class="btn def" disabled={!activatable} onclick={() => (open = 'activate')}>{$_('configure.activate')}</button>
    <span class="sep" aria-hidden="true"></span>
    <button class="btn" disabled={!ipAllowed} onclick={() => (open = 'network')}>{$_('configure.ip')}</button>
    <!-- Raccourci : l'onglet Opérations, sur Renuméroter, avec la sélection courante (aperçu, confirmation, Arrêter). -->
    <button class="btn" disabled={!batchAllowed} onclick={() => openOperations('renumber')}>{$_('batch.title')}</button>
    <button class="btn" disabled={!allowed} onclick={() => (open = 'time')}>{$_('configure.time')}</button>
    <button class="btn danger" disabled={!resetAllowed} onclick={() => (open = 'reset')}>{$_('configure.reset.button')}</button>
    {#if busy}<span class="spin" aria-label={$_('configure.busy')}></span>{/if}
    {#if error}<span class="err inline">{$_(error)}</span>{/if}
  </div>
{/if}

{#if open === 'activate'}
  <ActivateDialog count={cams.length} bind:accountId {busy} {pending} onSubmit={() => run({ kind: 'activate' })} onConfirm={confirmCleartext} onClose={closeDialog} />
{:else if open === 'network'}
  <NetworkDialog subtitle={oneLabel} own={cams.map((c) => c.ip)} bind:accountId {busy} {iface} onSubmit={run} onClose={() => (open = null)} />
{:else if open === 'batch'}
  <BatchIpDialog bind:accountId {iface} {cams} {others} onApplied={batchDone} onClose={() => (open = null)} />
{:else if open === 'time'}
  <TimeDialog bind:accountId {busy} onSubmit={run} onClose={() => (open = null)} />
{:else if open === 'reset'}
  <ResetDialog bind:accountId {cams} {busy} onSubmit={run} onClose={() => (open = null)} />
{/if}

<style>
  .err.inline { margin: 0; }
</style>

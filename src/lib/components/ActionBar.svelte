<script lang="ts">
  import { _ } from 'svelte-i18n';
  import { applyAction, canActivate, canAct, canChangeIp, clearResults, setResults, type ActionDto } from '$lib/api/configure';
  import { errorKey } from '$lib/api/errors';
  import { selectedCameras } from '$lib/stores/cameras';
  import ActivateDialog from './ActivateDialog.svelte';
  import NetworkDialog from './NetworkDialog.svelte';
  import TimeDialog from './TimeDialog.svelte';

  // `iface` : l'interface du scan en cours. `onDone` : appelé après une action
  // qui change l'IP, pour que la page rescanne.
  let { iface, onDone }: { iface: string; onDone: (a: ActionDto) => void } = $props();

  let open = $state<'activate' | 'network' | 'time' | null>(null);
  let accountId = $state('');
  let busy = $state(false);
  let error = $state('');

  const cams = $derived($selectedCameras);
  const allowed = $derived(canAct(cams));
  const activatable = $derived(canActivate(cams));
  const ipAllowed = $derived(canChangeIp(cams));

  async function run(action: ActionDto) {
    // La sélection est figée au clic : ce qui part est ce que le dialogue annonçait.
    const targets = cams;
    busy = true;
    error = '';
    clearResults();
    try {
      setResults(await applyAction(targets, accountId, action, iface));
      open = null;
      if (action.kind === 'network_dhcp' || action.kind === 'network_static') onDone(action);
    } catch (e) {
      open = null;
      error = $_(`configure.${errorKey(e)}`);
    } finally {
      busy = false;
    }
  }
</script>

{#if cams.length > 0}
  <div class="actions">
    <button disabled={!activatable} onclick={() => (open = 'activate')}>{$_('configure.activate')}</button>
    <button disabled={!ipAllowed} onclick={() => (open = 'network')}>{$_('configure.ip')}</button>
    <button disabled={!allowed} onclick={() => (open = 'time')}>{$_('configure.time')}</button>
    <span class="count">{$_('configure.cameras', { values: { count: cams.length } })}</span>
    {#if busy}<span class="spinner"></span>{/if}
    {#if error}<span class="error">{error}</span>{/if}
  </div>
{/if}

{#if open === 'activate'}
  <ActivateDialog count={cams.length} bind:accountId {busy} onSubmit={() => run({ kind: 'activate' })} onClose={() => (open = null)} />
{:else if open === 'network'}
  <NetworkDialog bind:accountId {busy} {iface} onSubmit={run} onClose={() => (open = null)} />
{:else if open === 'time'}
  <TimeDialog bind:accountId {busy} onSubmit={run} onClose={() => (open = null)} />
{/if}

<style>
  .actions { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; }
  button {
    padding: 5px 14px; font-size: 13px; cursor: pointer;
    background: var(--ep-glass-bg-md); border: 1px solid var(--ep-glass-border);
    border-radius: var(--ep-radius-md); color: var(--ep-text-primary);
  }
  button:hover:not(:disabled) { border-color: var(--ep-accent); }
  button:disabled { opacity: 0.55; cursor: not-allowed; }
  .count { color: var(--ep-text-muted); font-size: 12.5px; }
  .error { color: var(--ep-danger); font-size: 12.5px; }
  .spinner {
    width: 11px; height: 11px; border-radius: 50%;
    border: 2px solid var(--ep-accent-glow); border-top-color: var(--ep-accent-bright);
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>

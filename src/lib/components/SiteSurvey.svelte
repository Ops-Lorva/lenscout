<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { _, locale } from 'svelte-i18n';
  import { interfaceDetails } from '#lib/api/core.ts';
  import { errorKey } from '#lib/api/errors.ts';
  import { markPingWorked, pingWorked, withoutPingUnavailable } from '#lib/api/freeIps.ts';
  import { activeAddress, joined } from '#lib/api/net.ts';
  import { accountDevices, cancelSurvey, forgetAllDevices, nextSurveyRun, onAccountNetwork, startSurvey, type SeenDevice } from '#lib/api/siteNet.ts';
  import { cameras } from '#lib/stores/cameras.ts';
  import SiteDevices from './SiteDevices.svelte';

  // Relevé du réseau du compte, dans la page Site : bouton, progression,
  // date du dernier relevé, puis l'inventaire en dessous. `onDone` :
  // l'occupation a changé (relevé ou appareil oublié). `onFrame` : une
  // caméra de l'inventaire part au Cadrage.
  let {
    accountId,
    accountName = '',
    pcIp,
    iface,
    onDone,
    onFrame,
  }: { accountId: string; accountName?: string; pcIp: string | null; iface: string; onDone: () => void; onFrame: (ip: string) => void } = $props();

  let devices = $state<SeenDevice[]>([]);
  let surveyedAt = $state<number | null>(null);
  let run = $state<{ id: number; done: number; total: number } | null>(null);
  let truncated = $state(false);
  let error = $state('');
  let resetting = $state(false);

  let details = $state<{ ip: string | null; subnet: string | null } | null>(null);
  $effect(() => {
    const name = iface;
    details = null;
    if (!name) return;
    interfaceDetails(name).then((d) => { if (iface === name) details = d; }).catch(() => {});
  });
  const here = $derived(onAccountNetwork(activeAddress(iface, details, $joined), { pc_ip: pcIp }));
  const when = $derived(surveyedAt === null ? '' : new Date(surveyedAt * 1000).toLocaleString($locale ?? undefined, { dateStyle: 'short', timeStyle: 'short' }));

  async function load(id: string) {
    try {
      const d = await accountDevices(id);
      if (accountId !== id) return;
      devices = d.devices;
      surveyedAt = d.surveyed_at;
    } catch {}
  }

  $effect(() => {
    const id = accountId;
    devices = [];
    surveyedAt = null;
    error = '';
    truncated = false;
    resetting = false;
    void load(id);
  });

  // Repart à zéro : oublie tout l'inventaire relevé (évite d'« oublier »
  // chaque appareil à la main) puis relance un relevé. Clic en deux temps
  // pour confirmer la suppression.
  async function resetAndSurvey() {
    if (run) return;
    if (!resetting) { resetting = true; return; }
    resetting = false;
    const id = accountId;
    try {
      await forgetAllDevices(id);
    } catch (e) {
      if (accountId === id) error = `free.${errorKey(e)}`;
      return;
    }
    if (accountId !== id) return;
    devices = [];
    surveyedAt = null;
    truncated = false;
    onDone();
    await survey();
  }

  async function survey() {
    if (run) return;
    resetting = false;
    const id = nextSurveyRun();
    const account = accountId;
    run = { id, done: 0, total: 0 };
    error = '';
    truncated = false;
    try {
      await startSurvey(id, account, iface, $cameras, (e) => {
        if (accountId !== account) return;
        if (e.kind === 'progress') {
          if (run?.id === id) run = { id, done: e.done, total: e.total };
        } else {
          devices = e.devices;
          surveyedAt = e.surveyed_at;
          truncated = e.truncated;
          markPingWorked();
          onDone();
        }
      });
    } catch (e) {
      if (accountId === account) error = `free.${errorKey(e)}`;
    } finally {
      if (run?.id === id) run = null;
    }
  }

  // Un ping a abouti depuis (ici ou dans une recherche d'IP libres) : le
  // « ping impossible » d'un essai précédent ne vaut plus.
  $effect(() => {
    void $pingWorked;
    untrack(() => (error = withoutPingUnavailable(error)));
  });

  function stop() {
    if (run) void cancelSurvey(run.id).catch(() => {});
  }

  onMount(() => () => {
    if (run) void cancelSurvey(run.id).catch(() => {});
  });
</script>

<div class="survey">
  {#if run}
    <span class="spin"></span>
    <span class="m">{$_('sitenet.progress', { values: { done: run.done, total: run.total || '…' } })}</span>
    <span class="grow"></span>
    <button class="mini" type="button" onclick={stop}>{$_('sitenet.stop')}</button>
  {:else}
    <span class="dim-t">{surveyedAt === null ? $_('sitenet.never') : $_('sitenet.surveyed', { values: { date: when } })}</span>
    {#if devices.length > 0}<span class="dim-t">{$_('sitenet.count', { values: { count: devices.length } })}</span>{/if}
    {#if truncated}<span class="warn">{$_('sitenet.truncated')}</span>{/if}
    <span class="grow"></span>
    {#if !here}<span class="dim-t off">{$_('sitenet.offNetwork')}</span>{/if}
    {#if surveyedAt !== null || devices.length > 0}
      <button class="mini" class:confirm={resetting} type="button" onclick={resetAndSurvey} disabled={!here || !iface} title={$_('sitenet.reset')}>{resetting ? $_('sitenet.confirmReset') : $_('sitenet.reset')}</button>
    {/if}
    <button class="mini" type="button" onclick={survey} disabled={!here || !iface}>{$_('sitenet.survey')}</button>
  {/if}
</div>
{#if error}<p class="err">{$_(error)}</p>{/if}

{#if devices.length > 0}
  <SiteDevices {accountId} {accountName} {devices} {surveyedAt} {onFrame}
    onForgot={async () => { await load(accountId); onDone(); }} />
{/if}

<style>
  .survey { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 13px; }
  .survey .grow { flex: 1; }
  .survey .warn { color: var(--warn); }
  .survey .mini.confirm { color: var(--err); border-color: var(--err); }
  .off { font-size: 12px; }
  .err { margin: 0; color: var(--err); font-size: 12.5px; }
</style>

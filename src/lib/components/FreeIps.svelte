<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import { page } from '#lib/stores/nav.ts';
  import { _ } from 'svelte-i18n';
  import {
    cancelFreeIps, freeErrorKey, networkLabel, rangeContaining, rangeLabel, reduceFreeEvent, startFreeIps,
    type FreeRange, type FreeState,
  } from '#lib/api/freeIps.ts';

  // Au plus autant d'adresses balayées que le cœur (`MAX_CANDIDATES`).
  const MAX_SCANNED = 1024;

  // `value` : l'adresse du champ voisin, pour marquer la plage qui la contient ;
  // `onPick` la remplit ; `onFound` reçoit les plages à la fin de chaque balayage.
  // `accountId` : le compte retenu, ses IP exclues ne sont jamais proposées.
  // Fermer la feuille (démontage) annule le balayage.
  let {
    iface,
    accountId = '',
    ifaceIp,
    ifaceMask,
    value,
    hidden = false,
    onPick,
    onFound = () => {},
  }: {
    iface: string;
    accountId?: string;
    ifaceIp: string | null;
    ifaceMask: string | null;
    value: string;
    hidden?: boolean;
    onPick: (ip: string) => void;
    onFound?: (ranges: FreeRange[]) => void;
  } = $props();

  let state = $state<FreeState | null>(null);
  // Un balayage remplacé ou une feuille fermée ne doit plus rien écrire.
  let run = 0;
  let runId: number | null = null;
  let alive = true;

  const active = $derived(state?.phase === 'done' ? rangeContaining(state.ranges, value) : undefined);

  async function scan() {
    const mine = ++run;
    state = { phase: 'scanning', done: 0, total: 0 };
    try {
      const started = startFreeIps(
        iface,
        (e) => {
          if (!alive || mine !== run) return;
          state = reduceFreeEvent(state, e);
          if (e.kind === 'done') onFound(e.ranges);
        },
        accountId,
      );
      runId = started.id;
      await started.done;
    } catch (e) {
      if (alive && mine === run) state = { phase: 'error', code: freeErrorKey(e) };
    }
  }

  /** Balayage en cours abandonné : plus rien n'écrit, le cœur l'arrête. */
  function cancel() {
    run++;
    if (runId !== null) void cancelFreeIps(runId).catch(() => {});
    runId = null;
  }

  // Les feuilles vivent dans l'onglet Réseau, gardé monté : onglet quitté,
  // le balayage s'arrête (pas de trafic dans le dos) ; au retour il reprend
  // s'il n'avait pas fini. Premier passage visible : le premier balayage.
  let interrupted = true;
  $effect(() => {
    const visible = $page === 'network';
    untrack(() => {
      if (!visible && state?.phase === 'scanning') {
        cancel();
        interrupted = true;
      } else if (visible && interrupted) {
        interrupted = false;
        void scan();
      }
    });
  });

  // Un autre compte retenu, d'autres IP exclues : les plages affichées ne
  // valent plus, on rebalaie (si un balayage a déjà eu lieu ou tourne).
  let scannedFor = untrack(() => accountId);
  $effect(() => {
    const a = accountId;
    untrack(() => {
      if (a === scannedFor) return;
      scannedFor = a;
      if (!interrupted) void scan();
    });
  });

  onDestroy(() => {
    alive = false;
    cancel();
  });
</script>

<div class="free" {hidden}>
  <div class="fh">
    <b>{$_('free.title')}</b>
    <span>{networkLabel(iface, ifaceIp, ifaceMask)}</span>
    <span class="sp"></span>
    <button class="mini" onclick={scan} disabled={state?.phase === 'scanning'}>{$_('free.rescan')}</button>
  </div>
  {#if state?.phase === 'scanning'}
    <div class="scan">
      <span class="spin"></span>
      <span>{$_('free.scanning')}{state.total > 0 ? `, ${state.done} / ${state.total}` : ''}</span>
    </div>
  {:else if state?.phase === 'error'}
    <div class="fn e">{$_(state.code)}</div>
  {:else if state?.phase === 'done'}
    {#if state.ranges.length === 0}
      <div class="scan">{$_('free.none')}</div>
    {:else}
      <div class="rngs">
        {#each state.ranges as r (r.first)}
          <button class="rng" class:on={r === active} aria-pressed={r === active} onclick={() => onPick(r.first)}>
            {rangeLabel(r)} <small>{r.count}</small>
          </button>
        {/each}
      </div>
    {/if}
    {#if state.truncated}<div class="fn">{$_('free.truncated', { values: { n: MAX_SCANNED } })}</div>{/if}
    <div class="fn">{$_('free.note')}</div>
  {/if}
</div>

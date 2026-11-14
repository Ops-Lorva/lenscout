<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { _ } from 'svelte-i18n';
  import {
    cancelFreeIps, freeErrorKey, networkLabel, rangeContaining, rangeLabel, reduceFreeEvent, startFreeIps,
    type FreeRange, type FreeState,
  } from '$lib/api/freeIps';

  // Au plus autant d'adresses balayées que le cœur (`MAX_CANDIDATES`).
  const MAX_SCANNED = 1024;

  // `value` : l'adresse du champ voisin, pour marquer la plage qui la contient ;
  // `onPick` la remplit ; `onFound` reçoit les plages à la fin de chaque balayage.
  // Fermer la feuille (démontage) annule le balayage.
  let {
    iface,
    ifaceIp,
    ifaceMask,
    value,
    hidden = false,
    onPick,
    onFound = () => {},
  }: {
    iface: string;
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
  let alive = true;

  const active = $derived(state?.phase === 'done' ? rangeContaining(state.ranges, value) : undefined);

  async function scan() {
    const mine = ++run;
    state = { phase: 'scanning', done: 0, total: 0 };
    try {
      await startFreeIps(iface, (e) => {
        if (!alive || mine !== run) return;
        state = reduceFreeEvent(state, e);
        if (e.kind === 'done') onFound(e.ranges);
      });
    } catch (e) {
      if (alive && mine === run) state = { phase: 'error', code: freeErrorKey(e) };
    }
  }

  onMount(scan);
  onDestroy(() => {
    alive = false;
    void cancelFreeIps().catch(() => {});
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

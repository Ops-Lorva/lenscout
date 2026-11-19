<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import { page } from '#lib/stores/nav.ts';
  import { _ } from 'svelte-i18n';
  import {
    cancelFreeIps, freeErrorKey, markPingWorked, networkLabel, rangeContaining, rangeLabel, reduceFreeEvent, startFreeIps,
    type FreeRange, type FreeState,
  } from '#lib/api/freeIps.ts';
  import { joined, joinRequest, needsJoin } from '#lib/api/net.ts';
  import { accountList } from '#lib/stores/accounts.ts';

  // Au plus autant d'adresses balayées que le cœur (`MAX_CANDIDATES`).
  const MAX_SCANNED = 1024;

  // `value` : l'adresse du champ voisin, pour marquer la plage qui la contient ;
  // `onPick` la remplit ; `onFound` reçoit les plages à la fin de chaque balayage.
  // `accountId` : le compte retenu, ses IP exclues ne sont jamais proposées.
  // `own` : les adresses actuelles des caméras visées, libres pour elles.
  // Fermer la feuille (démontage) annule le balayage.
  let {
    iface,
    accountId = '',
    own = [],
    ifaceIp,
    ifaceMask,
    value,
    hidden = false,
    tab = '',
    onPick,
    onFound = () => {},
  }: {
    iface: string;
    accountId?: string;
    own?: string[];
    ifaceIp: string | null;
    ifaceMask: string | null;
    value: string;
    hidden?: boolean;
    tab?: string;
    onPick: (ip: string) => void;
    onFound?: (ranges: FreeRange[]) => void;
  } = $props();

  let sweep = $state<FreeState | null>(null);

  // Le compte retenu n'est pas celui posé sur le PC : balayer ne servirait à
  // rien (on verrait le réseau de l'interface). On le dit, et on propose de le poser.
  const account = $derived($accountList?.find((a) => a.id === accountId) ?? null);
  const blocked = $derived(needsJoin(account, $joined, ifaceIp));
  let asked = $state(false);
  function join() {
    asked = true;
    joinRequest.set(accountId);
  }

  // Un balayage remplacé ou une feuille fermée ne doit plus rien écrire.
  let run = 0;
  let runId: number | null = null;
  let alive = true;

  const active = $derived(sweep?.phase === 'done' ? rangeContaining(sweep.ranges, value) : undefined);

  async function scan() {
    if (blocked) {
      cancel();
      sweep = null;
      return;
    }
    const mine = ++run;
    sweep = { phase: 'scanning', done: 0, total: 0 };
    try {
      const started = startFreeIps(
        iface,
        (e) => {
          if (!alive || mine !== run) return;
          sweep = reduceFreeEvent(sweep, e);
          if (e.kind === 'done') {
            markPingWorked();
            onFound(e.ranges);
          }
        },
        accountId,
        own,
      );
      runId = started.id;
      await started.done;
    } catch (e) {
      if (alive && mine === run) sweep = { phase: 'error', code: freeErrorKey(e) };
    }
  }

  /** Balayage en cours abandonné : plus rien n'écrit, le cœur l'arrête. */
  function cancel() {
    run++;
    if (runId !== null) void cancelFreeIps(runId).catch(() => {});
    runId = null;
  }

  // Les onglets restent montés : onglet quitté,
  // le balayage s'arrête (pas de trafic dans le dos) ; au retour il reprend
  // s'il n'avait pas fini. Premier passage visible : le premier balayage.
  // L'onglet qui la porte : `tab`, sinon celui ouvert au montage (feuilles).
  const home = untrack(() => tab || $page);
  let interrupted = true;
  $effect(() => {
    const visible = $page === home;
    untrack(() => {
      if (!visible && sweep?.phase === 'scanning') {
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
  let scannedFor = untrack(() => `${accountId}|${blocked}`);
  $effect(() => {
    const a = `${accountId}|${blocked}`;
    untrack(() => {
      if (a === scannedFor) return;
      scannedFor = a;
      asked = false;
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
    <button class="mini" onclick={scan} disabled={blocked || sweep?.phase === 'scanning'}>{$_('free.rescan')}</button>
  </div>
  {#if blocked && account}
    <div class="scan">
      <span>{$_('free.not_joined', { values: { name: account.name, ip: account.pc_ip } })}</span>
      <span class="sp"></span>
      <button class="mini" onclick={join} disabled={asked}>{$_('free.join', { values: { name: account.name } })}</button>
    </div>
  {:else if sweep?.phase === 'scanning'}
    <div class="scan">
      <span class="spin"></span>
      <span>{$_('free.scanning')}{sweep.total > 0 ? `, ${sweep.done} / ${sweep.total}` : ''}</span>
    </div>
  {:else if sweep?.phase === 'error'}
    <div class="fn e">{$_(sweep.code)}</div>
  {:else if sweep?.phase === 'done'}
    {#if sweep.ranges.length === 0}
      <div class="scan">{$_('free.none')}</div>
    {:else}
      <div class="rngs">
        {#each sweep.ranges as r (r.first)}
          <button class="rng" class:on={r === active} aria-pressed={r === active} onclick={() => onPick(r.first)}>
            {rangeLabel(r)} <small>{r.count}</small>
          </button>
        {/each}
      </div>
    {/if}
    {#if sweep.truncated}<div class="fn">{$_('free.truncated', { values: { n: MAX_SCANNED } })}</div>{/if}
    <div class="fn">{$_('free.note')}</div>
  {/if}
</div>

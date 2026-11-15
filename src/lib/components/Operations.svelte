<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { accountFill, type Account, type NetworkFill } from '#lib/api/accounts.ts';
  import { batchErrorMessage, clearResults, defaultTimeZone, resultMessage, setResults, timeZones } from '#lib/api/configure.ts';
  import { interfaceDetails } from '#lib/api/core.ts';
  import { addressingKey, cameraName, shownMac } from '#lib/api/discovery.ts';
  import { errorKey } from '#lib/api/errors.ts';
  import { firstFit, type FreeRange } from '#lib/api/freeIps.ts';
  import { activeAddress, dnsFollowing, INITIAL_PREFILL, joined, prefillFields } from '#lib/api/net.ts';
  import {
    canApply, cells, conflictMessage, isBlocking, movedIps, opRequest, opsClose, opsFingerprint, opsPreview, opsStep, runSteps, summarize,
    type OpFields, type OpKind, type OpRow, type OpsPreview, type StepResult,
  } from '#lib/api/ops.ts';
  import type { Camera } from '#lib/api/types.ts';
  import { cameraKey, cameras, markAddressing, selection } from '#lib/stores/cameras.ts';
  import { ipsChanged, opsRequest, scanIface } from '#lib/stores/nav.ts';
  import AccountPicker from './AccountPicker.svelte';
  import FreeIps from './FreeIps.svelte';

  // Flux sur une page : choisir (caméras cochées, partagées avec Réseau, et
  // l'opération), aperçu calculé par Rust, confirmation par le nombre de
  // caméras tapé, application caméra par caméra avec Arrêter, puis rapport.
  const KINDS: OpKind[] = ['keep_ip', 'renumber', 'time'];
  const zones = timeZones();

  let kind = $state<OpKind>('keep_ip');
  let start = $state('');
  let mask = $state('');
  let gateway = $state('');
  let dns = $state('');
  let ntp = $state('');
  let timezone = $state(defaultTimeZone(zones));
  let accountId = $state('');
  let account = $state<Account | null>(null);
  let busy = $state(false);
  let error = $state<{ key: string; values?: Record<string, string | number> } | null>(null);
  let typed = $state('');

  const iface = $derived($scanIface);
  // Ordre affiché de Réseau (IP croissante) : celui du plan.
  const targets = $derived($cameras.filter((c) => $selection.has(cameraKey(c))));
  const others = $derived($cameras.filter((c) => !$selection.has(cameraKey(c))));
  const fields = $derived<OpFields>({ kind, start, mask, gateway, dns, ntp, timezone });
  const fingerprint = $derived(opsFingerprint(targets, fields, iface, accountId));

  // L'aperçu garde l'empreinte de ce qui l'a produit et les caméras visées.
  let preview = $state<{ data: OpsPreview; fingerprint: string; cams: Camera[]; kind: OpKind } | null>(null);
  const shown = $derived(preview && preview.fingerprint === fingerprint ? preview : null);
  const blocked = $derived(shown ? shown.data.rows.filter((r) => r.conflicts.some(isBlocking)).length : 0);

  // Une application en cours ou finie : figée, un rescan de Réseau ne la retire pas.
  let run = $state<{ id: string; rows: OpRow[]; cams: Camera[]; kind: OpKind; results: (StepResult | undefined)[]; current: number; stopping: boolean; done: boolean } | null>(null);
  let stopFlag = false;
  const running = $derived(!!run && !run.done);
  const table = $derived(run ?? (shown ? { rows: shown.data.rows, cams: shown.cams, kind: shown.kind, results: [] as (StepResult | undefined)[], current: -1 } : null));
  const report = $derived(run?.done ? summarize(run.results, run.rows.length) : null);
  const applyOk = $derived(canApply(shown?.data ?? null, typed, running));

  // Raccourci de Réseau (« IP en lot ») : l'opération demandée, la sélection est déjà partagée.
  $effect(() => {
    const req = $opsRequest;
    if (!req) return;
    untrack(() => {
      if (!running) {
        kind = req;
        run = null;
      }
      opsRequest.set(null);
    });
  });

  // Adresse du poste sur l'interface du scan (celle d'un compte posé, sinon la sienne).
  let details = $state<{ ip: string | null; subnet: string | null } | null>(null);
  $effect(() => {
    const name = iface;
    details = null;
    if (!name) return;
    interfaceDetails(name).then((d) => { if (iface === name) details = d; }).catch(() => {});
  });
  const addr = $derived(activeAddress(iface, details, $joined));

  // Renuméroter : le compte remplit masque et passerelle comme le lot ; un champ saisi n'est jamais écrasé.
  // Garder les IP : rien n'est prérempli (vide = inchangé).
  const touched = { mask: false, gateway: false };
  let dnsTouched = false;
  $effect(() => {
    const a = account;
    if (kind !== 'renumber') return;
    untrack(() => {
      if (mask === '') mask = INITIAL_PREFILL.mask;
      ({ mask, gateway } = prefillFields({ mask, gateway }, touched, a));
    });
  });
  $effect(() => {
    const g = gateway;
    if (kind !== 'renumber') return;
    untrack(() => (dns = dnsFollowing(dns, dnsTouched, g)));
  });

  function choose(k: OpKind) {
    if (running) return;
    kind = k;
    run = null;
    error = null;
    // Les champs d'une opération ne valent pas pour l'autre : vide = inchangé, pour garder les IP.
    start = mask = gateway = dns = '';
    touched.mask = touched.gateway = false;
    dnsTouched = false;
  }

  let fill = $state<NetworkFill | null>(null);
  $effect(() => {
    const id = accountId;
    fill = null;
    if (!id) return;
    accountFill(id).then((f) => { if (accountId === id) fill = f; }).catch(() => {});
  });

  function proposeStart(ranges: FreeRange[]) {
    if (start.trim() !== '') return;
    start = firstFit(ranges, targets.length) ?? '';
  }

  function toggle(c: Camera) {
    selection.update((s) => {
      const next = new Set(s);
      const k = cameraKey(c);
      if (!next.delete(k)) next.add(k);
      return next;
    });
  }

  const allChecked = $derived($cameras.length > 0 && $cameras.every((c) => $selection.has(cameraKey(c))));
  function toggleAll() {
    selection.update((s) => {
      const next = new Set(s);
      for (const c of $cameras) allChecked ? next.delete(cameraKey(c)) : next.add(cameraKey(c));
      return next;
    });
  }

  async function runPreview() {
    busy = true;
    error = null;
    preview = null;
    run = null;
    typed = '';
    const fp = fingerprint;
    const cams = targets;
    const k = kind;
    try {
      const data = await opsPreview(cams, others, opRequest(fields), iface, accountId);
      preview = { data, fingerprint: fp, cams, kind: k };
    } catch (e) {
      error = batchErrorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!shown?.data.id || !applyOk) return;
    const id = shown.data.id;
    const forAccount = accountId;
    const via = iface;
    run = { id, rows: shown.data.rows, cams: shown.cams, kind: shown.kind, results: [], current: -1, stopping: false, done: false };
    preview = null;
    typed = '';
    error = null;
    stopFlag = false;
    const r = run;
    try {
      await runSteps(
        r.rows.length,
        (i) => {
          r.current = i;
          return opsStep(id, i, forAccount, via);
        },
        () => stopFlag,
        (i, res) => (r.results[i] = res),
      );
    } catch (e) {
      error = { key: `configure.${errorKey(e)}` };
    } finally {
      r.current = -1;
      r.done = true;
      void opsClose(id).catch(() => {});
      finish(r);
    }
  }

  // Pastilles de Réseau, adressage posé, mémoire du compte (Rust) ; puis rescan de Réseau.
  function finish(r: NonNullable<typeof run>) {
    const done = r.results.filter((x): x is StepResult => !!x);
    clearResults();
    setResults(done);
    if (r.kind !== 'time' && done.some((x) => x.ok)) {
      markAddressing(done, 'static', movedIps(r.rows, r.results));
      ipsChanged.update((n) => n + 1);
    }
  }

  function stop() {
    stopFlag = true;
    if (run) run.stopping = true;
  }

  function stateOf(i: number): { text: string; cls: string } {
    const res = table?.results[i];
    if (!res) return { text: table?.current === i ? $_('ops.state.running') : '', cls: '' };
    if (!res.ok) {
      const m = resultMessage(res);
      return { text: m ? $_(m.key, { values: m.values }) : '', cls: 'bad' };
    }
    return res.reachable === false ? { text: $_('ops.state.unreachable'), cls: 'warn' } : { text: $_('ops.state.ok'), cls: 'ok' };
  }

  const ready = $derived(
    !busy && !running && !!iface && !!accountId && targets.length > 0 && (kind !== 'renumber' || (start.trim() !== '' && mask.trim() !== '')),
  );

  onMount(() => () => {
    // L'écran reste monté ; si jamais il part, plus rien ne doit suivre.
    stopFlag = true;
  });
</script>

<div class="tools bar">
  <span class="title">{$_('common.nav.operations')}</span>
  <span class="count">{$_('ops.selected', { values: { count: targets.length } })}</span>
</div>

<!-- 1. Choisir -->
<section class="step">
  <h4><b>1</b>{$_('ops.step.choose')}</h4>
  <div class="seg" role="radiogroup" aria-label={$_('ops.step.choose')}>
    {#each KINDS as k}
      <label><input type="radio" name="op-kind" value={k} checked={kind === k} disabled={running} onchange={() => choose(k)} /><span>{$_(`ops.kind.${k}`)}</span></label>
    {/each}
  </div>
  <div class="form">
    <label for="o-account">{$_('accounts.picker')}</label><AccountPicker id="o-account" bind:accountId bind:account />
    {#if kind === 'renumber'}
      {#if iface}
        <FreeIps {iface} {accountId} own={targets.map((c) => c.ip)} ifaceIp={addr.ip} ifaceMask={addr.mask} value={start} onPick={(a) => (start = a)} onFound={proposeStart} />
      {/if}
      {#if fill?.almost_full}<span class="note warn">{$_('batch.almostFull', { values: { free: fill.free } })}</span>{/if}
      <label for="o-start">{$_('batch.start')}</label><input id="o-start" type="text" bind:value={start} inputmode="decimal" autocomplete="off" />
    {/if}
    {#if kind !== 'time'}
      {@const ph = kind === 'keep_ip' ? $_('ops.unchanged') : ''}
      <label for="o-mask">{$_('configure.mask')}</label><input id="o-mask" type="text" bind:value={mask} placeholder={ph} oninput={() => (touched.mask = true)} inputmode="decimal" autocomplete="off" />
      <label for="o-gw">{$_('configure.gateway')}</label><input id="o-gw" type="text" bind:value={gateway} placeholder={ph} oninput={() => (touched.gateway = true)} inputmode="decimal" autocomplete="off" />
      <label for="o-dns">{$_('configure.dns')}</label><input id="o-dns" class="m" type="text" bind:value={dns} placeholder={ph} oninput={() => (dnsTouched = true)} autocomplete="off" />
    {:else}
      <label for="o-ntp">{$_('configure.ntp')}</label><input id="o-ntp" class="m" type="text" bind:value={ntp} autocomplete="off" spellcheck="false" />
      <label for="o-tz">{$_('configure.timezone')}</label>
      <select id="o-tz" bind:value={timezone}>{#each zones as z}<option value={z}>{z}</option>{/each}</select>
    {/if}
  </div>
  <div class="scroll ptable list">
    <table>
      <thead>
        <tr>
          <th class="chk"><input type="checkbox" checked={allChecked} onchange={toggleAll} disabled={running} aria-label={$_('network.selectAll')} /></th>
          <th>{$_('ops.col.camera')}</th>
          <th style="width:112px">{$_('ops.col.ip')}</th>
          <th style="width:136px">{$_('network.col.mac')}</th>
          <th style="width:100px">{$_('network.col.addressing')}</th>
        </tr>
      </thead>
      <tbody>
        {#each $cameras as c (cameraKey(c))}
          {@const mac = shownMac(c)}
          <tr>
            <td class="chk"><input type="checkbox" checked={$selection.has(cameraKey(c))} onchange={() => toggle(c)} disabled={running} aria-label={$_('network.select')} /></td>
            <td class="grow" title={cameraName(c)}>{cameraName(c)}</td>
            <td class="m">{c.ip}</td>
            <td class="mac" class:dim-t={!mac.mac}>{mac.mac ?? '—'}</td>
            <td class:dim-t={addressingKey(c).endsWith('.unknown')}>{$_(addressingKey(c))}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if $cameras.length === 0}<div class="none">{$_('ops.noCameras')}</div>{/if}
  </div>
  <div class="foot">
    <span class="sum" class:e={!!error}>{error ? $_(error.key, { values: error.values }) : ''}</span>
    <button class="btn" onclick={runPreview} disabled={!ready}>{#if busy}<span class="spin"></span>{/if}{$_('ops.preview')}</button>
  </div>
</section>

<!-- 2. Aperçu, puis 4. état de chaque caméra pendant et après l'application -->
{#if table}
  <section class="step">
    <h4><b>2</b>{$_('ops.step.preview')}</h4>
    <div class="scroll ptable">
      <table>
        <thead>
          <tr>
            <th>{$_('ops.col.camera')}</th>
            <th>{$_('ops.col.ip')}</th>
            {#if table.kind !== 'time'}
              <th>{$_('ops.col.mask')}</th>
              <th>{$_('ops.col.gateway')}</th>
              <th>{$_('ops.col.dns')}</th>
            {/if}
            <th>{$_('ops.col.state')}</th>
          </tr>
        </thead>
        <tbody>
          {#each table.rows as r, i (r.key)}
            {@const cl = cells(r)}
            {@const st = stateOf(i)}
            <tr class:cur={table.current === i}>
              <td class="grow" title={cameraName(table.cams[i])}>{cameraName(table.cams[i])}</td>
              {#each table.kind === 'time' ? [cl.ip] : [cl.ip, cl.mask, cl.gateway, cl.dns] as c}
                <td class="mono">
                  {#if c.changed}<span class="dim-t">{c.before ?? '?'}</span> → <b>{c.after || '—'}</b>{:else}{c.before ?? ''}{/if}
                </td>
              {/each}
              <td>
                {#each r.conflicts as cf}
                  {@const m = conflictMessage(cf)}
                  <span class="cf" class:bad={isBlocking(cf)} class:warn={!isBlocking(cf)}>{$_(m.key, { values: m.values })}</span>
                {/each}
                {#if st.text}<span class="res {st.cls}">{st.text}</span>{/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if shown && blocked > 0}<p class="err">{$_('ops.blocked', { values: { count: blocked } })}</p>{/if}
  </section>
{/if}

<!-- 3. Confirmer, 4. Appliquer -->
{#if shown && blocked === 0 && shown.data.id}
  <section class="step">
    <h4><b>3</b>{$_('ops.step.confirm')}</h4>
    <div class="confirm">
      <label for="o-typed">{$_('ops.confirm', { values: { count: shown.data.rows.length } })}</label>
      <input id="o-typed" type="text" bind:value={typed} inputmode="numeric" autocomplete="off" />
      <button class="btn def" onclick={apply} disabled={!applyOk}>{$_('ops.apply')}</button>
    </div>
  </section>
{/if}

{#if run}
  <section class="step">
    <h4><b>4</b>{$_('ops.step.apply')}</h4>
    <div class="confirm">
      {#if running}
        <span class="spin"></span>
        <span>{$_('ops.progress', { values: { done: run.results.filter(Boolean).length, total: run.rows.length } })}</span>
        <button class="btn" onclick={stop} disabled={run.stopping}>{$_('ops.stop')}</button>
        {#if run.stopping}<span class="dim-t">{$_('ops.stopping')}</span>{/if}
      {:else if report}
        <span>{$_('ops.report', { values: report })}</span>
        {#if report.skipped > 0}<span class="dim-t">{$_('ops.skipped', { values: { count: report.skipped } })}</span>{/if}
      {/if}
    </div>
  </section>
{/if}

<style>
  /* Étapes l'une sous l'autre, séparées par un filet, à l'alignement de la barre. */
  .step { padding: 20px 24px; border-bottom: 1px solid var(--line); }
  h4 { display: flex; align-items: center; gap: 8px; margin: 0 0 12px; font-size: 15px; font-weight: 500; letter-spacing: -.02em; }
  h4 b {
    display: inline-grid; place-items: center; width: 22px; height: 22px; border-radius: 4px;
    border: 1px solid var(--line-2); background: var(--page); color: var(--text-2);
    font: 500 12px/1 var(--font-mono);
  }
  .seg { margin-bottom: 16px; }
  .form { max-width: 560px; }
  .list { max-height: 260px; overflow-y: auto; }
  .mono { font-size: 13px; white-space: nowrap; }
  .mono b { font-weight: 500; color: var(--cool); }
  .cf { display: block; font-size: 11.5px; }
  .cf.bad { color: var(--err); }
  tr.cur td { background: var(--sel); }
  .confirm { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; font-size: 12.5px; }
  .confirm label { color: var(--text-2); }
  .confirm input { width: 80px; }
  .res { max-width: none; }
</style>

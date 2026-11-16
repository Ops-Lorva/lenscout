<script lang="ts">
  import { onMount } from 'svelte';
  import { _, locale } from 'svelte-i18n';
  import { save as saveFile } from '@tauri-apps/plugin-dialog';
  import { cameraName, shownMac } from '#lib/api/discovery.ts';
  import { errorKey } from '#lib/api/errors.ts';
  import {
    cancelLoginTest, filterLogin, LOGIN_CODES, loginCounts, loginCsvRows, nextLoginRun, startLoginTest,
    type LoginCode, type LoginResult,
  } from '#lib/api/loginTest.ts';
  import { saveReport } from '#lib/api/report.ts';
  import type { Camera } from '#lib/api/types.ts';
  import { csvLang, csvName, toCsv } from '#lib/csv.ts';

  // Résultat du test de login : lancé par le pied d'Opérations (`start`), il
  // garde les caméras du passage, indépendamment de la sélection qui suit.
  let {
    cams,
    accountId,
    accountName = '',
    iface,
    running = $bindable(false),
  }: { cams: Camera[]; accountId: string; accountName?: string; iface: string; running?: boolean } = $props();

  let run = $state<{ id: number; cams: Camera[]; rows: LoginResult[]; done: boolean; cancelled: boolean; stopping: boolean } | null>(null);
  let error = $state('');
  let codes = $state<Set<LoginCode>>(new Set());
  let query = $state('');
  let exported = $state('');

  const rows = $derived(run ? [...run.rows].sort((a, b) => a.index - b.index) : []);
  const counts = $derived(loginCounts(rows));
  const shown = $derived(run ? filterLogin(rows, run.cams, codes, query) : []);

  export async function start() {
    if (running) return;
    const id = nextLoginRun();
    run = { id, cams: [...cams], rows: [], done: false, cancelled: false, stopping: false };
    const r = run;
    error = '';
    exported = '';
    codes = new Set();
    query = '';
    running = true;
    try {
      await startLoginTest(id, r.cams, accountId, iface, (e) => {
        if (e.kind === 'result') {
          const { kind: _k, ...row } = e;
          r.rows.push(row);
        } else {
          r.cancelled = e.cancelled;
        }
      });
    } catch (e) {
      error = `configure.${errorKey(e)}`;
    } finally {
      r.done = true;
      running = false;
    }
  }

  function stop() {
    if (!run || run.done) return;
    run.stopping = true;
    void cancelLoginTest(run.id).catch(() => {});
  }

  function toggleCode(c: LoginCode) {
    const next = new Set(codes);
    if (!next.delete(c)) next.add(c);
    codes = next;
  }

  async function doExport() {
    if (!run) return;
    error = '';
    exported = '';
    try {
      const path = await saveFile({ defaultPath: csvName('login', accountName, new Date()), filters: [{ name: 'CSV', extensions: ['csv'] }] });
      if (!path) return;
      const csv = loginCsvRows(shown, run.cams, (k) => $_(k));
      await saveReport(path, toCsv(csv.header, csv.rows, csvLang($locale)));
      exported = path;
    } catch (e) {
      error = `configure.${errorKey(e)}`;
    }
  }

  const tone = (c: LoginCode) => (c === 'ok' ? 'ok' : c === 'denied' || c === 'other_device' ? 'bad' : 'warn');

  // L'écran reste monté ; s'il part, le passage en cours s'arrête.
  onMount(() => () => {
    if (run && !run.done) void cancelLoginTest(run.id).catch(() => {});
  });
</script>

{#if run || error}
  <section class="step">
    <h4><b>2</b>{$_('ops.kind.login_test')}</h4>
    {#if run}
      <div class="bar">
        {#if !run.done}
          <span class="spin"></span>
          <span class="m">{$_('logintest.progress', { values: { done: run.rows.length, total: run.cams.length } })}</span>
          <button class="btn" onclick={stop} disabled={run.stopping}>{$_('logintest.stop')}</button>
        {:else}
          <span class="m">{$_('logintest.progress', { values: { done: run.rows.length, total: run.cams.length } })}</span>
          {#if run.cancelled}<span class="dim-t">{$_('logintest.stopped')}</span>{/if}
        {/if}
        <span class="grow"></span>
        <input type="search" bind:value={query} placeholder={$_('logintest.search')} aria-label={$_('logintest.search')} spellcheck="false" />
        <button class="btn" onclick={doExport} disabled={!run.done || shown.length === 0}>{$_('logintest.export')}</button>
      </div>
      <div class="tabs">
        <button class="tab" class:on={codes.size === 0} onclick={() => (codes = new Set())}>
          {$_('logintest.all')} <span class="n">{rows.length}</span>
        </button>
        {#each LOGIN_CODES as c (c)}
          {#if counts[c]}
            <button class="tab" class:on={codes.has(c)} onclick={() => toggleCode(c)} aria-pressed={codes.has(c)}>
              <i class="dot {tone(c)}"></i>{$_(`logintest.code.${c}`)} <span class="n">{counts[c]}</span>
            </button>
          {/if}
        {/each}
      </div>
      <div class="scroll ptable list">
        <table>
          <thead>
            <tr>
              <th>{$_('logintest.col.camera')}</th>
              <th style="width:120px">{$_('logintest.col.ip')}</th>
              <th style="width:150px">{$_('logintest.col.mac')}</th>
              <th style="width:170px">{$_('logintest.col.result')}</th>
            </tr>
          </thead>
          <tbody>
            {#each shown as r (r.index)}
              {@const c = run.cams[r.index]}
              {@const mac = c ? shownMac(c).mac : null}
              <tr>
                <td class="grow" title={c ? cameraName(c) : ''}>{c ? cameraName(c) : ''}</td>
                <td class="m">{r.ip}</td>
                <td class="mac" class:dim-t={!mac}>{mac ?? '—'}</td>
                <td><span class="res {tone(r.code)}" title={r.code === 'held' ? $_('logintest.heldTitle') : undefined}>{$_(`logintest.code.${r.code}`)}</span></td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if run.done && shown.length === 0}<div class="none">{$_('logintest.none')}</div>{/if}
      </div>
    {/if}
    {#if error}<p class="err">{$_(error)}</p>{:else if exported}<p class="dim-t note">{$_('logintest.exported')} : <span class="m">{exported}</span></p>{/if}
  </section>
{/if}

<style>
  .step { padding: 20px 24px; border-bottom: 1px solid var(--line); }
  h4 { display: flex; align-items: center; gap: 8px; margin: 0 0 12px; font-size: 15px; font-weight: 500; letter-spacing: -.02em; }
  h4 b {
    display: inline-grid; place-items: center; width: 22px; height: 22px; border-radius: 4px;
    border: 1px solid var(--line-2); background: var(--page); color: var(--text-2);
    font: 500 12px/1 var(--font-mono);
  }
  .bar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; font-size: 13px; }
  .bar .grow { flex: 1; }
  /* Pastilles par résultat, avec leur compte (comme les onglets de Réseau). */
  .tabs { display: flex; flex-wrap: wrap; gap: 2px; margin: 10px 0 8px; }
  .tab { display: inline-flex; align-items: center; gap: 6px; padding: 5px 12px; border: 0; border-radius: 6px; background: none; color: var(--text-2); font: inherit; font-weight: 500; cursor: pointer; }
  .tab:hover { background: var(--hover); color: var(--text); }
  .tab.on { background: var(--sel); color: var(--text); }
  .tab .n { font-variant-numeric: tabular-nums; font-size: 12px; color: var(--text-2); }
  .tab.on .n { color: var(--act); }
  .tab:focus-visible { outline: 2px solid var(--act); outline-offset: 1px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--text-2); }
  .dot.ok { background: var(--ok); }
  .dot.bad { background: var(--err); }
  .dot.warn { background: var(--warn); }
  .list { max-height: 420px; overflow-y: auto; }
  .res { max-width: none; font-size: 12.5px; }
  .res.warn { color: var(--warn); font-weight: 400; }
  .note { margin: 10px 0 0; font-size: 12.5px; }
</style>

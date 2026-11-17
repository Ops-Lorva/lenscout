<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { save as saveFile } from '@tauri-apps/plugin-dialog';
  import { accountFill, type Account, type NetworkFill } from '#lib/api/accounts.ts';
  import { batchErrorMessage, clearResults, defaultTimeZone, resultMessage, setResults, timeZones } from '#lib/api/configure.ts';
  import { interfaceDetails } from '#lib/api/core.ts';
  import { addressingKey, cameraName, shownMac } from '#lib/api/discovery.ts';
  import { errorKey } from '#lib/api/errors.ts';
  import { firstFit, type FreeRange } from '#lib/api/freeIps.ts';
  import { activeAddress, dnsFollowing, INITIAL_PREFILL, joined, prefillFields } from '#lib/api/net.ts';
  import {
    canApply, cells, conflictMessage, credsRequest, credSummarize, isBlocking, isCredResult, movedIps, opRequest, opsClose,
    opsCredsStep, opsFingerprint, opsPreview, opsStep, runSteps, summarize,
    type AnyResult, type CredResult, type OpFields, type OpKind, type OpRequest, type OpRow, type OpsPreview, type StepResult,
  } from '#lib/api/ops.ts';
  import { opsXlsx, xlsxName } from '#lib/api/opsReport.ts';
  import { saveXlsx } from '#lib/api/report.ts';
  import type { Camera } from '#lib/api/types.ts';
  import { cameraKey, cameras, markAddressing, selection } from '#lib/stores/cameras.ts';
  import { opsRequest, scanIface } from '#lib/stores/nav.ts';
  import AccountPicker from './AccountPicker.svelte';
  import FreeIps from './FreeIps.svelte';
  import LoginTest from './LoginTest.svelte';

  // Flux sur une page : choisir (caméras cochées, partagées avec Réseau, et
  // l'opération), aperçu calculé par Rust, confirmation par le nombre de
  // caméras tapé, application caméra par caméra avec Arrêter, puis rapport.
  // « Test de login » n'écrit rien : ni aperçu ni confirmation, son résultat
  // est rendu par `LoginTest` (api/ops.ts ne le connaît pas).
  type Kind = OpKind | 'login_test';
  const KINDS: Kind[] = ['keep_ip', 'renumber', 'time', 'change_credentials', 'login_test'];
  const zones = timeZones();

  let kind = $state<Kind>('keep_ip');
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

  // « Changer les identifiants » : le nouvel identifiant visé EST celui du
  // compte sélectionné (Rust le lit) ; ici on ne saisit que les couples
  // actuels à essayer. Ces mots de passe ne vivent qu'ici, en mémoire : jamais
  // enregistrés, effacés à la fin et en quittant l'écran. `credsVersion`
  // invalide l'aperçu dès qu'un champ change, sans mettre de secret dans
  // l'empreinte.
  let pairs = $state<{ login: string; password: string }[]>([]);
  let revealPairs = $state(false);
  let credsVersion = $state(0);
  const bump = () => (credsVersion += 1);
  const addPair = () => (pairs = [...pairs, { login: '', password: '' }]);
  const removePair = (i: number) => { pairs = pairs.filter((_, j) => j !== i); bump(); };
  function clearCredentials() {
    pairs = [];
    revealPairs = false;
    bump();
  }

  const iface = $derived($scanIface);
  // Ordre affiché de Réseau (IP croissante) : celui du plan.
  const targets = $derived($cameras.filter((c) => $selection.has(cameraKey(c))));
  const others = $derived($cameras.filter((c) => !$selection.has(cameraKey(c))));
  const fields = $derived<OpFields>({ kind: kind as OpKind, start, mask, gateway, dns, ntp, timezone });
  // Test de login en cours : la sélection et le choix d'opération restent figés.
  let testing = $state(false);
  let loginTest = $state<ReturnType<typeof LoginTest> | null>(null);
  const fingerprint = $derived(opsFingerprint(targets, fields, iface, accountId, kind === 'change_credentials' ? String(credsVersion) : ''));

  // L'aperçu garde l'empreinte de ce qui l'a produit et les caméras visées.
  let preview = $state<{ data: OpsPreview; fingerprint: string; cams: Camera[]; kind: OpKind } | null>(null);
  const shown = $derived(preview && preview.fingerprint === fingerprint ? preview : null);
  const blocked = $derived(shown ? shown.data.rows.filter((r) => r.conflicts.some(isBlocking)).length : 0);

  // Une application en cours ou finie : figée, un rescan de Réseau ne la retire pas.
  // `account` et `at` : ce que le rapport Excel en dira (le compte peut changer ensuite).
  let run = $state<{
    id: string; rows: OpRow[]; cams: Camera[]; kind: OpKind; results: (AnyResult | undefined)[]; current: number; stopping: boolean; done: boolean;
    account: { name: string; login: string }; at: Date;
  } | null>(null);
  let exported = $state('');
  let exportError = $state('');
  let stopFlag = false;
  // Confirmation en deux clics (comme Supprimer dans Comptes) : le premier clic
  // arme, le second applique.
  let confirming = $state(false);
  const running = $derived(!!run && !run.done);
  const locked = $derived(running || testing);
  const table = $derived(run ?? (shown ? { rows: shown.data.rows, cams: shown.cams, kind: shown.kind, results: [] as (AnyResult | undefined)[], current: -1 } : null));
  const report = $derived(
    !run?.done ? null : run.kind === 'change_credentials' ? credSummarize(run.results as (CredResult | undefined)[], run.rows.length) : summarize(run.results as (StepResult | undefined)[], run.rows.length),
  );
  const applyOk = $derived(canApply(shown?.data ?? null, running));
  // Colonnes réseau seulement pour « garder les IP » et « renuméroter ».
  const hasNetCols = (k: Kind) => k === 'keep_ip' || k === 'renumber';

  // Raccourci de Réseau (« IP en lot ») : l'opération demandée, la sélection est déjà partagée.
  $effect(() => {
    const req = $opsRequest;
    if (!req) return;
    untrack(() => {
      if (!locked) {
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

  function choose(k: Kind) {
    if (locked) return;
    kind = k;
    run = null;
    error = null;
    confirming = false;
    // Les champs d'une opération ne valent pas pour l'autre : vide = inchangé, pour garder les IP.
    start = mask = gateway = dns = '';
    touched.mask = touched.gateway = false;
    dnsTouched = false;
    // Les identifiants ne traînent pas d'une opération à l'autre.
    clearCredentials();
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
    confirming = false;
    const fp = fingerprint;
    const cams = targets;
    const k = kind as OpKind;
    // Les secrets partent à part : l'aperçu n'essaie rien, mais le plan gardé
    // par Rust doit recevoir le nouvel identifiant et les couples à essayer.
    const req: OpRequest = k === 'change_credentials' ? credsRequest(pairs) : (opRequest(fields) as OpRequest);
    try {
      const data = await opsPreview(cams, others, req, iface, accountId);
      preview = { data, fingerprint: fp, cams, kind: k };
    } catch (e) {
      error = batchErrorMessage(e);
    } finally {
      busy = false;
    }
  }

  // Deux clics : le premier arme, le second applique.
  function confirmApply() {
    if (!applyOk) return;
    if (!confirming) {
      confirming = true;
      return;
    }
    confirming = false;
    void apply();
  }

  async function apply() {
    if (!shown?.data.id || !applyOk) return;
    const id = shown.data.id;
    const forAccount = accountId;
    const via = iface;
    const k = shown.kind;
    run = {
      id, rows: shown.data.rows, cams: shown.cams, kind: k, results: [], current: -1, stopping: false, done: false,
      account: { name: account?.name ?? '', login: account?.login ?? '' }, at: new Date(),
    };
    exported = exportError = '';
    preview = null;
    error = null;
    stopFlag = false;
    const r = run;
    const step = (i: number): Promise<AnyResult> =>
      k === 'change_credentials' ? opsCredsStep(id, i, forAccount, via) : opsStep(id, i, forAccount, via);
    try {
      await runSteps(
        r.rows.length,
        (i) => {
          r.current = i;
          return step(i);
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

  // Pastilles de Réseau, adressage posé, mémoire du compte (Rust) ; puis rescan
  // de Réseau. « Changer les identifiants » ne touche pas l'adressage ; ses
  // mots de passe sont effacés à la fin.
  function finish(r: NonNullable<typeof run>) {
    if (r.kind === 'change_credentials') {
      clearCredentials();
      return;
    }
    const done = r.results.filter((x): x is StepResult => !!x && !isCredResult(x));
    clearResults();
    setResults(done);
    // L'adressage posé se voit sur place ; pas de rescan automatique (le
    // technicien rafraîchit avec le bouton Rescanner de Réseau).
    if (r.kind !== 'time' && done.some((x) => x.ok)) {
      markAddressing(done, 'static', movedIps(r.rows, r.results as (StepResult | undefined)[]));
    }
  }

  async function doExport() {
    if (!run?.done) return;
    const r = run;
    exported = exportError = '';
    try {
      const path = await saveFile({ defaultPath: xlsxName(r.account.name, r.at), filters: [{ name: 'Excel', extensions: ['xlsx'] }] });
      if (!path) return;
      exported = await saveXlsx(path, opsXlsx(r, r.account, (k, v) => $_(k, { values: v })));
    } catch (e) {
      exportError = `configure.${errorKey(e)}`;
    }
  }

  function stop() {
    stopFlag = true;
    if (run) run.stopping = true;
  }

  function stateOf(i: number, r: OpRow): { text: string; cls: string } {
    const res = table?.results[i];
    if (!res) {
      if (table?.current === i) return { text: $_('ops.state.running'), cls: '' };
      // Avant l'application, « changer les identifiants » annonce son intention.
      if (table?.kind === 'change_credentials' && !r.conflicts.some(isBlocking)) return { text: $_('ops.cred.toTry'), cls: 'dim-t' };
      return { text: '', cls: '' };
    }
    if (isCredResult(res)) return credState(res);
    if (!res.ok) {
      const m = resultMessage(res);
      return { text: m ? $_(m.key, { values: m.values }) : '', cls: 'bad' };
    }
    return res.reachable === false ? { text: $_('ops.state.unreachable'), cls: 'warn' } : { text: $_('ops.state.ok'), cls: 'ok' };
  }

  // Sortie d'une caméra pour « changer les identifiants ». Le rapport ne montre
  // que l'utilisateur qui a marché, jamais le mot de passe.
  function credState(res: CredResult): { text: string; cls: string } {
    switch (res.code) {
      case 'posed': return { text: $_('ops.cred.posed', { values: { login: res.login } }), cls: 'ok' };
      case 'already_up_to_date': return { text: $_('ops.cred.already'), cls: 'ok' };
      case 'no_credential': return { text: $_('ops.cred.none'), cls: 'bad' };
      case 'stopped_by_guard': return { text: $_('ops.cred.stopped'), cls: 'warn' };
      case 'unsupported': return { text: $_('ops.conflict.unsupported'), cls: 'bad' };
      case 'unreachable': return { text: $_('ops.cred.unreachable'), cls: 'bad' };
      case 'rejected': return { text: res.detail, cls: 'bad' };
    }
  }

  // « Changer les identifiants » : rien d'autre à exiger que le compte (il
  // porte le nouvel identifiant) et des caméras cochées.
  const ready = $derived(
    !busy && !running && !!iface && !!accountId && targets.length > 0 &&
      (kind === 'renumber' ? start.trim() !== '' && mask.trim() !== '' : true),
  );

  onMount(() => () => {
    // L'écran reste monté ; si jamais il part, plus rien ne doit suivre, et les
    // mots de passe essayés ne restent pas en mémoire.
    stopFlag = true;
    clearCredentials();
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
      <label><input type="radio" name="op-kind" value={k} checked={kind === k} disabled={locked} onchange={() => choose(k)} /><span>{$_(`ops.kind.${k}`)}</span></label>
    {/each}
  </div>
  <div class="form">
    <label for="o-account">{$_('accounts.picker')}</label><AccountPicker id="o-account" bind:accountId bind:account />
    {#if kind === 'renumber'}
      {#if iface}
        <FreeIps tab="operations" {iface} {accountId} own={targets.map((c) => c.ip)} ifaceIp={addr.ip} ifaceMask={addr.mask} value={start} onPick={(a) => (start = a)} onFound={proposeStart} />
      {/if}
      {#if fill?.almost_full}<span class="note warn">{$_('batch.almostFull', { values: { free: fill.free } })}</span>{/if}
      <label for="o-start">{$_('batch.start')}</label><input id="o-start" type="text" bind:value={start} inputmode="decimal" autocomplete="off" />
    {/if}
    {#if hasNetCols(kind)}
      {@const ph = kind === 'keep_ip' ? $_('ops.unchanged') : ''}
      <label for="o-mask">{$_('configure.mask')}</label><input id="o-mask" type="text" bind:value={mask} placeholder={ph} oninput={() => (touched.mask = true)} inputmode="decimal" autocomplete="off" />
      <label for="o-gw">{$_('configure.gateway')}</label><input id="o-gw" type="text" bind:value={gateway} placeholder={ph} oninput={() => (touched.gateway = true)} inputmode="decimal" autocomplete="off" />
      <label for="o-dns">{$_('configure.dns')}</label><input id="o-dns" class="m" type="text" bind:value={dns} placeholder={ph} oninput={() => (dnsTouched = true)} autocomplete="off" />
    {:else if kind === 'time'}
      <label for="o-ntp">{$_('configure.ntp')}</label><input id="o-ntp" class="m" type="text" bind:value={ntp} autocomplete="off" spellcheck="false" />
      <label for="o-tz">{$_('configure.timezone')}</label>
      <select id="o-tz" bind:value={timezone}>{#each zones as z}<option value={z}>{z}</option>{/each}</select>
    {:else if kind === 'change_credentials'}
      <span class="note">{$_('ops.cred.fromAccount')}</span>
      <span class="note">{$_('ops.cred.tryHint')}</span>
      <div class="pairs">
        {#each pairs as p, i (i)}
          <div class="pair">
            <input type="text" placeholder={$_('ops.cred.login')} bind:value={p.login} oninput={bump} autocomplete="off" spellcheck="false" />
            <span class="pw">
              <input type={revealPairs ? 'text' : 'password'} placeholder={$_('ops.cred.password')} bind:value={p.password} oninput={bump} autocomplete="off" />
              <button class="eye" type="button" onclick={() => (revealPairs = !revealPairs)}
                aria-label={$_(revealPairs ? 'accounts.hidePassword' : 'accounts.showPassword')} aria-pressed={revealPairs}>
                <svg viewBox="0 0 16 16" aria-hidden="true">
                  <path d="M1.5 8S4 3.5 8 3.5 14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8z" />
                  <circle cx="8" cy="8" r="2" />
                  {#if revealPairs}<path d="M2.5 13.5l11-11" />{/if}
                </svg>
              </button>
            </span>
            <button class="mini" type="button" onclick={() => removePair(i)}>{$_('ops.cred.removePair')}</button>
          </div>
        {/each}
        <button class="mini" type="button" onclick={addPair}>{$_('ops.cred.addPair')}</button>
      </div>
    {/if}
  </div>
  <div class="scroll ptable list">
    <table>
      <thead>
        <tr>
          <th class="chk"><input type="checkbox" checked={allChecked} onchange={toggleAll} disabled={locked} aria-label={$_('network.selectAll')} /></th>
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
            <td class="chk"><input type="checkbox" checked={$selection.has(cameraKey(c))} onchange={() => toggle(c)} disabled={locked} aria-label={$_('network.select')} /></td>
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
    {#if kind === 'login_test'}
      <button class="btn" onclick={() => loginTest?.start()} disabled={!ready || testing}>{#if testing}<span class="spin"></span>{/if}{$_('logintest.test')}</button>
    {:else}
      <button class="btn" onclick={runPreview} disabled={!ready}>{#if busy}<span class="spin"></span>{/if}{$_('ops.preview')}</button>
    {/if}
  </div>
</section>

{#if kind === 'login_test'}
  <LoginTest bind:this={loginTest} cams={targets} {accountId} accountName={account?.name ?? ''} {iface} bind:running={testing} />
{/if}

<!-- 2. Aperçu, puis 4. état de chaque caméra pendant et après l'application -->
{#if table && kind !== 'login_test'}
  <section class="step">
    <h4><b>2</b>{$_('ops.step.preview')}</h4>
    <div class="scroll ptable">
      <table>
        <thead>
          <tr>
            <th>{$_('ops.col.camera')}</th>
            <th>{$_('ops.col.ip')}</th>
            {#if hasNetCols(table.kind)}
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
            {@const st = stateOf(i, r)}
            <tr class:cur={table.current === i}>
              <td class="grow" title={cameraName(table.cams[i])}>{cameraName(table.cams[i])}</td>
              {#each hasNetCols(table.kind) ? [cl.ip, cl.mask, cl.gateway, cl.dns] : [cl.ip] as c}
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
      <span>{$_('ops.willApply', { values: { count: shown.data.rows.length } })}</span>
      <button class="btn def" class:danger={confirming} onclick={confirmApply} disabled={!applyOk}>
        {confirming ? $_('ops.confirmApply') : $_('ops.apply')}
      </button>
      {#if confirming}<span class="dim-t">{$_('ops.confirmHint')}</span>{/if}
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
        {#if run.kind === 'change_credentials'}
          <span>{$_('ops.credReport', { values: report })}</span>
        {:else}
          <span>{$_('ops.report', { values: report })}</span>
        {/if}
        {#if report.skipped > 0}<span class="dim-t">{$_('ops.skipped', { values: { count: report.skipped } })}</span>{/if}
        <button class="btn" onclick={doExport}>{$_('ops.xlsx.export')}</button>
      {/if}
    </div>
    {#if exportError}<p class="err">{$_(exportError)}</p>{:else if exported}<p class="dim-t note">{$_('ops.xlsx.exported')} : <span class="m">{exported}</span></p>{/if}
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
  .res { max-width: none; }
  /* Couples à essayer : une liste en colonne 2 du formulaire. */
  .pairs { grid-column: 2; display: flex; flex-direction: column; gap: 6px; align-items: flex-start; }
  .pair { display: flex; gap: 8px; width: 100%; }
  .pair > input { flex: 1; }
  .pair .pw { position: relative; flex: 1; display: block; }
  .pair .pw input { width: 100%; padding-right: 30px; }
  .eye {
    position: absolute; right: 3px; top: 50%; transform: translateY(-50%);
    width: 24px; height: 22px; padding: 0; border: 0; border-radius: 5px;
    background: transparent; color: var(--text-2); cursor: pointer;
    display: inline-flex; align-items: center; justify-content: center;
  }
  .eye:hover { color: var(--text); }
  .eye:focus-visible { outline: 2px solid var(--act); outline-offset: 1px; }
  .eye svg { width: 16px; height: 16px; fill: none; stroke: currentColor; stroke-width: 1.3; stroke-linecap: round; stroke-linejoin: round; }
</style>

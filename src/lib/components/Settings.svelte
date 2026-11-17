<script lang="ts">
  import { onMount } from 'svelte';
  import { _, locale } from 'svelte-i18n';
  import { getVersion } from '@tauri-apps/api/app';
  import { debugGet, debugSet } from '#lib/api/core.ts';
  import { errorKey } from '#lib/api/errors.ts';
  import { LANGS, setLang, type Lang } from '#lib/i18n/index.ts';
  import { setTheme, theme, THEMES } from '#lib/stores/settings.ts';
  import { applyUpdate, checkUpdate, type UpdateInfo } from '#lib/api/update.ts';

  let version = $state('');
  let debug = $state(false);
  let error = $state('');

  const onLang = (e: Event) => setLang((e.currentTarget as HTMLSelectElement).value as Lang);

  async function onDebug(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const on = input.checked;
    error = '';
    try {
      await debugSet(on);
      debug = on;
    } catch (e) {
      // La case revient à l'état réel : `debug` n'a pas changé, Svelte ne
      // retoucherait pas le DOM, donc on remet la case à la main.
      input.checked = debug;
      error = `settings.${errorKey(e)}`;
    }
  }

  // Recherche à la demande, sans tenir compte d'une version écartée du bandeau.
  let upd = $state<UpdateInfo | null>(null);
  let updState = $state<'' | 'checking' | 'installing' | 'unreachable' | 'failed'>('');
  async function check() {
    updState = 'checking';
    upd = null;
    try {
      upd = await checkUpdate();
      updState = '';
    } catch {
      updState = 'unreachable';
    }
  }
  async function install() {
    if (!upd?.asset_url || !upd.asset_name) return;
    updState = 'installing';
    try {
      // L'installeur est lancé ; c'est lui qui fermera l'application.
      await applyUpdate(upd.asset_url, upd.asset_name);
      updState = '';
    } catch {
      updState = 'failed';
    }
  }

  onMount(async () => {
    try { version = await getVersion(); } catch {}
    try { debug = await debugGet(); } catch {}
  });
</script>

<div class="tools bar"><span class="title">{$_('common.nav.settings')}</span></div>

<div class="settings">
  <span class="k">{$_('settings.theme')}</span>
  <div>
    <div class="seg" role="radiogroup" aria-label={$_('settings.theme')}>
      {#each THEMES as t}
        <label><input type="radio" name="theme" value={t} checked={$theme === t} onchange={() => setTheme(t)} /><span>{$_(`settings.${t}`)}</span></label>
      {/each}
    </div>
  </div>

  <span class="k">{$_('settings.language')}</span>
  <div>
    <select value={$locale?.slice(0, 2)} onchange={onLang} aria-label={$_('settings.language')}>
      {#each LANGS as l}<option value={l}>{$_(`common.lang.${l}`)}</option>{/each}
    </select>
  </div>

  <span class="k">{$_('settings.diag')}</span>
  <div>
    <label><input type="checkbox" checked={debug} onchange={onDebug} /> <span>{$_('settings.diaglog')}</span></label>
    <div class="n">{$_('settings.diagNote')}</div>
    {#if error}<div class="n err">{$_(error)}</div>{/if}
  </div>

  <span class="k">{$_('settings.version')}</span>
  <div class="upd">
    <span class="v m">{version || '—'}</span>
    {#if upd?.has_update && upd.latest_version}
      <span>{$_('update.available')} <strong>v{upd.latest_version}</strong></span>
      {#if upd.asset_url}
        <button class="btn def" onclick={install} disabled={updState === 'installing'}>
          {#if updState === 'installing'}<span class="spin"></span>{/if}{updState === 'installing' ? $_('update.installing') : $_('update.install')}
        </button>
      {:else if upd.release_notes_url}
        <a class="btn def" href={upd.release_notes_url} target="_blank" rel="noopener noreferrer">{$_('update.view')}</a>
      {/if}
    {:else}
      <button class="btn" onclick={check} disabled={updState === 'checking'}>
        {#if updState === 'checking'}<span class="spin"></span>{/if}{updState === 'checking' ? $_('update.checking') : $_('update.check')}
      </button>
      {#if upd && !upd.has_update}<span class="n">{$_('update.uptodate')}</span>{/if}
    {/if}
    {#if updState === 'unreachable' || updState === 'failed'}<span class="n err">{$_(`update.${updState}`)}</span>{/if}
  </div>
</div>

<style>
  .n.err { margin-top: 4px; }
  .upd { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .upd .n { margin: 0; }
  a.btn { text-decoration: none; }
</style>

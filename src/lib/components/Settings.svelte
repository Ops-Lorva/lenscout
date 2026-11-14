<script lang="ts">
  import { onMount } from 'svelte';
  import { _, locale } from 'svelte-i18n';
  import { getVersion } from '@tauri-apps/api/app';
  import { debugGet, debugSet } from '$lib/api/core';
  import { errorKey } from '$lib/api/errors';
  import { LANGS, setLang, type Lang } from '$lib/i18n';
  import { setTheme, theme, THEMES } from '$lib/stores/settings';

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

  onMount(async () => {
    try { version = await getVersion(); } catch {}
    try { debug = await debugGet(); } catch {}
  });
</script>

<div class="tools"><span class="title">{$_('common.nav.settings')}</span></div>

<div class="settings">
  <span class="k">{$_('settings.theme')}</span>
  <div class="seg" role="radiogroup" aria-label={$_('settings.theme')}>
    {#each THEMES as t}
      <label><input type="radio" name="theme" value={t} checked={$theme === t} onchange={() => setTheme(t)} /><span>{$_(`settings.${t}`)}</span></label>
    {/each}
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
  <div class="v">{version || '—'}</div>
</div>

<style>
  .n.err { margin-top: 4px; }
</style>

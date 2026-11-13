<script lang="ts">
  import { onMount } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { applyUpdate, checkUpdate, DISMISS_KEY, shouldShow, type UpdateInfo } from '$lib/api/update';

  let info = $state<UpdateInfo | null>(null);
  let installing = $state(false);
  let failed = $state(false);

  onMount(async () => {
    try {
      const u = await checkUpdate();
      let dismissed: string | null = null;
      try { dismissed = localStorage.getItem(DISMISS_KEY); } catch {}
      if (shouldShow(u, dismissed)) info = u;
    } catch {
      // Hors ligne ou GitHub injoignable : pas de bandeau, pas de bruit.
    }
  });

  function dismiss() {
    if (info?.latest_version) {
      try { localStorage.setItem(DISMISS_KEY, info.latest_version); } catch {}
    }
    info = null;
  }

  async function install() {
    if (!info?.asset_url || !info.asset_name) return;
    installing = true;
    failed = false;
    try {
      // L'installeur est lancé ; c'est lui qui fermera l'application.
      await applyUpdate(info.asset_url, info.asset_name);
    } catch {
      failed = true;
    }
    installing = false;
  }
</script>

{#if info}
  <div class="banner" role="status">
    <span class="text">
      {$_('update.available')} <strong>v{info.latest_version}</strong>
      {#if failed}<span class="err"> · {$_('update.failed')}</span>{/if}
    </span>
    {#if info.asset_url}
      <button class="install" onclick={install} disabled={installing}>
        {installing ? $_('update.installing') : $_('update.install')}
      </button>
    {:else if info.release_notes_url}
      <a class="link" href={info.release_notes_url} target="_blank" rel="noopener noreferrer">{$_('update.view')}</a>
    {/if}
    <button class="dismiss" onclick={dismiss} title={$_('update.dismiss')} aria-label={$_('update.dismiss')} disabled={installing}>✕</button>
  </div>
{/if}

<style>
  .banner { display: flex; align-items: center; gap: 10px; padding: 8px 16px; background: var(--ep-accent); color: #fff; font-size: 13px; flex-shrink: 0; }
  .text { flex: 1; }
  .err { opacity: 0.9; }
  .link { color: #fff; font-weight: 700; text-decoration: underline; white-space: nowrap; }
  .install { background: rgba(255,255,255,0.18); border: 1px solid rgba(255,255,255,0.4); color: #fff; font-weight: 600; padding: 4px 12px; border-radius: 4px; cursor: pointer; white-space: nowrap; }
  .install:hover:not(:disabled) { background: rgba(255,255,255,0.28); }
  .install:disabled { opacity: 0.7; cursor: wait; }
  .dismiss { background: transparent; border: none; color: rgba(255,255,255,0.8); cursor: pointer; font-size: 14px; padding: 2px 6px; border-radius: 4px; }
  .dismiss:hover:not(:disabled) { background: rgba(255,255,255,0.2); }
</style>

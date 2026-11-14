<script lang="ts">
  import { onMount } from 'svelte';
  import { _ } from 'svelte-i18n';
  import { applyUpdate, checkUpdate, DISMISS_KEY, shouldShow, type UpdateInfo } from '#lib/api/update.ts';

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

<!-- Bande plate sous la barre de titre, dans le gris de la barre latérale. -->
{#if info}
  <div class="update" role="status">
    <span class="t">
      {$_('update.available')} <strong>v{info.latest_version}</strong>
      {#if failed}<span class="fail">{$_('update.failed')}</span>{/if}
    </span>
    {#if info.asset_url}
      <button class="btn def" onclick={install} disabled={installing}>
        {#if installing}<span class="spin"></span>{/if}{installing ? $_('update.installing') : $_('update.install')}
      </button>
    {:else if info.release_notes_url}
      <a class="btn def" href={info.release_notes_url} target="_blank" rel="noopener noreferrer">{$_('update.view')}</a>
    {/if}
    <button class="btn" onclick={dismiss} disabled={installing}>{$_('update.dismiss')}</button>
  </div>
{/if}

<style>
  .update {
    display: flex; align-items: center; gap: 10px; padding: 6px 16px; flex-shrink: 0;
    border-bottom: 1px solid var(--line); background: var(--side); font-size: 12.5px;
  }
  .t { flex: 1; }
  .fail { color: var(--err); margin-left: 6px; }
  a.btn { text-decoration: none; }
</style>

<script lang="ts">
  import { _, locale } from 'svelte-i18n';
  import { LANGS, setLang, type Lang } from '$lib/i18n';
  import { page, type Page } from '$lib/stores/nav';

  // Icônes Lucide 16×16, trait `currentColor`, comme celles de LanProbe.
  const items: { id: Page; key: string; paths: string[] }[] = [
    { id: 'network',  key: 'common.nav.network',  paths: ['M8 2a6 6 0 100 12A6 6 0 008 2z', 'M2 8h12', 'M8 2c2 2 2 10 0 12M8 2c-2 2-2 10 0 12'] },
    { id: 'framing',  key: 'common.nav.framing',  paths: ['M2 5.5A1.5 1.5 0 013.5 4h9A1.5 1.5 0 0114 5.5v5a1.5 1.5 0 01-1.5 1.5h-9A1.5 1.5 0 012 10.5v-5z', 'M8 6.5a1.5 1.5 0 100 3 1.5 1.5 0 000-3z'] },
    { id: 'accounts', key: 'common.nav.accounts', paths: ['M10 5a2 2 0 11-4 0 2 2 0 014 0z', 'M3 14c0-2.5 2.2-4 5-4s5 1.5 5 4'] },
  ];

  const onLang = (e: Event) => setLang((e.currentTarget as HTMLSelectElement).value as Lang);
</script>

<nav class="sidebar">
  <div class="logo">Lenscout</div>

  <div class="nav-main">
    {#each items as item}
      <button
        class="nav-item"
        class:active={$page === item.id}
        onclick={() => page.set(item.id)}
        title={$_(item.key)}
      >
        <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          {#each item.paths as d}<path {d} />{/each}
        </svg>
        <span class="nav-label">{$_(item.key)}</span>
      </button>
    {/each}
  </div>

  <div class="nav-bottom">
    <select class="lang" value={$locale?.slice(0, 2)} onchange={onLang}>
      {#each LANGS as l}
        <option value={l}>{$_(`common.lang.${l}`)}</option>
      {/each}
    </select>
  </div>
</nav>

<style>
  .sidebar {
    width: 168px;
    height: 100vh;
    background: var(--ep-glass-bg);
    border-right: 1px solid var(--ep-glass-border);
    display: flex;
    flex-direction: column;
    padding: 10px 8px;
    flex-shrink: 0;
    gap: 2px;
  }
  .logo {
    font-size: 12px;
    font-weight: 800;
    color: var(--ep-text-primary);
    letter-spacing: .4px;
    padding: 6px 8px 14px;
    border-bottom: 1px solid var(--ep-glass-border);
    margin-bottom: 6px;
  }
  .nav-main { flex: 1; display: flex; flex-direction: column; gap: 2px; }
  .nav-bottom { padding-top: 8px; border-top: 1px solid var(--ep-glass-border); }
  .nav-item {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 8px 10px;
    border: none;
    background: transparent;
    border-radius: var(--ep-radius-md);
    color: var(--ep-text-secondary);
    cursor: pointer;
    font-size: 12.5px;
    font-weight: 500;
    text-align: left;
    transition: background 0.12s, color 0.12s;
  }
  .nav-item:hover { background: var(--ep-glass-bg-md); color: var(--ep-text-primary); }
  .nav-item.active {
    background: var(--ep-accent-dim);
    border: 1px solid var(--ep-accent-glow);
    color: var(--ep-accent-bright);
    font-weight: 600;
  }
  .nav-label { flex: 1; }
  .lang {
    width: 100%;
    padding: 6px 8px;
    background: var(--ep-glass-bg-md);
    border: 1px solid var(--ep-glass-border);
    border-radius: var(--ep-radius-md);
    color: var(--ep-text-primary);
    font-size: 12px;
  }
</style>

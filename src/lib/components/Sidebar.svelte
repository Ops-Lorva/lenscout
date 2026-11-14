<script lang="ts">
  import { _ } from 'svelte-i18n';
  import { page, type Page } from '$lib/stores/nav';

  // Icônes de ligne 16×16 de la maquette, trait `currentColor`.
  const items: { id: Page; key: string; paths: string[] }[] = [
    { id: 'network',  key: 'common.nav.network',  paths: ['M8 2a6 6 0 100 12A6 6 0 008 2z', 'M2 8h12', 'M8 2c2 2 2 10 0 12M8 2c-2 2-2 10 0 12'] },
    { id: 'framing',  key: 'common.nav.framing',  paths: ['M2 5.5A1.5 1.5 0 013.5 4h9A1.5 1.5 0 0114 5.5v5a1.5 1.5 0 01-1.5 1.5h-9A1.5 1.5 0 012 10.5v-5z', 'M8 6.5a1.5 1.5 0 100 3 1.5 1.5 0 000-3z'] },
    { id: 'accounts', key: 'common.nav.accounts', paths: ['M10 5a2 2 0 11-4 0 2 2 0 014 0z', 'M3 14c0-2.5 2.2-4 5-4s5 1.5 5 4'] },
    { id: 'settings', key: 'common.nav.settings', paths: ['M2 4.5h2.5M8.5 4.5H14', 'M2 11.5h5.5M11.5 11.5H14', 'M6.5 2.5a2 2 0 100 4 2 2 0 000-4z', 'M9.5 9.5a2 2 0 100 4 2 2 0 000-4z'] },
  ];
</script>

<nav class="sidebar">
  {#each items as item}
    <button class="item" class:on={$page === item.id} onclick={() => page.set(item.id)} aria-current={$page === item.id ? 'page' : undefined}>
      <svg class="ic" viewBox="0 0 16 16" aria-hidden="true">
        {#each item.paths as d}<path {d} />{/each}
      </svg>
      <span>{$_(item.key)}</span>
    </button>
  {/each}
</nav>

<style>
  .sidebar {
    width: 160px; flex: none;
    background: var(--side); border-right: 1px solid var(--line);
    padding: 12px 10px; display: flex; flex-direction: column; gap: 2px;
  }
  .item {
    display: flex; align-items: center; gap: 9px; height: 30px; padding: 0 10px;
    border: 0; border-radius: 7px; background: transparent; color: var(--text);
    font: inherit; font-size: 13px; text-align: left; cursor: pointer;
  }
  .item svg { color: var(--text-2); }
  .item:hover { background: var(--hover); }
  .item.on { background: var(--sel); font-weight: 500; }
  .item.on svg { color: var(--act); }
</style>

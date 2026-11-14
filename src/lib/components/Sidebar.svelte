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

{#snippet entry(item: (typeof items)[number])}
  <button class="item" class:on={$page === item.id} onclick={() => page.set(item.id)} aria-current={$page === item.id ? 'page' : undefined}>
    <svg class="ic" viewBox="0 0 16 16" aria-hidden="true">
      {#each item.paths as d}<path {d} />{/each}
    </svg>
    <span>{$_(item.key)}</span>
  </button>
{/snippet}

<!-- Réglages en pied de barre, séparé des onglets (comme macOS / VS Code). -->
<nav class="sidebar">
  <!-- Logo D3 « Repère » (docs/logo) : cône en currentColor, point en couleur d'action → suit le thème. -->
  <div class="brand">
    <svg class="logo" viewBox="222 286 516 516" aria-hidden="true">
      <defs><clipPath id="sb-logo-gap"><path clip-rule="evenodd" d="M 0 0 H 1024 V 1024 H 0 Z M 168 692 a 164 164 0 1 0 328 0 a 164 164 0 1 0 -328 0 Z" /></clipPath></defs>
      <g clip-path="url(#sb-logo-gap)"><path d="M 332 692 L 345.1 316.2 A 376 376 0 0 1 707.8 678.9 Z" fill="currentColor" stroke="currentColor" stroke-width="48" stroke-linejoin="round" /></g>
      <circle cx="332" cy="692" r="104" fill="var(--act)" />
    </svg>
    <span>LenScout</span>
  </div>
  {#each items.filter((i) => i.id !== 'settings') as item}{@render entry(item)}{/each}
  <div class="bottom">
    {#each items.filter((i) => i.id === 'settings') as item}{@render entry(item)}{/each}
  </div>
</nav>

<style>
  .sidebar {
    width: 160px; flex: none;
    background: var(--side); border-right: 1px solid var(--line);
    padding: 12px 10px; display: flex; flex-direction: column; gap: 2px;
  }
  .brand { display: flex; align-items: center; gap: 9px; height: 30px; padding: 0 10px; margin-bottom: 8px; font-size: 13px; font-weight: 600; color: var(--text); }
  .logo { width: 20px; height: 20px; flex: none; color: var(--text-2); }
  .bottom { margin-top: auto; padding-top: 8px; border-top: 1px solid var(--line); display: flex; flex-direction: column; }
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

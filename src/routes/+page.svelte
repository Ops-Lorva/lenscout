<script lang="ts">
  import Sidebar from '#lib/components/Sidebar.svelte';
  import Network from '#lib/components/Network.svelte';
  import Framing from '#lib/components/Framing.svelte';
  import Accounts from '#lib/components/Accounts.svelte';
  import Settings from '#lib/components/Settings.svelte';
  import UpdateBanner from '#lib/components/UpdateBanner.svelte';
  import { page, status } from '#lib/stores/nav.ts';
  import { _ } from 'svelte-i18n';
</script>

<div class="app">
  <UpdateBanner />
  <div class="body">
    <Sidebar />
    <!-- Les quatre écrans restent montés, un seul visible : changer d'onglet ne
         perd ni le scan, ni le filtre, ni les coches, ni une feuille ouverte. -->
    <main class="pane">
      <section class="page" hidden={$page !== 'network'}><Network /></section>
      <section class="page" hidden={$page !== 'framing'}><Framing /></section>
      <section class="page" hidden={$page !== 'accounts'}><Accounts /></section>
      <section class="page" hidden={$page !== 'settings'}><Settings /></section>
    </main>
  </div>
  {#if $status}
    <div class="status" role="status">
      {#if $status.tone || $status.detail}<b class={$status.tone}>{$_($status.text.key, { values: $status.text.values })}</b>{:else}{$_($status.text.key, { values: $status.text.values })}{/if}{#if $status.detail}{' '}{$_($status.detail.key, { values: $status.detail.values })}{/if}
    </div>
  {/if}
</div>

<style>
  .app { display: flex; flex-direction: column; height: 100vh; position: relative; background: var(--win); color: var(--text); }
  .body { flex: 1; min-height: 0; display: flex; }
  .pane { flex: 1; min-width: 0; min-height: 0; overflow: auto; padding: 16px 16px 36px; display: flex; flex-direction: column; }
  /* Même mise en page que le panneau : chaque écran y était enfant direct. */
  /* Largeur bornée : au-delà, agrandir la fenêtre ne déplace plus rien
     (colonnes et boutons restent où ils sont, l'espace en plus reste à droite). */
  .page { flex: 1; min-height: 0; display: flex; flex-direction: column; width: 100%; max-width: 1180px; }
  .page[hidden] { display: none; }
  /* Barre d'état : à droite de la barre latérale, par-dessus le bas du panneau. */
  .status {
    position: absolute; left: 160px; right: 0; bottom: 0;
    border-top: 1px solid var(--line); background: var(--side);
    padding: 6px 18px; font-size: 12px; color: var(--text-2);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .status b { font-weight: 500; }
  .status b.ok { color: var(--ok); }
  .status b.warn { color: var(--warn); }
</style>

<script lang="ts">
  import Sidebar from '#lib/components/Sidebar.svelte';
  import Network from '#lib/components/Network.svelte';
  import Framing from '#lib/components/Framing.svelte';
  import Accounts from '#lib/components/Accounts.svelte';
  import Site from '#lib/components/Site.svelte';
  import Operations from '#lib/components/Operations.svelte';
  import Settings from '#lib/components/Settings.svelte';
  import UpdateBanner from '#lib/components/UpdateBanner.svelte';
  import { page, status } from '#lib/stores/nav.ts';
  import { _ } from 'svelte-i18n';
</script>

<div class="app">
  <UpdateBanner />
  <div class="body">
    <Sidebar />
    <!-- Les écrans restent montés, un seul visible : changer d'onglet ne
         perd ni le scan, ni le filtre, ni les coches, ni une feuille ouverte. -->
    <main class="pane">
      <section class="page" hidden={$page !== 'network'}><Network /></section>
      <section class="page" hidden={$page !== 'framing'}><Framing /></section>
      <section class="page" hidden={$page !== 'accounts'}><Accounts /></section>
      <section class="page" hidden={$page !== 'site'}><Site /></section>
      <section class="page" hidden={$page !== 'operations'}><Operations /></section>
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
  .pane { flex: 1; min-width: 0; min-height: 0; overflow: auto; padding: 0 0 36px; display: flex; flex-direction: column; }
  /* Même mise en page que le panneau : chaque écran y était enfant direct.
     Bord à bord : chaque écran pose sa barre du haut et ses marges. */
  /* Pleine largeur : les colonnes fixes ne bougent pas, seule la première
     (le nom) prend l'espace ; les boutons restent groupés à gauche. */
  .page { flex: 1; min-height: 0; display: flex; flex-direction: column; }
  .page[hidden] { display: none; }
  /* Barre d'état : à droite de la barre latérale, par-dessus le bas du panneau. */
  .status {
    position: absolute; left: 208px; right: 0; bottom: 0;
    border-top: 1px solid var(--line); background: var(--side);
    padding: 7px 24px; font-size: 13px; color: var(--text-2);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .status b { font-weight: 500; }
  .status b.ok { color: var(--ok); }
  .status b.warn { color: var(--warn); }
</style>

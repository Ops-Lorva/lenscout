<script lang="ts">
  import Sidebar from '$lib/components/Sidebar.svelte';
  import Network from '$lib/components/Network.svelte';
  import Framing from '$lib/components/Framing.svelte';
  import Accounts from '$lib/components/Accounts.svelte';
  import Settings from '$lib/components/Settings.svelte';
  import UpdateBanner from '$lib/components/UpdateBanner.svelte';
  import { page, status } from '$lib/stores/nav';
</script>

<div class="app">
  <UpdateBanner />
  <div class="body">
    <Sidebar />
    <main class="pane">
      {#if $page === 'network'}<Network />
      {:else if $page === 'framing'}<Framing />
      {:else if $page === 'accounts'}<Accounts />
      {:else}<Settings />
      {/if}
    </main>
  </div>
  {#if $status}
    <div class="status" role="status">
      {#if $status.tone || $status.detail}<b class={$status.tone}>{$status.text}</b>{:else}{$status.text}{/if}{#if $status.detail}{' '}{$status.detail}{/if}
    </div>
  {/if}
</div>

<style>
  .app { display: flex; flex-direction: column; height: 100vh; position: relative; background: var(--win); color: var(--text); }
  .body { flex: 1; min-height: 0; display: flex; }
  .pane { flex: 1; min-width: 0; min-height: 0; overflow: auto; padding: 16px 16px 36px; display: flex; flex-direction: column; }
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

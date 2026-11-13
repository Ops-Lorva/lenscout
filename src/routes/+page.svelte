<script lang="ts">
  import Sidebar from '$lib/components/Sidebar.svelte';
  import Network from '$lib/components/Network.svelte';
  import Framing from '$lib/components/Framing.svelte';
  import Accounts from '$lib/components/Accounts.svelte';
  import UpdateBanner from '$lib/components/UpdateBanner.svelte';
  import { page } from '$lib/stores/nav';
</script>

<div class="app">
  <Sidebar />
  <div class="main">
    <UpdateBanner />
    <main class="content">
      {#if $page === 'network'}<Network />
      {:else if $page === 'framing'}<Framing />
      {:else}<Accounts />
      {/if}
    </main>
  </div>
</div>

<style>
  .app { display: flex; height: 100vh; background: var(--ep-bg-primary); color: var(--ep-text-primary); }
  .main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .content { flex: 1; min-width: 0; min-height: 0; overflow: auto; padding: 16px 20px; }
</style>

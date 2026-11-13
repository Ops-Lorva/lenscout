<script lang="ts">
  import '@fontsource/geist-sans/400.css';
  import '@fontsource/geist-sans/500.css';
  import '@fontsource/geist-sans/600.css';
  import '@fontsource/geist-mono/400.css';
  import '../app.css';
  import type { Snippet } from 'svelte';
  import { isLoading } from 'svelte-i18n';
  import { initI18n } from '$lib/i18n';

  initI18n();

  const { children } = $props<{ children: Snippet }>();
</script>

{#if !$isLoading}
  {@render children()}
{/if}

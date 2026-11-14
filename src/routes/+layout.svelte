<script lang="ts">
  import '../app.css';
  import type { Snippet } from 'svelte';
  import { isLoading } from 'svelte-i18n';
  import { initI18n } from '$lib/i18n';
  import { applyTheme, theme } from '$lib/stores/settings';

  initI18n();

  // Le script de app.html a déjà posé le thème mémorisé ; ici on suit les
  // changements faits dans les Réglages.
  $effect(() => applyTheme($theme, document.documentElement));

  const { children } = $props<{ children: Snippet }>();
</script>

{#if !$isLoading}
  {@render children()}
{/if}

<script lang="ts">
  import type { Snippet } from 'svelte';

  // Feuille façon macOS : tombe du haut de la fenêtre, le reste s'assombrit.
  // `subtitle` : complément du titre en gris (caméra visée, par exemple).
  let {
    title,
    subtitle = '',
    width = 440,
    onClose,
    children,
  }: { title: string; subtitle?: string; width?: number; onClose: () => void; children: Snippet } = $props();

  // À l'ouverture, le clavier est dans la feuille : premier champ, sinon premier bouton.
  // À la fermeture, il retourne à l'élément qui l'avait (s'il existe encore).
  function focusFirst(sheet: HTMLElement) {
    const before = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const all = [...sheet.querySelectorAll<HTMLElement>('input, select, textarea, button')];
    const usable = all.filter((el) => !(el as HTMLInputElement).disabled && el.getAttribute('type') !== 'hidden');
    (usable.find((el) => el.tagName !== 'BUTTON') ?? usable[0])?.focus();
    return () => {
      if (before?.isConnected) before.focus();
    };
  }

  // Les onglets restent montés : la feuille d'un onglet caché ne doit pas
  // se fermer sur un Échap tapé ailleurs.
  let sheetEl = $state<HTMLElement | null>(null);
  const shown = () => (sheetEl?.getClientRects().length ?? 0) > 0;
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && shown() && onClose()} />

<div class="dim" role="presentation" onclick={onClose}></div>
<div class="sheet" bind:this={sheetEl} role="dialog" aria-modal="true" aria-label={title} style:width="{width}px" {@attach focusFirst}>
  <h3>{title}{#if subtitle}<span class="sub">{subtitle}</span>{/if}</h3>
  {@render children()}
</div>

<style>
  .sub { color: var(--text-2); font-weight: 400; margin-left: 6px; }
</style>

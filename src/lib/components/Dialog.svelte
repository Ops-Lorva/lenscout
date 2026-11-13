<script lang="ts">
  import type { Snippet } from 'svelte';

  let { title, onClose, children }: { title: string; onClose: () => void; children: Snippet } = $props();
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && onClose()} />

<div class="overlay" role="presentation" onclick={(e) => e.target === e.currentTarget && onClose()}>
  <div class="dialog" role="dialog" aria-modal="true" aria-label={title}>
    <h2>{title}</h2>
    {@render children()}
  </div>
</div>

<style>
  .overlay {
    position: fixed; inset: 0; z-index: 10; display: flex; align-items: center; justify-content: center;
    background: rgba(0, 0, 0, 0.5);
  }
  .dialog {
    min-width: 340px; max-width: 460px; padding: 16px 18px; display: flex; flex-direction: column; gap: 10px;
    background: var(--ep-bg-primary); border: 1px solid var(--ep-border-strong); border-radius: var(--ep-radius-md);
  }
  h2 { font-size: 14px; font-weight: 600; margin: 0; }
  .dialog :global(label) { display: flex; flex-direction: column; gap: 3px; font-size: 11px; color: var(--ep-text-muted); }
  .dialog :global(input), .dialog :global(select), .dialog :global(textarea) {
    padding: 5px 10px; font-size: 13px; background: var(--ep-bg-secondary); border: 1px solid var(--ep-border);
    border-radius: var(--ep-radius-md); color: var(--ep-text-primary);
  }
  .dialog :global(input:focus), .dialog :global(select:focus), .dialog :global(textarea:focus) {
    outline: none; border-color: var(--ep-accent);
  }
  .dialog :global(.row) { display: flex; gap: 8px; justify-content: flex-end; margin-top: 4px; }
  .dialog :global(button) {
    padding: 5px 14px; font-size: 13px; cursor: pointer;
    background: var(--ep-glass-bg-md); border: 1px solid var(--ep-glass-border);
    border-radius: var(--ep-radius-md); color: var(--ep-text-primary);
  }
  .dialog :global(button:hover) { border-color: var(--ep-accent); }
  .dialog :global(button.primary) {
    font-weight: 600; background: var(--ep-accent-dim); border-color: var(--ep-accent-glow); color: var(--ep-accent-bright);
  }
  .dialog :global(button:disabled) { opacity: 0.55; cursor: not-allowed; }
</style>

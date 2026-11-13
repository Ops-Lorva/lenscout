<script lang="ts">
  import { _ } from 'svelte-i18n';
  import { resultMessage, type ActionResult } from '$lib/api/configure';
  import type { Camera } from '$lib/api/types';

  let {
    camera,
    result,
    selected,
    onToggle,
    onOpenWeb,
    onFrame,
  }: {
    camera: Camera;
    result?: ActionResult;
    selected: boolean;
    onToggle: () => void;
    onOpenWeb: () => void;
    onFrame: () => void;
  } = $props();

  const message = $derived(result ? resultMessage(result) : null);
  const label = $derived([camera.brand, camera.model].filter(Boolean).join(' ') || '—');
</script>

<tr class:selected>
  <td class="check">
    <input type="checkbox" checked={selected} onchange={onToggle} aria-label={$_('network.select')} />
  </td>
  <td>{label}</td>
  <td class="mono">{camera.ip}</td>
  <td class="mono">{camera.mac ?? '—'}</td>
  <td class="mono">{camera.serial ?? '—'}</td>
  <td>{camera.firmware ?? '—'}</td>
  <td>
    <span class="pill {camera.activation}">{$_(`network.state.${camera.activation}`)}</span>
  </td>
  <td class="result">
    {#if result?.ok}
      <span class="pill ok">{$_('configure.ok')}</span>
    {:else if message}
      <span class="pill bad">{$_(`configure.${message.key}`, { values: { detail: message.detail ?? '' } })}</span>
    {/if}
  </td>
  <td class="actions">
    <button onclick={onOpenWeb}>{$_('network.openWeb')}</button>
    <button onclick={onFrame}>{$_('network.frame')}</button>
  </td>
</tr>

<style>
  td { padding: 7px 10px; border-bottom: 1px solid var(--ep-border); font-size: 12.5px; white-space: nowrap; }
  tr:hover td { background: var(--ep-bg-hover); }
  tr.selected td { background: var(--ep-accent-dim); }
  .check { width: 28px; }
  .mono { font-family: var(--ep-font-mono, monospace); font-size: 12px; }
  .pill {
    display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px;
    border: 1px solid var(--ep-glass-border); color: var(--ep-text-muted);
  }
  .pill.new { color: var(--ep-warning); border-color: var(--ep-warning); }
  .pill.activated { color: var(--ep-success); border-color: var(--ep-success); }
  .pill.ok { color: var(--ep-success); border-color: var(--ep-success); }
  .pill.bad { color: var(--ep-danger); border-color: var(--ep-danger); }
  .actions { text-align: right; }
  button {
    padding: 4px 10px; margin-left: 6px; font-size: 12px; cursor: pointer;
    background: var(--ep-glass-bg-md); border: 1px solid var(--ep-glass-border);
    border-radius: var(--ep-radius-md); color: var(--ep-text-primary);
  }
  button:hover { border-color: var(--ep-accent); }
</style>

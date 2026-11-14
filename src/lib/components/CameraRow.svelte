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
  const text = $derived(message ? $_(message.key, { values: message.values }) : '');
  const label = $derived([camera.brand, camera.model].filter(Boolean).join(' ') || '—');
</script>

<tr class:sel={selected}>
  <td class="chk">
    <input type="checkbox" checked={selected} onchange={onToggle} aria-label={$_('network.select')} />
  </td>
  <td>{label}</td>
  <td>{camera.ip}</td>
  <td class="mac" class:dim-t={!camera.mac}>{camera.mac ?? '—'}</td>
  <td class="mac ser" class:dim-t={!camera.serial} title={camera.serial ?? ''}>{camera.serial ?? '—'}</td>
  <td class:dim-t={!camera.firmware}>{camera.firmware ?? '—'}</td>
  <!-- Le résultat de la dernière action se lit sous l'état, en texte. -->
  <td class="st {camera.activation}" class:dim-t={camera.activation === 'unknown'}>
    {$_(`network.state.${camera.activation}`)}
    {#if result?.ok}
      <div class="res ok">{$_('configure.ok')}</div>
    {:else if text}
      <div class="res bad" title={text}>{text}</div>
    {/if}
  </td>
  <td class="ra">
    <button class="mini" onclick={onOpenWeb}>{$_('network.openWeb')}</button>
    <button class="mini" onclick={onFrame}>{$_('network.frame')}</button>
  </td>
</tr>

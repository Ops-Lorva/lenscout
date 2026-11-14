<script lang="ts">
  import { _ } from 'svelte-i18n';
  import { resultMessage, type ActionResult } from '#lib/api/configure.ts';
  import type { Camera } from '#lib/api/types.ts';
  import { addressingKey, cameraName, shownMac } from '#lib/api/discovery.ts';

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
  const label = $derived(cameraName(camera));
  const addressing = $derived(addressingKey(camera));
  const mac = $derived(shownMac(camera));
</script>

<tr class:sel={selected}>
  <td class="chk">
    <input type="checkbox" checked={selected} onchange={onToggle} aria-label={$_('network.select')} />
  </td>
  <td class="grow" title={label}>{label}</td>
  <td>{camera.ip}</td>
  <td class="mac" class:dim-t={!mac.mac} class:decl={mac.declared} title={mac.declared ? $_('network.macDeclared') : undefined}>{mac.mac ?? '—'}{#if mac.declared}<sup>*</sup>{/if}</td>
  <td class="mac ser" class:dim-t={!camera.serial} title={camera.serial ?? ''}>{camera.serial ?? '—'}</td>
  <td class:dim-t={!camera.firmware}>{camera.firmware ?? '—'}</td>
  <td class:dim-t={addressing.endsWith('.unknown')}>{$_(addressing)}</td>
  <!-- Le résultat de la dernière action se lit sous l'état, en texte. -->
  <td class="st {camera.activation}" class:dim-t={camera.activation === 'unknown'}>
    {$_(`network.state.${camera.activation}`)}
    {#if result?.ok}
      <div class="res ok">{$_('configure.ok')}</div>
    {:else if text}
      <div class="res bad" title={text}>{text}</div>
    {/if}
  </td>
  <td class="ra acts">
    <button class="mini" onclick={onOpenWeb}>{$_('network.openWeb')}</button>
    <button class="mini" onclick={onFrame}>{$_('network.frame')}</button>
  </td>
</tr>

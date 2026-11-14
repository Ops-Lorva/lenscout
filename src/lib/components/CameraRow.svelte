<script lang="ts">
  import { _ } from 'svelte-i18n';
  import { resultMessage, type ActionResult } from '#lib/api/configure.ts';
  import type { Camera } from '#lib/api/types.ts';
  import { addressingKey, shownMac } from '#lib/api/discovery.ts';

  let {
    camera,
    result,
    selected,
    onToggle,
    onOpenWeb,
    onFrame,
    onReset,
  }: {
    camera: Camera;
    result?: ActionResult;
    selected: boolean;
    onToggle: () => void;
    onOpenWeb: () => void;
    onFrame: () => void;
    onReset: () => void;
  } = $props();

  // Menu « … » de la ligne : actions moins courantes, réinitialisation d'abord.
  // Placé en position fixe : le tableau défile (.scroll) et rognerait un menu absolu.
  let menu = $state(false);
  let menuPos = $state({ top: 0, right: 0 });
  function toggleMenu(e: MouseEvent) {
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    menuPos = { top: r.bottom + 4, right: window.innerWidth - r.right };
    menu = !menu;
  }
  // Un défilement (du tableau ou de la page) décalerait le menu fixe : on le ferme.
  $effect(() => {
    if (!menu) return;
    const close = () => (menu = false);
    window.addEventListener('scroll', close, true);
    return () => window.removeEventListener('scroll', close, true);
  });

  const message = $derived(result ? resultMessage(result) : null);
  const text = $derived(message ? $_(message.key, { values: message.values }) : '');
  const label = $derived([camera.brand, camera.model].filter(Boolean).join(' ') || '—');
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
    <span class="more">
      <button class="mini" aria-haspopup="menu" aria-expanded={menu} aria-label={$_('network.more')} onclick={toggleMenu}>…</button>
      {#if menu}
        <div class="menu" role="menu" style="top: {menuPos.top}px; right: {menuPos.right}px">
          <button role="menuitem" disabled={camera.family === 'other'} onclick={() => { menu = false; onReset(); }}>{$_('configure.reset.button')}</button>
        </div>
      {/if}
    </span>
  </td>
</tr>

<svelte:window
  onclick={(e) => { if (menu && !(e.target as Element).closest?.('.more')) menu = false; }}
  onresize={() => (menu = false)}
/>

<style>
  .more { position: relative; display: inline-block; margin-left: 4px; }
  .menu {
    position: fixed; z-index: 50; min-width: 160px;
    background: var(--win); border: 1px solid var(--line); border-radius: 6px; padding: 4px;
    box-shadow: 0 4px 16px #0003; text-align: left;
  }
  .menu button { display: block; width: 100%; text-align: left; background: none; border: 0; padding: 5px 8px; border-radius: 4px; color: inherit; font: inherit; cursor: default; }
  .menu button:hover:not([disabled]) { background: var(--hover); }
  .menu button[disabled] { opacity: .42; }
</style>

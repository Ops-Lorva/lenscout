<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import { get } from 'svelte/store';
  import { _ } from 'svelte-i18n';
  import { errorKey } from '#lib/api/errors.ts';
  import { ackFrame, FramePresenter, identifyCamera, identityChanged, listViews, needsIdentify, noticeKey, startStream, stopStream, viewLabel, type View } from '#lib/api/stream.ts';
  import { framingTarget, page, suspendStep } from '#lib/stores/nav.ts';
  import AccountPicker from './AccountPicker.svelte';
  import ImageSettings from './ImageSettings.svelte';
  import { normRect } from '#lib/api/imaging.ts';
  import { cameraName } from '#lib/api/discovery.ts';

  let accountId = $state('');
  let playing = $state(false);
  // Mis en pause à la main (le bouton de secours) : ni l'auto-démarrage ni la
  // relance automatique ne repartent tant que le technicien n'a pas relancé.
  let paused = $state(false);
  let src = $state<string | null>(null);
  let error = $state('');
  // Un flux qui tombe (caméra qui redémarre, réseau qui cligne) se relance seul
  // après ce délai ; une pause ou un changement de caméra l'annulent.
  const RELAUNCH_MS = 1500;
  let relaunchTimer: ReturnType<typeof setTimeout> | null = null;
  // Un start remplacé par un autre se résout aussi : seule la dernière
  // génération a le droit de toucher à l'état.
  let generation = 0;
  // Flux coupé parce que l'onglet est passé caché : à reprendre au retour.
  let suspended = false;

  const presenter = new FramePresenter(
    (u) => (src = u),
    undefined,
    undefined,
    undefined,
    () => void ackFrame().catch(() => {}),
  );
  const cam = $derived($framingTarget);

  // IP saisie : Rust identifie la caméra (même garde que le flux), qui
  // devient la cible comme si elle venait de Réseau, puis la lecture part.
  let typedIp = $state('');
  let identifying = $state(false);
  async function openTyped() {
    if (!typedIp.trim() || !accountId || identifying) return;
    identifying = true;
    error = '';
    try {
      const found = await identifyCamera(typedIp, accountId);
      paused = false;
      // La nouvelle cible déclenche l'auto-démarrage (effet sur `cam`).
      framingTarget.set(found);
    } catch (e) {
      error = `framing.${errorKey(e)}`;
    } finally {
      identifying = false;
    }
  }

  // Le flux est-il encore voulu ? (caméra et compte là, onglet visible, ni
  // suspendu par l'onglet caché, ni mis en pause à la main.)
  function wantsStream(): boolean {
    return !!cam && !!accountId && get(page) === 'framing' && !suspended && !paused;
  }

  function clearRelaunch() {
    if (relaunchTimer) { clearTimeout(relaunchTimer); relaunchTimer = null; }
  }
  function scheduleRelaunch() {
    clearRelaunch();
    relaunchTimer = setTimeout(() => { relaunchTimer = null; if (wantsStream()) void play(); }, RELAUNCH_MS);
  }

  async function play() {
    if (!cam || !accountId) return;
    clearRelaunch();
    const mine = ++generation;
    error = '';
    playing = true;
    try {
      await startStream(
        cam,
        accountId,
        (buf) => {
          if (mine === generation) presenter.push(buf);
        },
        views.find((v) => v.n === view) ?? null,
      );
      // Flux terminé de lui-même et toujours voulu : on le relance.
      if (mine === generation && wantsStream()) { scheduleRelaunch(); return; }
    } catch (e) {
      // Le flux est tombé : s'il est encore voulu, on affiche la raison mais on
      // relance quand même (la caméra redémarre peut-être).
      if (mine === generation) {
        error = `framing.${errorKey(e)}`;
        if (wantsStream()) { scheduleRelaunch(); return; }
      }
    }
    if (mine === generation) {
      playing = false;
      presenter.clear();
    }
  }

  async function stop() {
    clearRelaunch();
    generation++;
    playing = false;
    presenter.clear();
    try { await stopStream(); } catch {}
  }

  // Bouton de secours : mettre en pause ou relancer à la main.
  function pause() { paused = true; void stop(); }
  function resume() { paused = false; void play(); }

  // Ratio largeur/hauteur de l'image reçue ; 16/9 tant qu'aucune n'est décodée.
  let ratio = $state(16 / 9);
  function onLoad(e: Event) {
    const img = e.currentTarget as HTMLImageElement;
    if (img.naturalWidth > 0 && img.naturalHeight > 0) ratio = img.naturalWidth / img.naturalHeight;
  }

  function fullscreen(e: MouseEvent) {
    const el = e.currentTarget as HTMLElement;
    if (document.fullscreenElement) void document.exitFullscreen();
    else void el.requestFullscreen?.();
  }

  // Caméra ou compte prêts : le flux démarre tout seul (plus de bouton Lecture).
  // Changer de cible coupe d'abord le flux de la précédente. Une caméra encore
  // à trancher (cf. `needsIdentify` : marque « other », ou vue à travers le
  // routeur sans être confirmée Axis) peut n'avoir pas d'URL de flux : on attend
  // qu'elle soit relue avec le compte, qui repose la cible et redéclenche cet
  // effet — évite un bref « unsupported_brand ».
  $effect(() => {
    void cam; void accountId;
    untrack(() => {
      suspended = false;
      void stop();
      if (!paused && !(cam && needsIdentify(cam))) void play();
    });
  });

  // Échec visible (identification ou vues) : identifiants refusés, caméra
  // injoignable, vues illisibles — un message au lieu du silence.
  let notice = $state('');

  // Caméra arrivée par « Cadrer » : le scan l'a posée telle qu'il l'a vue. Une
  // Axis routée, identifiée sans compte au balayage HTTP, y paraît « other » ou
  // Hikvision — son sélecteur de vues et son panneau Axis restent cachés. On la
  // relit avec le compte, comme l'ouverture par IP, pour trancher sa marque
  // AVANT de lister les vues. `identify` rend une caméra sans source et jamais
  // « other » : la relecture ne se répète pas (pas de boucle), et une caméra
  // déjà tranchée (ouverture par IP, scan de couche 2) passe tout droit.
  $effect(() => {
    const c = cam;
    const a = accountId;
    untrack(() => {
      notice = '';
      if (!c || !a || !needsIdentify(c)) return;
      identifyCamera(c.ip, a)
        .then((found) => {
          // Même caméra visée et identité vraiment changée : on repose la cible
          // (relance flux + vues, comme l'ouverture par IP).
          if (get(framingTarget)?.ip === c.ip && identityChanged(found, c)) framingTarget.set(found);
        })
        .catch((e) => { notice = noticeKey(e); });
    });
  });

  // Axis multicapteur : ses vues, lues avec le compte, pour le sélecteur.
  // Une seule vue (ou rien de lisible) : pas de sélecteur, URL d'avant.
  let views = $state<View[]>([]);
  let view = $state<number | null>(null);
  let viewsRun = 0;
  $effect(() => {
    const c = cam;
    const a = accountId;
    untrack(() => {
      const mine = ++viewsRun;
      views = [];
      view = null;
      if (!c || !a) return;
      listViews(c, a)
        .then((v) => {
          if (mine !== viewsRun || v.length < 2) return;
          views = v;
          view = v[0].n;
        })
        .catch((e) => { if (mine === viewsRun) notice = noticeKey(e); });
    });
  });

  // Autre vue pendant la lecture : le flux repart sur elle.
  function pickView(n: number) {
    view = n;
    if (playing) void play();
  }

  // Panneau de réglages (Axis) : il suit la vue choisie.
  const chosenView = $derived(views.find((v) => v.n === view) ?? null);
  // Vue groupée (« 1,0 ») : la caméra pose ses capteurs côte à côte, un
  // réticule au centre de chacun.
  const reticles = $derived.by(() => {
    const n = Math.max(1, chosenView?.source?.split(',').filter((s) => s.trim() !== '').length ?? 1);
    return Array.from({ length: n }, (_, i) => ((i + 0.5) / n) * 100);
  });
  let panel = $state<ReturnType<typeof ImageSettings> | null>(null);
  let drawing = $state(false);
  // Rectangle de la zone d'autofocus en cours de tracé, en coordonnées de la page.
  let dragFrom = $state<{ x: number; y: number } | null>(null);
  let dragTo = $state<{ x: number; y: number } | null>(null);
  let frameEl = $state<HTMLElement | null>(null);

  function dragStart(e: PointerEvent) {
    if (!drawing) return;
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    dragFrom = dragTo = { x: e.clientX, y: e.clientY };
  }
  function dragMove(e: PointerEvent) {
    if (dragFrom) dragTo = { x: e.clientX, y: e.clientY };
  }
  function dragEnd() {
    const box = frameEl?.getBoundingClientRect();
    const w = dragFrom && dragTo && box ? normRect(dragFrom, dragTo, box) : null;
    dragFrom = dragTo = null;
    if (w) void panel?.applyWindow(w);
  }
  // Le tracé dans le repère du cadre, pour l'afficher.
  const dragged = $derived.by(() => {
    const box = frameEl?.getBoundingClientRect();
    return dragFrom && dragTo && box ? normRect(dragFrom, dragTo, box) : null;
  });

  // Rotation écrite : l'image change de géométrie, le flux repart.
  function rotated() {
    if (playing) void play();
  }

  // Onglet caché (il reste monté) : le flux est coupé, pas de bande
  // passante dans le dos ; il reprend au retour sur l'onglet.
  $effect(() => {
    const visible = $page === 'framing';
    untrack(() => {
      const step = suspendStep(visible, playing, suspended);
      if (step === 'suspend') {
        suspended = true;
        void stop();
      } else if (step === 'resume') {
        suspended = false;
        if (!paused) void play();
      } else if (visible) {
        suspended = false;
      }
    });
  });

  // Démontage (sortie de l'app) : coupe le flux et libère l'image.
  onDestroy(() => {
    clearRelaunch();
    generation++;
    presenter.dispose();
    void stopStream().catch(() => {});
  });
</script>

<div class="fbar tools bar">
  <span class="title">{$_('common.nav.framing')}</span>
  <form class="byip" onsubmit={(e) => { e.preventDefault(); void openTyped(); }}>
    <input type="text" bind:value={typedIp} placeholder="192.168.1.64" aria-label={$_('framing.ip')}
      inputmode="decimal" autocomplete="off" spellcheck="false" />
    <button class="btn" type="submit" disabled={!typedIp.trim() || !accountId || identifying}>
      {#if identifying}<span class="spin"></span>{/if}{$_('framing.open')}
    </button>
  </form>
  <!-- Compte avant le nom de la caméra : sa place ne dépend pas de la longueur du nom. -->
  <label class="acc field">{$_('accounts.picker')} <AccountPicker bind:accountId /></label>
  {#if cam}
    <strong>{cameraName(cam)}</strong>
    <span class="ip">{cam.ip}</span>
    {#if views.length > 1}
      <select value={view} onchange={(e) => pickView(Number(e.currentTarget.value))} aria-label={$_('framing.viewPicker')}>
        {#each views as v (v.n)}
          {@const l = viewLabel(v)}
          <option value={v.n}>{$_(l.key, { values: l.values })}</option>
        {/each}
      </select>
    {/if}
  {/if}
  {#if cam}
    <!-- Secours : le flux est automatique, ce bouton n'est qu'un filet. -->
    {#if paused}
      <button class="btn def" onclick={resume} disabled={!accountId}>{$_('framing.resume')}</button>
    {:else}
      <button class="btn" onclick={pause}>{$_('framing.pause')}</button>
    {/if}
  {/if}
</div>
{#if error}<p class="err">{$_(error)}</p>{/if}
{#if cam && notice}<p class="err note">{$_(notice)}</p>{/if}
{#if !cam}
  <div class="none">{$_('framing.none')}</div>
{:else}
  <div class="stage">
    <!-- Sans flux, la zone reste à sa place, vide et claire, pour que la fenêtre ne saute pas. -->
    <div class="view" class:off={!src} ondblclick={fullscreen} role="presentation">
      {#if src}
        <!-- Le cadre a le ratio réel de l'image : la grille des tiers et le
             réticule tombent sur l'image, jamais sur les bandes. -->
        <div class="frame" style:--r={ratio} bind:this={frameEl}>
          <img {src} alt={$_('framing.image')} onload={onLoad} />
          <div class="grid"></div>
          {#each reticles as x (x)}<div class="ret" style:left="{x}%"></div>{/each}
          {#if drawing}
            <div class="draw" role="presentation" onpointerdown={dragStart} onpointermove={dragMove} onpointerup={dragEnd}
              ondblclick={(e) => e.stopPropagation()}>
              {#if dragged}
                <div class="zone" style:left="{dragged.x * 100}%" style:top="{dragged.y * 100}%"
                  style:width="{dragged.width * 100}%" style:height="{dragged.height * 100}%"></div>
              {/if}
            </div>
          {/if}
        </div>
      {/if}
    </div>
    {#if accountId}
      <ImageSettings bind:this={panel} bind:drawing camera={cam} {accountId} view={chosenView} onRotated={rotated} />
    {/if}
  </div>
{/if}

<style>
  .byip { display: inline-flex; align-items: center; gap: 8px; margin: 0; }
  .byip input { width: 9.5rem; }
  .view { display: flex; align-items: center; justify-content: center; container-type: size; }
  /* Largeur bornée par la zone et par la hauteur transposée via le ratio (unités de conteneur). */
  .frame { position: relative; width: min(100%, calc(100cqh * var(--r))); aspect-ratio: var(--r); }
  .frame img { display: block; width: 100%; height: 100%; }
  /* Sans unités de conteneur (WebKit < 16) : l'image seule, centrée, sans grille. */
  @supports not (width: 1cqh) {
    .frame { width: 100%; align-self: stretch; aspect-ratio: auto; display: flex; align-items: center; justify-content: center; }
    .frame img { width: auto; height: auto; max-width: 100%; max-height: 100%; object-fit: contain; }
    .frame .grid, .frame .ret { display: none; }
  }
  .view:fullscreen { border-radius: 0; background: #000; }
  /* Image à gauche, panneau des réglages optiques collé à droite (maquette). */
  .stage { flex: 1; display: flex; min-height: 0; }
  .stage .view { margin: 24px; }
  /* Information (vues/réglages indisponibles), pas une panne de flux : ton plus discret. */
  .note { opacity: 0.85; font-weight: 400; }
  .draw { position: absolute; inset: 0; cursor: crosshair; }
  .zone { position: absolute; border: 1.5px solid var(--view-line); background: #ffffff1a; pointer-events: none; }
</style>

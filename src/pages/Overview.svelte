<script lang="ts">
  // Startseite: Statusbild des gewählten Looks, großes Statuswort, Kennzahlen als Band
  import { fly, fade } from 'svelte/transition'
  import { invoke } from '@tauri-apps/api/core'
  import SceneFeld from '../components/SceneFeld.svelte'
  import SceneOrbit from '../components/SceneOrbit.svelte'
  import SceneTerminal from '../components/SceneTerminal.svelte'
  import SceneBlueprint from '../components/SceneBlueprint.svelte'
  import type { SceneMode } from '../components/scene'
  import Icon from '../components/Icon.svelte'
  import Num from '../components/Num.svelte'
  import { ask } from '../components/Confirm.svelte'
  import { app } from '../lib/store.svelte'
  import { bytes, clock, duration, kindLabel, nextRun, relative } from '../lib/format'
  import { i18n, loc, t, tn } from '../lib/i18n.svelte'
  import { toasts } from '../lib/toast.svelte'
  import { isHint, type Segment } from '../lib/types'

  const status = $derived(app.status)
  const job = $derived(app.job)
  const snap = $derived(app.snap)
  const look = $derived(snap?.settings.look ?? 'feld')
  const scanning = $derived(status === 'scanning' || status === 'counting' || status === 'paused')

  // Fortschritt der laufenden Prüfung
  const progress = $derived(job && job.total > 0 ? Math.min(1, job.scanned / job.total) : 0)
  const percent = $derived(Math.floor(progress * 100))

  let now = $state(Date.now())
  $effect(() => {
    const id = setInterval(() => (now = Date.now()), 1000)
    return () => clearInterval(id)
  })

  // Tempo aus den letzten Sekunden (gleitend), damit die Restzeit ruhig bleibt
  let samples: { at: number; n: number }[] = []
  let rate = $state(0)
  $effect(() => {
    const j = job
    if (!j || j.phase !== 'scanning') {
      samples = []
      if (!j || j.phase !== 'paused') rate = 0
      return
    }
    samples.push({ at: Date.now(), n: j.scanned })
    samples = samples.filter((s) => Date.now() - s.at < 12000)
    if (samples.length > 1) {
      const a = samples[0]
      const b = samples[samples.length - 1]
      rate = b.at > a.at ? ((b.n - a.n) * 1000) / (b.at - a.at) : rate
    }
  })
  const remaining = $derived(rate > 0 && job ? (job.total - job.scanned) / rate : NaN)

  const sceneMode = $derived<SceneMode>(
    status === 'setup' || status === 'loading'
      ? 'setup'
      : status === 'counting'
        ? 'counting'
        : status === 'scanning'
          ? 'scanning'
          : status === 'paused'
            ? 'paused'
            : status === 'threat'
              ? 'threat'
              : status === 'warn'
                ? 'warn'
                : 'safe',
  )

  const segments = $derived<Segment[]>(job?.segments ?? [])
  const segLabels = $derived(segments.map((s) => loc(s, 'label')))
  const currentSeg = $derived(segments[job?.segmentIndex ?? 0] ? segLabels[job?.segmentIndex ?? 0] : null)
  // Für die Blaupause im Ruhezustand: Bereiche der letzten Prüfung
  const DEFAULT_AREAS: Segment[] = [
    { label: '/home', path: '/home', files: 900 },
    { label: '/usr', path: '/usr', files: 1400 },
    { label: '/var', path: '/var', files: 260 },
    { label: '/etc', path: '/etc', files: 90 },
    { label: '/opt', path: '/opt', files: 160 },
    { label: '/tmp', path: '/tmp', files: 40 },
  ]
  const lastSegments = $derived(app.lastScan?.segments?.length ? app.lastScan.segments : DEFAULT_AREAS)
  // Nur echte Bedrohungen werden in Bildern rot markiert
  const threatPaths = $derived([...app.openThreats.filter((o) => !o.hint).map((o) => o.threat.path), ...(job?.threats ?? []).filter((x) => !isHint(x)).map((x) => x.path)])
  const jobThreats = $derived(job ? job.threats.filter((x) => !isHint(x)).length : 0)

  const word = $derived(
    status === 'threat'
      ? tn('status.threat', app.threatCount)
      : t(`status.${status}`),
  )

  const sentence = $derived.by(() => {
    const kind = job ? kindLabel(job.kind) : ''
    switch (status) {
      case 'loading':
        return app.loadError ? t('overview.loadError', { e: app.loadError }) : t('overview.loading')
      case 'setup':
        return t('overview.setup')
      case 'counting':
        return t('overview.counting', { kind, n: new Intl.NumberFormat(i18n.locale).format(job!.total) })
      case 'scanning':
        return t(job!.trigger === 'schedule' ? 'overview.scanningScheduled' : 'overview.scanning', { kind })
      case 'paused':
        return t('overview.paused', { kind })
      case 'busy':
        return t('overview.busy', { kind })
      case 'threat':
        return t('overview.threat')
      case 'warn':
        return app.problems[0] ?? t('overview.warnFallback')
      default: {
        const last = app.lastScan
        if (!last) return t('overview.noScan')
        // Nur was noch offen ist: erledigte oder gelöschte Funde zählen nicht mehr
        const threats = app.threatCount
        const hints = app.hintCount
        const result = [threats ? tn('overview.findings', threats) : t('overview.noFindings'), hints ? tn('overview.hints', hints) : ''].filter(Boolean).join(', ')
        return t('overview.lastScan', { when: relative(last.finishedAt ?? last.startedAt, now), result })
      }
    }
  })

  const next = $derived.by(() => {
    const c = snap?.config
    if (!c) return null
    const runs = (['quick', 'full'] as const)
      .map((k) => ({ k, at: nextRun(c.schedule[k]) }))
      .filter((r) => r.at)
      .sort((a, b) => a.at!.getTime() - b.at!.getTime())
    return runs[0] ?? null
  })

  const systemWarnings = $derived(snap?.system?.items.filter((i) => i.status === 'warn' || i.status === 'critical').length ?? 0)

  // Terminal-Look: die letzten geprüften Pfade als mitlaufendes Protokoll
  let log = $state<string[]>([])
  $effect(() => {
    const c = job?.current
    if (look === 'terminal' && scanning && c && log[log.length - 1] !== c) log = [...log, c].slice(-7)
    if (!scanning) log = []
  })

  async function cancel() {
    if (await ask(t('overview.cancelTitle'), t('overview.cancelText'), t('overview.cancelConfirm'), true)) app.startJob('cancel')
  }

  async function copySetup() {
    if (!snap?.setupCommand) return
    await navigator.clipboard.writeText(snap.setupCommand)
    toasts.show('success', t('overview.copied'))
  }

  async function pickFolder() {
    try {
      const picked = await invoke<string[] | null>('pick_folders')
      if (picked && picked.length) app.startJob('custom', picked)
    } catch (e) {
      toasts.show('error', t('overview.folderFailed'), String(e))
    }
  }

  function shortPath(p: string) {
    if (!p) return '…'
    return p.length > 96 ? `…${p.slice(-95)}` : p
  }
</script>

<section class="overview look-{look}" in:fade={{ duration: 260 }}>
  <div class="hero">
    {#if look === 'orbit'}
      <SceneOrbit mode={sceneMode} {progress} {segments} segmentIndex={job?.segmentIndex} scanned={job?.scanned} threats={app.threatCount || jobThreats} pulse={app.pulse} labels={segLabels} />
    {:else if look === 'terminal'}
      <SceneTerminal mode={sceneMode} {progress} {segments} segmentIndex={job?.segmentIndex} scanned={job?.scanned} threats={app.threatCount || jobThreats} pulse={app.pulse} labels={segLabels} />
    {:else if look === 'blaupause'}
      <SceneBlueprint mode={sceneMode} {progress} {segments} segmentIndex={job?.segmentIndex} scanned={job?.scanned} threats={app.threatCount || jobThreats} pulse={app.pulse} labels={segLabels} fallback={lastSegments} {threatPaths} />
    {:else}
      <SceneFeld mode={sceneMode} {progress} {segments} segmentIndex={job?.segmentIndex} scanned={job?.scanned} threats={job && scanning ? jobThreats : app.threatCount} pulse={app.pulse} labels={segLabels} />
    {/if}

    <div class="status">
      {#key word}
        <h1 class="word display" class:threat={status === 'threat'} class:warn={status === 'warn' || status === 'paused'} aria-live="polite">
          {#each word.split('') as ch, i}
            <span in:fly={{ y: 38, duration: 620, delay: i * 38, opacity: 0 }}>{ch === ' ' ? ' ' : ch}</span>
          {/each}
          {#if look === 'terminal'}<span class="cursor">_</span>{/if}
        </h1>
      {/key}
      {#key sentence}<p class="sentence" in:fade={{ duration: 300 }}>{sentence}</p>{/key}

      {#if status === 'warn' && app.problems.length > 1}
        <ul class="problems" in:fade>
          {#each app.problems.slice(1, 4) as p}<li>{p}</li>{/each}
        </ul>
      {/if}

      {#if status === 'setup' && snap?.setupCommand}
        <div class="setup" in:fly={{ y: 10, duration: 400, delay: 300 }}>
          <code class="mono">{snap.setupCommand}</code>
          <button class="btn small" onclick={copySetup}><Icon name="copy" size={14} />{t('overview.copy')}</button>
        </div>
      {/if}

      {#if look === 'terminal' && log.length}
        <ol class="log mono">
          {#each log as line, i (line + i)}
            <li in:fly={{ y: 8, duration: 200 }}><span>scan</span> {line}</li>
          {/each}
        </ol>
      {/if}
    </div>

    {#if scanning && job}
      <aside class="meter" in:fly={{ x: 20, duration: 500 }} out:fade={{ duration: 200 }}>
        <div class="pct mono" class:paused={status === 'paused'}>
          {#if status === 'counting'}··{:else}<Num value={percent} duration={400} />{/if}<small>%</small>
        </div>
        <div class="bar"><span style="transform: scaleX({progress})" class:paused={status === 'paused'}></span></div>
        <dl>
          {#if currentSeg}
            <dt>{t('overview.meter.area')}</dt>
            <dd class="mono seg" title={segments[job.segmentIndex ?? 0]?.path}>{currentSeg}</dd>
          {/if}
          <dt>{t('overview.meter.files')}</dt>
          <dd class="mono"><Num value={job.scanned} duration={350} /> <span>/ {job.counted ? new Intl.NumberFormat(i18n.locale).format(job.total) : '…'}</span></dd>
          <dt>{t('overview.meter.data')}</dt>
          <dd class="mono">{bytes(job.bytes)}</dd>
          <dt>{t('overview.meter.speed')}</dt>
          <dd class="mono">{rate > 0 ? t('overview.meter.perSecond', { n: new Intl.NumberFormat(i18n.locale).format(Math.round(rate)) }) : '…'}</dd>
          <dt>{t('overview.meter.remaining')}</dt>
          <dd class="mono">{status === 'paused' ? t('status.paused') : isFinite(remaining) ? t('overview.meter.about', { d: duration(remaining) }) : '…'}</dd>
          <dt>{t('overview.meter.skipped')}</dt>
          <dd class="mono">{new Intl.NumberFormat(i18n.locale).format(job.skipped)}</dd>
          {#if jobThreats}
            <dt class="hot">{t('overview.meter.findings')}</dt>
            <dd class="mono hot"><Num value={jobThreats} /></dd>
          {/if}
        </dl>
      </aside>
    {/if}
  </div>

  {#if scanning && job}
    <div class="ticker mono" title={job.current}>
      <span class="label">{t('overview.now')}</span>
      {#key job.current}<span class="path" in:fade={{ duration: 120 }}>{shortPath(loc(job, 'current') || job.current)}</span>{/key}
    </div>
  {:else}
    <div class="band stagger">
      <div class="cell" style="--i: 0">
        <span class="label">{t('overview.band.signatures')}</span>
        <span class="val" class:hot={(app.signatureAgeHours ?? 0) > 48}>{snap?.signatures ? relative(snap.signatures.checkedAt ?? snap.signatures.date, now) : t('time.unknown')}</span>
        <span class="sub mono">{snap?.signatures ? t('overview.band.sigFrom', { when: relative(snap.signatures.date, now) }) : t('overview.band.noClam')}</span>
      </div>
      <div class="cell" style="--i: 1">
        <span class="label">{t('overview.band.lastScan')}</span>
        <span class="val">{app.lastScan ? relative(app.lastScan.finishedAt ?? app.lastScan.startedAt, now) : t('time.never')}</span>
        <span class="sub">{app.lastScan ? t('overview.band.lastScanSub', { kind: kindLabel(app.lastScan.kind), n: new Intl.NumberFormat(i18n.locale).format(app.lastScan.scanned) }) : t('overview.band.recommendQuick')}</span>
      </div>
      <div class="cell" style="--i: 2">
        <span class="label">{t('overview.band.nextScan')}</span>
        <span class="val">{next ? relative(next.at!.toISOString(), now) : t('overview.band.notPlanned')}</span>
        <span class="sub">{next ? t('overview.band.nextSub', { kind: kindLabel(next.k), time: clock(next.at!.toISOString()) }) : t('overview.band.planHint')}</span>
      </div>
      <div class="cell" style="--i: 3">
        <span class="label">{t('overview.band.watcher')}</span>
        <span class="val">{snap?.watcherActive ? t('overview.band.watching') : t('overview.band.off')}</span>
        <span class="sub" title={snap?.watcherLast?.path}>
          {#if snap?.watcherLast}{snap.watcherLast.path.split('/').pop()}: {snap.watcherLast.verdict === 'clean' ? t('overview.band.clean') : snap.watcherLast.verdict === 'infected' ? t('overview.band.hit') : t('overview.band.unchecked')}{:else}{t('overview.band.noDownloads')}{/if}
        </span>
      </div>
      <div class="cell" style="--i: 4">
        <span class="label">{t('overview.band.system')}</span>
        <span class="val" class:warnc={systemWarnings > 0}>{snap?.system ? (systemWarnings ? tn('overview.band.hints', systemWarnings) : t('overview.band.ok')) : t('overview.band.notChecked')}</span>
        <span class="sub">{snap?.system ? (snap.system.hardeningIndex === null ? t('overview.band.hardeningNone') : t('overview.band.hardening', { n: snap.system.hardeningIndex })) : t('overview.band.startCheck')}</span>
      </div>
    </div>
  {/if}

  <div class="actions">
    {#if scanning}
      {#if status !== 'counting'}
        <button class="btn" class:busy={app.pending['pause']} onclick={() => app.togglePause()}>
          <Icon name={status === 'paused' ? 'play' : 'pause'} size={14} />{status === 'paused' ? t('overview.actions.resume') : t('overview.actions.pause')}
        </button>
      {/if}
      <button class="btn danger" onclick={cancel}><Icon name="stop" size={14} />{t('overview.actions.cancel')}</button>
      <span class="hint">{t('overview.actions.background')}</span>
    {:else if status === 'setup'}
      <span class="hint">{t('overview.actions.afterSetup')}</span>
    {:else}
      {#if status === 'threat'}
        <button class="btn primary" onclick={() => (app.page = 'findings')}><Icon name="alert" size={15} />{t('overview.actions.viewFindings')}</button>
        <button class="btn" class:busy={app.pending['job:quick']} onclick={() => app.startScan('quick')}>{t('overview.actions.quick')}</button>
      {:else if status === 'warn'}
        <button class="btn primary" onclick={() => (app.page = 'system')}><Icon name="shield" size={15} />{t('overview.actions.toSystem')}</button>
        <button class="btn" class:busy={app.pending['job:quick']} onclick={() => app.startScan('quick')}>{t('overview.actions.quick')}</button>
      {:else}
        <button class="btn primary" class:busy={app.pending['job:quick'] || status === 'busy'} onclick={() => app.startScan('quick')}><Icon name="play" size={14} />{t('overview.actions.quick')}</button>
      {/if}
      <button class="btn" class:busy={app.pending['job:full']} onclick={() => app.startScan('full')}>{t('overview.actions.full')}</button>
      <button class="btn ghost" onclick={pickFolder}><Icon name="folder" size={15} />{t('overview.actions.folder')}</button>
    {/if}
  </div>
</section>

<style>
  .overview {
    height: 100%;
    display: flex;
    flex-direction: column;
  }
  .hero {
    position: relative;
    flex: 1;
    min-height: 300px;
    overflow: hidden;
  }
  .status {
    position: absolute;
    left: var(--pad);
    bottom: 28px;
    right: 320px;
    pointer-events: none;
  }
  .status :global(button),
  .status .setup {
    pointer-events: auto;
  }
  .word {
    margin: 0;
    font-size: calc(clamp(64px, 10.5vw, 148px) * var(--display-scale));
    line-height: 0.86;
    color: var(--text);
    display: flex;
    align-items: baseline;
    overflow: hidden;
    /* Platz für Umlautpunkte über Großbuchstaben und Unterlängen (g, p, y), ohne die Lage zu verschieben */
    padding-top: 0.2em;
    margin-top: -0.2em;
    padding-bottom: 0.24em;
    margin-bottom: -0.18em;
  }
  .word span {
    display: inline-block;
  }
  .word.threat {
    color: var(--threat);
  }
  .word.warn {
    color: var(--warn);
  }
  .cursor {
    color: var(--safe);
    animation: blink 1.05s steps(1) infinite;
    margin-left: 0.08em;
  }
  @keyframes blink {
    50% {
      opacity: 0;
    }
  }
  .sentence {
    margin: 14px 0 0 4px;
    font-size: 16px;
    color: var(--text-dim);
    max-width: 560px;
  }
  .problems {
    margin: 8px 0 0 4px;
    padding: 0;
    list-style: none;
    color: var(--text-dim);
    font-size: 13px;
  }
  .problems li::before {
    content: '';
    display: inline-block;
    width: 5px;
    height: 5px;
    border-radius: 50%;
    background: var(--warn);
    margin-right: 9px;
    vertical-align: middle;
  }
  .setup {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 18px 0 0 4px;
    max-width: 760px;
  }
  .setup code {
    flex: 1;
    min-width: 0;
    padding: 9px 12px;
    background: var(--bg-sunk);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    font-size: 12.5px;
    overflow-x: auto;
    white-space: nowrap;
    user-select: text;
  }
  .log {
    list-style: none;
    margin: 16px 0 0 4px;
    padding: 0;
    font-size: 11.5px;
    color: var(--text-faint);
    max-width: 640px;
  }
  .log li {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .log li:last-child {
    color: var(--text-dim);
  }
  .log span {
    color: var(--safe);
  }
  .meter {
    position: absolute;
    right: var(--pad);
    bottom: 28px;
    width: 260px;
    padding-left: 22px;
    border-left: 1px solid var(--line-strong);
    isolation: isolate;
  }
  /* Weicher, leicht durchscheinender Verlauf hinter dem Messwerk, damit die Zahlen vor dem Feld lesbar bleiben */
  .meter::before {
    content: '';
    position: absolute;
    inset: -48px calc(-1 * var(--pad)) -36px -70px;
    z-index: -1;
    pointer-events: none;
    background: radial-gradient(ellipse 72% 70% at 62% 55%, color-mix(in srgb, var(--bg) 90%, transparent) 0%, color-mix(in srgb, var(--bg) 78%, transparent) 55%, transparent 100%);
  }
  .pct {
    font-size: 64px;
    line-height: 0.9;
    letter-spacing: -0.05em;
    font-weight: 300;
    color: var(--safe);
    transition: color var(--t-normal) ease;
  }
  .pct.paused {
    color: var(--warn);
  }
  .pct small {
    font-size: 22px;
    margin-left: 4px;
    color: var(--text-dim);
  }
  .bar {
    height: 2px;
    margin-top: 12px;
    background: var(--line);
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    background: var(--safe);
    transform-origin: left;
    transition:
      transform 500ms var(--ease-out),
      background-color var(--t-normal) ease;
  }
  .bar span.paused {
    background: var(--warn);
  }
  dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 6px 16px;
    margin: 16px 0 0;
    font-size: 13px;
  }
  dt {
    color: var(--text-faint);
  }
  dd {
    margin: 0;
    text-align: right;
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
  dd span {
    color: var(--text-faint);
  }
  dd.seg {
    color: var(--safe);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .hot {
    color: var(--threat) !important;
  }
  .warnc {
    color: var(--warn);
  }
  .ticker {
    display: flex;
    align-items: center;
    gap: 14px;
    height: 74px;
    padding: 0 var(--pad);
    border-top: 1px solid var(--line);
    font-size: 12.5px;
    color: var(--text-dim);
    overflow: hidden;
  }
  .ticker .path {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .band {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    border-top: 1px solid var(--line);
  }
  .cell {
    display: flex;
    flex-direction: column;
    gap: 3px;
    padding: 16px 20px 16px var(--pad);
    border-right: 1px solid var(--line);
    min-width: 0;
    transition: background-color var(--t-normal) ease;
  }
  .cell:hover {
    background: var(--bg-raised);
  }
  .cell + .cell {
    padding-left: 20px;
  }
  .cell:last-child {
    border-right: 0;
  }
  .val {
    font-size: 16px;
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .sub {
    font-size: 12.5px;
    color: var(--text-faint);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .actions {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    padding: 18px var(--pad) 22px;
    border-top: 1px solid var(--line);
  }
  .hint {
    color: var(--text-faint);
    font-size: 13px;
  }

  /* Orbit: Status mittig im Kreis, Messwerk rechts oben */
  .look-orbit .status {
    left: 50%;
    top: 50%;
    bottom: auto;
    right: auto;
    transform: translate(-50%, -50%);
    text-align: center;
    width: min(380px, 60%);
  }
  .look-orbit .word {
    justify-content: center;
    font-size: calc(clamp(40px, 5vw, 68px) * var(--display-scale));
  }
  .look-orbit .sentence {
    margin: 10px auto 0;
    font-size: 13.5px;
  }
  .look-orbit .setup,
  .look-orbit .problems {
    display: none;
  }
  .look-orbit .meter {
    top: 24px;
    bottom: auto;
    width: 220px;
  }
  .look-orbit .actions {
    justify-content: center;
  }
  .look-orbit .actions .hint {
    width: 100%;
    text-align: center;
  }

  /* Terminal: Statuswort klein und kantig, Messwerk als Tabelle */
  .look-terminal .word {
    font-size: calc(clamp(56px, 8vw, 110px) * var(--display-scale));
  }
  .look-terminal .meter {
    border-left-style: dashed;
  }
  .look-terminal .pct {
    font-weight: 600;
  }
  .look-terminal .cell {
    border-right-style: dashed;
  }

  /* Blaupause: Statuswort als Umriss wie gezeichnet */
  .look-blaupause .word {
    -webkit-text-stroke: 1.6px var(--text);
    color: transparent;
  }
  .look-blaupause .word.threat {
    -webkit-text-stroke-color: var(--threat);
  }
  .look-blaupause .word.warn {
    -webkit-text-stroke-color: var(--warn);
  }
  .look-blaupause .status {
    bottom: 22px;
  }
  .look-blaupause .meter {
    background: var(--bg);
    padding: 14px 0 0 22px;
  }

  @media (max-width: 980px) {
    .band {
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }
    .cell:nth-child(3) {
      border-right: 0;
    }
    .cell:nth-child(n + 4) {
      border-top: 1px solid var(--line);
    }
    .status {
      right: var(--pad);
    }
    .meter {
      top: 24px;
      bottom: auto;
    }
  }
</style>

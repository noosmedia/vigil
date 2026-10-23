<script lang="ts">
  // Look „Blaupause“: technische Zeichnung. Die Ordner sind Flächen nach Dateimenge,
  // die Prüfung schraffiert sie Fläche für Fläche, ein Fadenkreuz zeigt die Position.
  import { onMount } from 'svelte'
  import { frontPosition, bands, loop, motionReduced, type SceneProps } from './scene'
  import type { Segment } from '../lib/types'

  let {
    mode,
    progress = 0,
    segments = [],
    segmentIndex = 0,
    scanned = 0,
    threats = 0,
    pulse = 0,
    labels = [],
    fallback = [],
    threatPaths = [],
  }: SceneProps & { fallback?: Segment[]; threatPaths?: string[] } = $props()

  let host: HTMLDivElement
  let W = $state(800)
  let H = $state(400)
  let cross = $state({ x: 0.5, y: 0.5 })
  let pingKey = $state(0)
  let lastPulse = 0

  interface Cell {
    x: number
    y: number
    w: number
    h: number
    label: string
    files: number
    path: string | null
    index: number
  }

  // Unten bleibt Platz für Statuswort und Satz
  const PAD = $derived({ l: 28, r: 28, t: 54, b: Math.min(170, Math.max(40, H * 0.36)) })
  const scanning = $derived(mode === 'scanning' || mode === 'paused')
  const source = $derived<Segment[]>(segments.length ? segments : fallback)
  const names = $derived(segments.length ? labels : fallback.map((s) => s.label))

  // Flächen nach Dateimenge aufteilen, abwechselnd waagrecht und senkrecht
  function split(items: { w: number; i: number }[], x: number, y: number, w: number, h: number, out: { i: number; x: number; y: number; w: number; h: number }[]) {
    if (items.length === 0) return
    if (items.length === 1) {
      out.push({ i: items[0].i, x, y, w, h })
      return
    }
    const total = items.reduce((a, b) => a + b.w, 0)
    let acc = 0
    let cut = 0
    for (; cut < items.length - 1; cut++) {
      if (acc + items[cut].w > total / 2) break
      acc += items[cut].w
    }
    if (cut === 0) {
      acc = items[0].w
      cut = 1
    }
    const share = acc / total
    if (w >= h) {
      split(items.slice(0, cut), x, y, w * share, h, out)
      split(items.slice(cut), x + w * share, y, w * (1 - share), h, out)
    } else {
      split(items.slice(0, cut), x, y, w, h * share, out)
      split(items.slice(cut), x, y + h * share, w, h * (1 - share), out)
    }
  }

  const cells = $derived.by<Cell[]>(() => {
    const items = source.map((s, i) => ({ w: Math.max(1, Math.sqrt(Math.max(1, s.files))), i }))
    const out: { i: number; x: number; y: number; w: number; h: number }[] = []
    split(items, PAD.l, PAD.t, Math.max(10, W - PAD.l - PAD.r), Math.max(10, H - PAD.t - PAD.b), out)
    return out.map((o) => ({ ...o, label: names[o.i] ?? source[o.i].label, files: source[o.i].files, path: source[o.i].path, index: o.i }))
  })

  // Anteil der aktuellen Fläche, der schon geprüft ist
  const activeFrac = $derived.by(() => {
    if (!scanning || !segments.length) return 0
    const b = bands(segments, labels)
    const pos = frontPosition(segments, b, segmentIndex, scanned, progress)
    const band = b[segmentIndex ?? 0]
    return band ? Math.min(1, Math.max(0, (pos - band.start) / Math.max(0.0001, band.end - band.start))) : progress
  })

  const totalFiles = $derived(source.reduce((a, s) => a + s.files, 0))
  const active = $derived(cells.find((c) => c.index === segmentIndex) ?? null)

  function cellState(c: Cell): 'done' | 'active' | 'open' | 'idle' {
    if (!scanning) return 'idle'
    if (c.index < (segmentIndex ?? 0)) return 'done'
    if (c.index === segmentIndex) return 'active'
    return 'open'
  }

  function hasThreat(c: Cell) {
    return threatPaths.some((p) => c.path && (p === c.path || p.startsWith(c.path.endsWith('/') ? c.path : c.path + '/')))
  }

  // Fadenkreuz: folgt der Schraffurkante oder wandert ruhig über die Zeichnung
  onMount(() => {
    const ctl = loop(host, (now, reduced) => {
      if (scanning && active) {
        cross = { x: (active.x + active.w * activeFrac) / W, y: (active.y + active.h / 2) / H }
      } else if (!reduced) {
        const t = now / 1000
        cross = { x: 0.5 + 0.32 * Math.sin(t * 0.13), y: 0.52 + 0.22 * Math.sin(t * 0.21 + 1) }
      }
    })
    return () => ctl.stop()
  })

  $effect(() => {
    if (pulse !== lastPulse) {
      lastPulse = pulse
      pingKey++
    }
  })

  const fmt = (n: number) => new Intl.NumberFormat(document.documentElement.lang === 'en' ? 'en-GB' : 'de-DE').format(n)
  const reduced = motionReduced()
</script>

<div class="scene" bind:this={host} bind:clientWidth={W} bind:clientHeight={H} aria-hidden="true" class:counting={mode === 'counting'}>
  <svg width={W} height={H} viewBox="0 0 {W} {H}">
    <defs>
      <pattern id="bp-hatch" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
        <line x1="0" y1="0" x2="0" y2="7" class="hatch-line" />
      </pattern>
      <pattern id="bp-hatch-warn" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
        <line x1="0" y1="0" x2="0" y2="7" class="hatch-line warn" />
      </pattern>
    </defs>

    <!-- Maßkette über der Zeichnung mit Gesamtzahl der Dateien -->
    <g class="dim">
      <line x1={PAD.l} y1="30" x2={W - PAD.r} y2="30" />
      <line x1={PAD.l} y1="24" x2={PAD.l} y2="36" />
      <line x1={W - PAD.r} y1="24" x2={W - PAD.r} y2="36" />
      {#if totalFiles > 0}
        <rect x={W / 2 - 70} y="22" width="140" height="16" class="dim-bg" />
        <text x={W / 2} y="34" text-anchor="middle">{fmt(totalFiles)}</text>
      {/if}
    </g>

    {#each cells as c, i (c.index + ':' + c.label)}
      {@const st = cellState(c)}
      {@const threat = hasThreat(c)}
      <g class="cell {st}" class:threat style="--d: {i * 70}ms">
        {#if st === 'done' || st === 'idle'}
          <rect x={c.x + 3} y={c.y + 3} width={Math.max(0, c.w - 6)} height={Math.max(0, c.h - 6)} fill="url(#bp-hatch)" class="fill" />
        {:else if st === 'active'}
          <rect
            x={c.x + 3}
            y={c.y + 3}
            width={Math.max(0, c.w - 6)}
            height={Math.max(0, c.h - 6)}
            fill={mode === 'paused' ? 'url(#bp-hatch-warn)' : 'url(#bp-hatch)'}
            class="fill grow"
            style="transform: scaleX({activeFrac}); transform-origin: {c.x + 3}px 0px"
          />
        {/if}
        <rect x={c.x + 3} y={c.y + 3} width={Math.max(0, c.w - 6)} height={Math.max(0, c.h - 6)} class="frame" pathLength="100" />
        {#if c.w > 70 && c.h > 34}
          <text x={c.x + 11} y={c.y + 20} class="name">{c.label.length > Math.floor(c.w / 7) ? c.label.slice(0, Math.max(3, Math.floor(c.w / 7) - 1)) + '…' : c.label}</text>
          {#if c.h > 52}<text x={c.x + 11} y={c.y + 35} class="count">{fmt(c.files)}</text>{/if}
        {/if}
        {#if threat}
          <line x1={c.x + 10} y1={c.y + 10} x2={c.x + c.w - 10} y2={c.y + c.h - 10} class="x" />
          <line x1={c.x + c.w - 10} y1={c.y + 10} x2={c.x + 10} y2={c.y + c.h - 10} class="x" />
        {/if}
      </g>
    {/each}

    <!-- Fadenkreuz mit Hilfslinien und Koordinate -->
    <g class="cross" class:paused={mode === 'paused'} class:hot={mode === 'threat' || (threats > 0 && scanning)}>
      <line x1={PAD.l} y1={cross.y * H} x2={W - PAD.r} y2={cross.y * H} class="guide" />
      <line x1={cross.x * W} y1={PAD.t} x2={cross.x * W} y2={H - PAD.b} class="guide" />
      <circle cx={cross.x * W} cy={cross.y * H} r="9" />
      <line x1={cross.x * W - 15} y1={cross.y * H} x2={cross.x * W + 15} y2={cross.y * H} />
      <line x1={cross.x * W} y1={cross.y * H - 15} x2={cross.x * W} y2={cross.y * H + 15} />
      <text x={cross.x * W + 14} y={cross.y * H - 12}>{scanning ? `${Math.round(activeFrac * 100)} %` : `${cross.x.toFixed(2)} · ${cross.y.toFixed(2)}`}</text>
    </g>

    {#key pingKey}
      {#if pingKey > 0 && !reduced}
        <circle cx={cross.x * W} cy={cross.y * H} r="10" class="ping" />
      {/if}
    {/key}
  </svg>
</div>

<style>
  .scene {
    position: absolute;
    inset: 0;
    overflow: hidden;
  }
  svg {
    display: block;
  }
  .dim line,
  .dim text {
    stroke: var(--text-faint);
    fill: var(--text-faint);
    stroke-width: 1;
    font: 500 10.5px var(--font-mono);
  }
  .dim text {
    stroke: none;
  }
  .dim-bg {
    fill: var(--bg);
    stroke: none;
  }
  .hatch-line {
    stroke: var(--safe);
    stroke-width: 1.1;
  }
  .hatch-line.warn {
    stroke: var(--warn);
  }
  .frame {
    fill: none;
    stroke: var(--text);
    stroke-opacity: 0.45;
    stroke-width: 1;
    stroke-dasharray: 100;
    stroke-dashoffset: 0;
    transition: stroke-opacity var(--t-normal) ease;
  }
  .counting .frame {
    animation: draw 900ms var(--ease-out) both;
    animation-delay: var(--d);
  }
  @keyframes draw {
    from {
      stroke-dashoffset: 100;
    }
  }
  .fill {
    opacity: 0.18;
    transition: opacity 600ms ease;
  }
  .cell.done .fill {
    opacity: 0.45;
  }
  .cell.active .fill {
    opacity: 0.75;
  }
  .grow {
    transition: transform 500ms var(--ease-out);
  }
  .cell.active .frame {
    stroke: var(--safe);
    stroke-opacity: 0.95;
    stroke-width: 1.5;
  }
  .cell.open .frame {
    stroke-dasharray: 3 4;
    stroke-opacity: 0.35;
  }
  .name,
  .count {
    font: 600 11px var(--font-mono);
    fill: var(--text);
    opacity: 0.8;
  }
  .count {
    font-weight: 400;
    opacity: 0.5;
  }
  .cell.threat .frame {
    stroke: var(--threat);
    stroke-opacity: 1;
  }
  .x {
    stroke: var(--threat);
    stroke-width: 1.5;
    opacity: 0.8;
  }
  .cross line,
  .cross circle {
    stroke: var(--safe);
    stroke-width: 1;
    fill: none;
  }
  .cross .guide {
    stroke-dasharray: 2 5;
    opacity: 0.35;
  }
  .cross text {
    font: 500 10.5px var(--font-mono);
    fill: var(--safe);
  }
  .cross.paused line,
  .cross.paused circle {
    stroke: var(--warn);
  }
  .cross.paused text {
    fill: var(--warn);
  }
  .cross.hot circle {
    stroke: var(--threat);
  }
  .ping {
    fill: none;
    stroke: var(--safe);
    animation: ping 1200ms var(--ease-out) forwards;
    transform-box: fill-box;
    transform-origin: center;
  }
  @keyframes ping {
    to {
      transform: scale(9);
      opacity: 0;
    }
  }
</style>

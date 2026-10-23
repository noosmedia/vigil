<script lang="ts">
  // Look „Terminal“: ein Zeichenfeld im Raster der Festbreitenschrift.
  // Geprüfte Spalten werden zu ruhigen Punkten, an der Front flackern gelesene Bytes.
  import { onMount } from 'svelte'
  import { bands, fitCanvas, frontPosition, loop, readColors, seeded, type Band, type Colors, type SceneProps } from './scene'

  let { mode, progress = 0, segments = [], segmentIndex = 0, scanned = 0, threats = 0, pulse = 0, labels = [] }: SceneProps = $props()

  let canvas: HTMLCanvasElement
  let host: HTMLDivElement
  let W = 0
  let H = 0
  let dpr = 1
  let cols = 0
  let rows = 0
  let noise: Float32Array = new Float32Array(0)
  let seedCells: Float32Array = new Float32Array(0)
  let colors: Colors = readColors()
  // Für die Anzeige der Rasterzeilen: heller Grund ohne Raster
  let light = $state(colors.light)
  // Zeichen und Linien auf hellem Grund etwas kräftiger
  const boost = (a: number) => Math.min(1, a * colors.gain)
  let shown = 0
  let clock = 0
  let lastNow = 0
  let lastPulse = 0
  let pingAt = -1e9
  let ping = { c: 0, r: 0 }
  let bloomAt = -1e9
  let lastMode: string | null = null
  let ctl: { kick: () => void; stop: () => void } | null = null

  const CW = 9
  const CH = 16
  const HEX = '0123456789abcdef'
  const layout = $derived<Band[]>(bands(segments, labels))

  function build() {
    ;({ W, H, dpr } = fitCanvas(host, canvas))
    cols = Math.ceil(W / CW)
    rows = Math.ceil(H / CH)
    const rnd = seeded(4242)
    noise = new Float32Array(cols * rows)
    seedCells = new Float32Array(cols * rows)
    for (let i = 0; i < noise.length; i++) {
      noise[i] = rnd()
      seedCells[i] = rnd()
    }
  }

  function draw(now: number, reduced: boolean) {
    const ctx = canvas.getContext('2d')
    if (!ctx || !cols) return
    const dt = lastNow ? Math.min(0.05, (now - lastNow) / 1000) : 0
    lastNow = now
    clock += dt * (mode === 'paused' ? 0.1 : 1)
    const t = reduced ? 0 : clock
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, W, H)
    // Auf hellem Grund kräftigere Zeichen
    ctx.font = `${colors.light ? 600 : 500} 12px "JetBrains Mono Variable", monospace`
    ctx.textBaseline = 'top'

    const scanning = mode === 'scanning' || mode === 'paused'
    const target = scanning ? frontPosition(segments, layout, segmentIndex, scanned, progress) : 0
    shown += (target - shown) * (reduced ? 1 : 0.08)
    const frontCol = Math.floor(shown * cols)
    const accent = mode === 'warn' || mode === 'paused' ? colors.warn : colors.safe
    const bloom = Math.max(0, 1 - (now - bloomAt) / 1200)
    const bloomCol = Math.floor((1 - bloom) * (cols + 20)) - 10

    for (let r = 2; r < rows - 1; r++) {
      for (let c = 0; c < cols; c++) {
        const i = r * cols + c
        const n = noise[i]
        const x = c * CW
        const y = r * CH
        let alpha = 0
        let rgb = colors.dot
        let glyph = ''
        if (scanning) {
          if (c < frontCol) {
            alpha = 0.18 + n * 0.25
            rgb = accent
          } else if (c === frontCol) {
            glyph = mode === 'paused' ? (Math.floor(now / 450) % 2 ? '‖' : ' ') : '█'
            alpha = 0.9
            rgb = accent
          } else if (c < frontCol + 6) {
            if (seedCells[i] > 0.45) {
              glyph = HEX[Math.floor((seedCells[i] * 97 + t * 23) % 16)]
              alpha = (1 - (c - frontCol) / 6) * 0.75
            }
          } else {
            alpha = n > 0.72 ? 0.12 : 0
          }
        } else if (mode === 'counting') {
          if (seedCells[i] > 0.82) {
            glyph = HEX[Math.floor((seedCells[i] * 131 + t * 18) % 16)]
            alpha = 0.15 + 0.4 * Math.abs(Math.sin(t * 3 + n * 20))
          }
        } else {
          // Ruhiges Rauschen, das langsam durchs Feld wandert
          const v = 0.5 + 0.5 * Math.sin(c * 0.11 + t * 0.35 + n * 2) * Math.cos(r * 0.17 - t * 0.22)
          if (v > 0.78) {
            // Hell wie ein Papierausdruck: blasse Zeichen eines Speicherauszugs statt winziger Doppelpunkte
            glyph = colors.light ? HEX[Math.floor(seedCells[i] * 16)] : v > 0.93 ? ':' : ''
            alpha = (v - 0.78) * 2.6
            rgb = v > 0.9 && mode !== 'threat' ? accent : colors.dot
          }
        }
        if (bloom > 0 && Math.abs(c - bloomCol) < 3) {
          glyph = '#'
          alpha = Math.max(alpha, bloom * 0.9)
          rgb = accent
        }
        if (alpha <= 0.02) continue
        ctx.globalAlpha = boost(Math.min(1, alpha))
        ctx.fillStyle = `rgb(${rgb})`
        if (glyph) ctx.fillText(glyph, x, y)
        else ctx.fillRect(x + 3, y + 7, 2, 2)
      }
    }

    // Kopfzeile mit Bereichen in eckigen Klammern
    if (scanning && layout.length) {
      for (let k = 0; k < layout.length; k++) {
        const b = layout[k]
        const c0 = Math.floor(b.start * cols)
        const c1 = Math.floor(b.end * cols)
        const room = c1 - c0 - 1
        if (room < 5) continue
        const active = k === segmentIndex
        const done = k < (segmentIndex ?? 0)
        let text = b.label
        if (text.length > room - 2) text = text.slice(0, Math.max(1, room - 3)) + '…'
        ctx.globalAlpha = boost(active ? 1 : done ? 0.6 : 0.35)
        ctx.fillStyle = `rgb(${active ? accent : colors.dot})`
        ctx.fillText(`[${text}]`, c0 * CW, 6)
        if (k > 0) {
          ctx.globalAlpha = boost(0.12)
          for (let r = 2; r < rows - 1; r += 2) ctx.fillText('│', c0 * CW, r * CH)
        }
      }
    }

    // Funde als blinkende Markierung
    const n = mode === 'threat' || scanning ? Math.min(threats, 6) : 0
    for (let k = 0; k < n; k++) {
      const c = Math.floor(cols * (0.55 + ((k * 0.618) % 0.4)))
      const r = 4 + Math.floor(((k * 0.37 + 0.2) % 1) * (rows - 8))
      const on = Math.floor(now / 380 + k) % 2 === 0
      ctx.globalAlpha = 1
      ctx.fillStyle = `rgb(${colors.threat})`
      ctx.fillText(on ? '[×]' : '[ ]', c * CW - CW, r * CH)
    }

    // Wächter-Ereignis: kurz aufleuchtendes Zeichen
    const pk = Math.max(0, 1 - (now - pingAt) / 900)
    if (pk > 0) {
      ctx.globalAlpha = boost(pk)
      ctx.fillStyle = `rgb(${colors.safe})`
      ctx.fillText('+', ping.c * CW, ping.r * CH)
    }
    ctx.globalAlpha = 1
  }

  $effect(() => {
    if (pulse !== lastPulse) {
      lastPulse = pulse
      ping = { c: Math.floor(Math.random() * cols), r: 3 + Math.floor(Math.random() * Math.max(1, rows - 6)) }
      pingAt = performance.now()
      ctl?.kick()
    }
  })

  $effect(() => {
    const m = mode
    if (lastMode && (lastMode === 'scanning' || lastMode === 'paused') && m !== 'scanning' && m !== 'paused') bloomAt = performance.now()
    lastMode = m
    ctl?.kick()
  })

  $effect(() => {
    void progress
    void scanned
    ctl?.kick()
  })

  onMount(() => {
    colors = readColors()
    light = colors.light
    build()
    const ro = new ResizeObserver(() => {
      build()
      ctl?.kick()
    })
    ro.observe(host)
    const mo = new MutationObserver(() => {
      colors = readColors(colors)
      light = colors.light
      ctl?.kick()
    })
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme', 'data-palette'] })
    ctl = loop(host, draw)
    return () => {
      ctl?.stop()
      ro.disconnect()
      mo.disconnect()
    }
  })
</script>

<div class="scene" bind:this={host} aria-hidden="true">
  <canvas bind:this={canvas}></canvas>
  {#if !light}<div class="scan"></div>{/if}
</div>

<style>
  .scene {
    position: absolute;
    inset: 0;
    overflow: hidden;
    contain: strict;
  }
  canvas {
    display: block;
  }
  /* Feine Rasterzeilen, still und ohne Bewegung */
  .scan {
    position: absolute;
    inset: 0;
    pointer-events: none;
    background: repeating-linear-gradient(to bottom, rgba(0, 0, 0, 0.09) 0 1px, transparent 1px 3px);
  }
</style>

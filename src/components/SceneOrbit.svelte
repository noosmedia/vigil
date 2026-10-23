<script lang="ts">
  // Look „Orbit“: Ringe aus Punkten kreisen um den Status in der Mitte.
  // Eine Prüfung füllt die Ringe wie ein Zifferblatt, die Ordner liegen als Bögen auf dem äußeren Ring.
  import { onMount } from 'svelte'
  import { bands, fitCanvas, frontPosition, loop, readColors, seeded, softGlow, type Band, type Colors, type SceneProps } from './scene'

  let { mode, progress = 0, segments = [], segmentIndex = 0, scanned = 0, threats = 0, pulse = 0, labels = [] }: SceneProps = $props()

  let canvas: HTMLCanvasElement
  let host: HTMLDivElement

  interface Dot {
    ring: number
    angle: number
    base: number
    phase: number
  }
  interface Ring {
    r: number
    speed: number
  }

  let dots: Dot[] = []
  let ringsGeo: Ring[] = []
  let W = 0
  let H = 0
  let dpr = 1
  let cx = 0
  let cy = 0
  let colors: Colors = readColors()
  // Linien und Beschriftungen auf hellem Grund etwas kräftiger
  const boost = (a: number) => Math.min(1, a * colors.gain)
  let shown = 0
  let clock = 0
  let lastNow = 0
  let timeScale = 1
  let flashAt = -1e9
  let flashKind: 'safe' | 'threat' | 'bloom' = 'safe'
  let lastPulse = 0
  let lastThreats = 0
  let lastMode: string | null = null
  let ctl: { kick: () => void; stop: () => void } | null = null

  const layout = $derived<Band[]>(bands(segments, labels))
  const TAU = Math.PI * 2

  function build() {
    ;({ W, H, dpr } = fitCanvas(host, canvas))
    cx = W / 2
    cy = H / 2
    // Platz für Ordnerbögen (26 px außerhalb) und deren Beschriftung, damit nichts abgeschnitten wird
    const rMax = Math.max(90, Math.min(W / 2 - 160, H / 2 - 52))
    const r0 = Math.max(70, Math.min(150, rMax * 0.45))
    const count = 7
    ringsGeo = []
    dots = []
    const rnd = seeded(77)
    for (let i = 0; i < count; i++) {
      const r = r0 + ((rMax - r0) * i) / (count - 1)
      ringsGeo.push({ r, speed: (i % 2 ? -1 : 1) * (0.02 + 0.012 * (count - i)) })
      const n = Math.floor((TAU * r) / 13)
      for (let k = 0; k < n; k++) dots.push({ ring: i, angle: (k / n) * TAU + rnd() * 0.02, base: 0.18 + rnd() * 0.35, phase: rnd() * TAU })
    }
  }

  function draw(now: number, reduced: boolean) {
    const ctx = canvas.getContext('2d')
    if (!ctx || !dots.length) return
    const dt = lastNow ? Math.min(0.05, (now - lastNow) / 1000) : 0
    lastNow = now
    timeScale += ((mode === 'paused' ? 0.08 : mode === 'scanning' ? 2.2 : 1) - timeScale) * 0.04
    clock += dt * timeScale
    const t = reduced ? 0 : clock

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, W, H)

    const scanning = mode === 'scanning' || mode === 'paused'
    const target = scanning ? frontPosition(segments, layout, segmentIndex, scanned, progress) : 0
    shown += (target - shown) * (reduced ? 1 : 0.06)
    const sweep = shown * TAU
    const accent = mode === 'warn' || mode === 'paused' ? colors.warn : colors.safe
    const flash = Math.max(0, 1 - (now - flashAt) / 1600)

    for (const d of dots) {
      const ring = ringsGeo[d.ring]
      const ang = d.angle + t * ring.speed
      const x = cx + Math.cos(ang - Math.PI / 2) * ring.r
      const y = cy + Math.sin(ang - Math.PI / 2) * ring.r
      if (x < -4 || x > W + 4 || y < -4 || y > H + 4) continue
      let a = d.base
      let lit = 0
      let size = 1.6
      if (scanning) {
        // Winkel des Punkts im festen Zifferblatt (oben = 0)
        const fixed = ((d.angle % TAU) + TAU) % TAU
        const behind = sweep - fixed
        if (behind >= 0) {
          const trail = Math.max(0, 1 - behind / 0.5)
          a = 0.35 + d.base * 0.4 + trail * 0.5
          lit = 0.75 + trail * 0.25
          size += trail * 1.6
        } else {
          a = d.base * 0.45
        }
      } else if (mode === 'counting') {
        const tw = Math.pow(0.5 + 0.5 * Math.sin(t * 3 + d.phase * 7), 8)
        a = d.base * 0.4 + tw * 0.6
        lit = tw * 0.6
      } else if (mode === 'safe' || mode === 'warn') {
        // Lichtwelle wandert im Kreis
        const wave = Math.pow(0.5 + 0.5 * Math.cos(ang - t * 0.6 - d.ring * 0.35), 6)
        a = d.base * 0.65 + wave * 0.5
        lit = wave
      } else {
        a = d.base * 0.4
      }
      if (flash > 0) {
        const ringDelay = d.ring / ringsGeo.length
        const w = Math.max(0, 1 - Math.abs(1 - flash - ringDelay) * 5)
        a += w * 0.7
        lit = Math.max(lit, w)
      }
      const hue = flashKind === 'threat' && flash > 0 ? colors.threat : accent
      if (colors.light) {
        // Heller Modus: runde, zarte Punkte; bewegte Punkte färben sich mit weichem Hof
        const r = size * 0.6 + lit * 0.8
        const ink = Math.min(1, a) * 0.85 * (1 - lit * 0.7)
        if (ink > 0.02) {
          ctx.globalAlpha = Math.min(1, ink)
          ctx.fillStyle = `rgb(${colors.dot})`
          ctx.beginPath()
          ctx.arc(x, y, r, 0, TAU)
          ctx.fill()
        }
        if (lit > 0.05) {
          ctx.fillStyle = `rgb(${hue})`
          ctx.globalAlpha = Math.min(1, lit * (0.55 + a * 0.6))
          ctx.beginPath()
          ctx.arc(x, y, r, 0, TAU)
          ctx.fill()
          if (lit > 0.4) {
            const s = r * 6.5
            ctx.globalAlpha = Math.min(1, (lit - 0.4) * 0.8)
            ctx.drawImage(softGlow(hue), x - s / 2, y - s / 2, s, s)
          }
        }
        continue
      }
      ctx.globalAlpha = Math.min(1, a) * (1 - lit * 0.5)
      ctx.fillStyle = `rgb(${colors.dot})`
      ctx.fillRect(x - size / 2, y - size / 2, size, size)
      if (lit > 0.05) {
        ctx.globalAlpha = Math.min(1, a * lit * 1.4)
        ctx.fillStyle = `rgb(${hue})`
        ctx.fillRect(x - size / 2, y - size / 2, size, size)
      }
    }

    const outer = ringsGeo[ringsGeo.length - 1]?.r ?? 100
    const inner = ringsGeo[0]?.r ?? 60

    // Zeiger der Prüfung
    if (scanning) {
      const a = sweep - Math.PI / 2
      const g = ctx.createLinearGradient(cx + Math.cos(a) * inner, cy + Math.sin(a) * inner, cx + Math.cos(a) * (outer + 18), cy + Math.sin(a) * (outer + 18))
      g.addColorStop(0, `rgba(${accent},0)`)
      g.addColorStop(1, `rgba(${accent},0.85)`)
      ctx.globalAlpha = 1
      ctx.strokeStyle = g
      ctx.lineWidth = 1.2
      ctx.beginPath()
      ctx.moveTo(cx + Math.cos(a) * inner, cy + Math.sin(a) * inner)
      ctx.lineTo(cx + Math.cos(a) * (outer + 18), cy + Math.sin(a) * (outer + 18))
      ctx.stroke()
    }

    // Ordner als Bögen auf einem äußeren Band, mit Beschriftung
    if (scanning && layout.length) {
      const R = outer + 26
      ctx.font = '500 10px "JetBrains Mono Variable", monospace'
      ctx.textBaseline = 'middle'
      for (let i = 0; i < layout.length; i++) {
        const b = layout[i]
        const a0 = b.start * TAU - Math.PI / 2 + 0.012
        const a1 = b.end * TAU - Math.PI / 2 - 0.012
        const active = i === segmentIndex
        const done = i < (segmentIndex ?? 0)
        ctx.globalAlpha = boost(active ? 0.95 : done ? 0.6 : 0.22)
        ctx.strokeStyle = active || done ? `rgb(${accent})` : `rgb(${colors.dot})`
        ctx.lineWidth = active ? 3 : 2
        ctx.beginPath()
        ctx.arc(cx, cy, R, a0, a1)
        ctx.stroke()
        if (a1 - a0 > 0.22 || active) {
          const mid = (a0 + a1) / 2
          const lx = cx + Math.cos(mid) * (R + 14)
          const ly = cy + Math.sin(mid) * (R + 14)
          if (lx > 10 && lx < W - 10 && ly > 8 && ly < H - 8) {
            ctx.textAlign = Math.cos(mid) > 0.2 ? 'left' : Math.cos(mid) < -0.2 ? 'right' : 'center'
            ctx.globalAlpha = boost(active ? 0.95 : done ? 0.55 : 0.35)
            ctx.fillStyle = active ? `rgb(${accent})` : `rgb(${colors.dot})`
            const text = b.label.length > 18 ? b.label.slice(0, 17) + '…' : b.label
            ctx.fillText(text, lx, ly)
          }
        }
      }
      ctx.textAlign = 'left'
    }

    // Funde als rote Trabanten mit Schweif
    const n = mode === 'threat' || scanning ? Math.min(threats, 5) : 0
    for (let i = 0; i < n; i++) {
      const ring = ringsGeo[Math.min(ringsGeo.length - 1, 2 + i)]
      const ang = t * (0.9 + i * 0.17) + i * 1.3 - Math.PI / 2
      for (let k = 0; k < 14; k++) {
        const aa = ang - k * 0.035
        ctx.globalAlpha = boost((1 - k / 14) * 0.7)
        ctx.fillStyle = `rgb(${colors.threat})`
        const s = 4 - k * 0.22
        ctx.beginPath()
        ctx.arc(cx + Math.cos(aa) * ring.r, cy + Math.sin(aa) * ring.r, Math.max(0.8, s), 0, TAU)
        ctx.fill()
      }
    }

    // Leiser Kern um das Statuswort
    ctx.globalAlpha = 1
    const core = ctx.createRadialGradient(cx, cy, 0, cx, cy, inner * 0.95)
    core.addColorStop(0, `rgba(${mode === 'threat' ? colors.threat : accent},${mode === 'threat' ? 0.1 : 0.05})`)
    core.addColorStop(1, `rgba(${accent},0)`)
    ctx.fillStyle = core
    ctx.beginPath()
    ctx.arc(cx, cy, inner * 0.95, 0, TAU)
    ctx.fill()
  }

  $effect(() => {
    if (pulse !== lastPulse) {
      lastPulse = pulse
      flashAt = performance.now()
      flashKind = 'safe'
      ctl?.kick()
    }
  })

  $effect(() => {
    if (threats > lastThreats && W > 0) {
      flashAt = performance.now()
      flashKind = 'threat'
    }
    lastThreats = threats
  })

  $effect(() => {
    const m = mode
    if (lastMode && (lastMode === 'scanning' || lastMode === 'paused') && m !== 'scanning' && m !== 'paused') {
      flashAt = performance.now()
      flashKind = m === 'threat' ? 'threat' : 'bloom'
    }
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
    build()
    const ro = new ResizeObserver(() => {
      build()
      ctl?.kick()
    })
    ro.observe(host)
    const mo = new MutationObserver(() => {
      colors = readColors(colors)
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

<div class="scene" bind:this={host} aria-hidden="true"><canvas bind:this={canvas}></canvas></div>

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
</style>

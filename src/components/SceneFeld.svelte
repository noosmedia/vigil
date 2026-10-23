<script lang="ts">
  // Look „Feld“: Lichtmarken stehen für Dateien. Ruhig atmend im geschützten Zustand,
  // während einer Prüfung beschriftete Bereiche, eine Prüffront und Teilchen, die zur Front strömen.
  import { onMount } from 'svelte'
  import { bands, fitCanvas, frontPosition, loop, readColors, seeded, smooth, softGlow, type Band, type Colors, type SceneProps } from './scene'

  let { mode, progress = 0, segments = [], segmentIndex = 0, scanned = 0, threats = 0, pulse = 0, labels = [] }: SceneProps = $props()

  let canvas: HTMLCanvasElement
  let host: HTMLDivElement

  interface Pt {
    x: number
    y: number
    base: number
    phase: number
    size: number
    hash: number
    lens: number
  }
  interface Ring {
    x: number
    y: number
    born: number
    life: number
    max: number
    kind: 'safe' | 'threat' | 'wave' | 'warn'
  }
  interface Particle {
    x: number
    y: number
    vx: number
    life: number
  }

  let pts: Pt[] = []
  let rings: Ring[] = []
  let parts: Particle[] = []
  let hot: { x: number; y: number; phase: number }[] = []
  let W = 0
  let H = 0
  let dpr = 1
  let colors: Colors = readColors()
  // Linien und Beschriftungen auf hellem Grund etwas kräftiger
  const boost = (a: number) => Math.min(1, a * colors.gain)
  const TAU = Math.PI * 2
  let shownFront = 0
  let timeScale = 1
  let clock = 0
  let lastNow = 0
  let bloomAt = -1e9
  let pointer = { x: -9999, y: -9999, active: false }
  let lastPulse = 0
  let lastMode: string | null = null
  let lastThreats = 0
  let lastRingAt = 0
  let ctl: { kick: () => void; stop: () => void } | null = null

  const layout = $derived<Band[]>(bands(segments, labels))

  function build() {
    ;({ W, H, dpr } = fitCanvas(host, canvas))
    const gap = W < 700 ? 13 : 15
    const rnd = seeded()
    const next: Pt[] = []
    for (let y = gap * 0.6; y < H; y += gap) {
      for (let x = gap * 0.6; x < W; x += gap) {
        const r = rnd()
        next.push({
          x: x + (rnd() - 0.5) * gap * 0.62,
          y: y + (rnd() - 0.5) * gap * 0.62,
          base: 0.2 + rnd() * 0.36,
          phase: rnd() * Math.PI * 2,
          size: r > 0.93 ? 2.3 : r > 0.6 ? 1.7 : 1.25,
          hash: rnd(),
          lens: 0,
        })
      }
    }
    pts = next
  }

  // Ersatzweise feste Glutpunkte, wenn keine Fundorte aus der Prüfung bekannt sind
  function hashedHot(n: number) {
    const out: { x: number; y: number; phase: number }[] = []
    for (let i = 0; i < Math.min(n, 6); i++) {
      const target = (0.37 + i * 0.618) % 1
      let best = pts[0]
      let bestD = 9
      for (const p of pts) {
        if (p.x < W * 0.42 || p.y > H * 0.7 || p.y < H * 0.16) continue
        const d = Math.abs(p.hash - target)
        if (d < bestD) {
          bestD = d
          best = p
        }
      }
      if (best) out.push({ x: best.x, y: best.y, phase: best.phase })
    }
    return out
  }

  function draw(now: number, reduced: boolean) {
    const ctx = canvas.getContext('2d')
    if (!ctx || !pts.length) return
    // Eigene Uhr: bei Pause läuft die Zeit langsamer weiter
    const dt = lastNow ? Math.min(0.05, (now - lastNow) / 1000) : 0
    lastNow = now
    const wantScale = mode === 'paused' ? 0.12 : 1
    timeScale += (wantScale - timeScale) * 0.05
    clock += dt * timeScale
    const t = reduced ? 0 : clock

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, W, H)

    const scanning = mode === 'scanning' || mode === 'paused'
    const target = scanning ? frontPosition(segments, layout, segmentIndex, scanned, progress) : 0
    shownFront += (target - shownFront) * (reduced ? 1 : 0.07)
    const front = shownFront * (W + 120) - 60
    const tint = mode === 'warn' ? colors.warn : colors.safe
    const frontRgb = mode === 'paused' ? colors.warn : colors.safe
    const bloom = Math.max(0, 1 - (now - bloomAt) / 1400)
    const bloomX = (1 - bloom) * (W + 300) - 150

    for (const p of pts) {
      const edge = smooth(0, 70, p.y) * smooth(0, 90, H - p.y) * smooth(0, 40, p.x) * smooth(0, 40, W - p.x)
      if (edge <= 0.01) continue
      const dx = p.x - pointer.x
      const dy = p.y - pointer.y
      const near = pointer.active ? Math.max(0, 1 - Math.sqrt(dx * dx + dy * dy) / 110) : 0
      p.lens += (near - p.lens) * 0.15

      let a = p.base
      let size = p.size
      let lit = 0
      if (mode === 'safe' || mode === 'warn') {
        const wave = 0.5 + 0.5 * Math.sin(t * 0.42 + p.x * 0.0065 - p.y * 0.0042 + p.phase * 0.25)
        const swell = Math.pow(wave, 4)
        a = p.base * 0.7 + swell * 0.55
        lit = swell
      } else if (mode === 'counting') {
        const tw = 0.5 + 0.5 * Math.sin(t * 2.6 + p.hash * 40)
        a = p.base * 0.35 + Math.pow(tw, 8) * 0.55
        lit = Math.pow(tw, 8) * 0.6
      } else if (scanning) {
        const d = front - p.x
        if (d > 0) {
          const trail = Math.max(0, 1 - d / 140)
          a = 0.3 + p.base * 0.45 + trail * 0.6
          lit = 0.8 + trail * 0.2
          size += trail * 1.4
        } else {
          const ahead = Math.max(0, 1 - -d / 26)
          const tw = Math.pow(0.5 + 0.5 * Math.sin(t * 1.7 + p.hash * 50), 10)
          a = p.base * 0.5 + ahead * 0.6 + tw * 0.35
          lit = Math.max(ahead, tw * 0.5)
        }
      } else if (mode === 'threat') {
        a = p.base * 0.42
      } else {
        a = p.base * 0.35
      }
      // Lichtwelle nach Abschluss einer Prüfung
      if (bloom > 0) {
        const wv = Math.max(0, 1 - Math.abs(p.x - bloomX) / 120)
        a += wv * 0.8 * bloom
        lit = Math.max(lit, wv * bloom)
        size += wv * 1.6 * bloom
      }
      a = Math.min(1, a + p.lens * 0.55) * edge

      if (colors.light) {
        // Heller Modus, „Tinte auf Papier“: runde, zarte Punkte. Was sich bewegt (Welle, Front, Maus),
        // färbt sich in der Akzentfarbe und bekommt einen weichen Hof; das ersetzt das Leuchten im Dunkeln
        lit = Math.max(lit, p.lens)
        let px = p.x
        let py = p.y
        // Unter der Maus weichen die Punkte sanft aus
        if (p.lens > 0.01) {
          const d = Math.max(1, Math.sqrt(dx * dx + dy * dy))
          px += (dx / d) * p.lens * 7
          py += (dy / d) * p.lens * 7
        }
        const r = size * 0.6 + lit * 0.9
        const ink = a * 0.85 * (1 - lit * 0.7)
        if (ink > 0.02) {
          ctx.globalAlpha = Math.min(1, ink)
          ctx.fillStyle = `rgb(${colors.dot})`
          ctx.beginPath()
          ctx.arc(px, py, r, 0, TAU)
          ctx.fill()
        }
        if (lit > 0.04) {
          ctx.fillStyle = `rgb(${scanning ? frontRgb : tint})`
          ctx.globalAlpha = Math.min(1, lit * (0.55 + a * 0.6))
          ctx.beginPath()
          ctx.arc(px, py, r, 0, TAU)
          ctx.fill()
          if (lit > 0.4) {
            const s = r * 7
            ctx.globalAlpha = Math.min(1, (lit - 0.4) * 0.9)
            ctx.drawImage(softGlow(scanning ? frontRgb : tint), px - s / 2, py - s / 2, s, s)
          }
        }
        continue
      }

      size += p.lens * 1.2
      ctx.globalAlpha = a * (1 - lit * 0.6)
      ctx.fillStyle = `rgb(${colors.dot})`
      ctx.fillRect(p.x - size / 2, p.y - size / 2, size, size)
      if (lit > 0.04) {
        ctx.globalAlpha = Math.min(1, a * lit * 1.4)
        ctx.fillStyle = `rgb(${scanning ? frontRgb : tint})`
        ctx.fillRect(p.x - size / 2, p.y - size / 2, size, size)
      }
    }

    // Bereichsgrenzen und Beschriftungen der echten Ordner
    if (scanning && layout.length > 1) {
      ctx.font = '500 10.5px "JetBrains Mono Variable", monospace'
      ctx.textBaseline = 'top'
      for (let i = 0; i < layout.length; i++) {
        const b = layout[i]
        const x0 = b.start * (W + 120) - 60
        const x1 = b.end * (W + 120) - 60
        if (i > 0 && x0 > 0 && x0 < W) {
          ctx.globalAlpha = boost(0.12)
          ctx.fillStyle = `rgb(${colors.dot})`
          for (let y = 18; y < H - 30; y += 6) ctx.fillRect(x0, y, 1, 2)
        }
        const width = x1 - Math.max(0, x0)
        if (width < 46 || x1 < 0 || x0 > W) continue
        const active = i === segmentIndex
        const done = i < (segmentIndex ?? 0)
        let text = b.label
        while (text.length > 3 && ctx.measureText(text).width > width - 14) text = text.slice(0, -2)
        if (text !== b.label) text = text.slice(0, -1) + '…'
        ctx.globalAlpha = boost(active ? 0.95 : done ? 0.55 : 0.32)
        ctx.fillStyle = active ? `rgb(${frontRgb})` : `rgb(${colors.dot})`
        ctx.fillText(text, Math.max(6, x0 + 7), 14)
        if (active) ctx.fillRect(Math.max(6, x0 + 7), 30, Math.min(width - 14, 26), 1.5)
      }
    }

    // Teilchen strömen von rechts zur Prüffront
    if (mode === 'scanning' && !reduced && front > 0 && front < W) {
      for (let k = 0; k < 3; k++) {
        if (parts.length < 140) parts.push({ x: front + 30 + Math.random() * 260, y: 40 + Math.random() * (H - 90), vx: 2 + Math.random() * 4, life: 1 })
      }
    }
    for (const q of parts) {
      q.x -= q.vx * timeScale
      if (q.x < front) q.life -= 0.2
      // In der Pause verglimmen die Teilchen
      if (mode === 'paused') q.life -= 0.04
    }
    parts = parts.filter((q) => q.life > 0 && q.x > -10)
    ctx.fillStyle = `rgb(${colors.safe})`
    for (const q of parts) {
      const dist = Math.max(0, q.x - front)
      ctx.globalAlpha = boost(Math.min(0.75, (1 - dist / 300) * 0.8) * q.life)
      ctx.fillRect(q.x, q.y, Math.min(14, 3 + q.vx * 2), 1)
    }

    // Prüffront als feine senkrechte Linie mit weichem Schein
    if (scanning && front > 0 && front < W) {
      const g = ctx.createLinearGradient(0, 0, 0, H)
      g.addColorStop(0, `rgba(${frontRgb},0)`)
      g.addColorStop(0.5, `rgba(${frontRgb},${mode === 'paused' ? 0.4 + 0.3 * Math.sin(now / 400) : 0.6})`)
      g.addColorStop(1, `rgba(${frontRgb},0)`)
      ctx.globalAlpha = 1
      ctx.fillStyle = g
      ctx.fillRect(front, 0, 1, H)
      const glow = ctx.createLinearGradient(front - 70, 0, front + 4, 0)
      glow.addColorStop(0, `rgba(${frontRgb},0)`)
      glow.addColorStop(1, `rgba(${frontRgb},0.07)`)
      ctx.fillStyle = glow
      ctx.fillRect(front - 70, 0, 74, H)
    }

    // Glühende Funde mit Wellenringen
    const glowing = hot.length ? hot : mode === 'threat' ? hashedHot(threats) : []
    for (const p of glowing) {
      const beat = 0.5 + 0.5 * Math.sin(t * 3.2 + p.phase)
      ctx.globalAlpha = boost(0.18 + beat * 0.12)
      ctx.fillStyle = `rgb(${colors.threat})`
      ctx.beginPath()
      ctx.arc(p.x, p.y, 10 + beat * 3, 0, Math.PI * 2)
      ctx.fill()
      ctx.globalAlpha = 1
      ctx.beginPath()
      ctx.arc(p.x, p.y, 3.2, 0, Math.PI * 2)
      ctx.fill()
    }
    if (glowing.length && !reduced && now - lastRingAt > 2200) {
      for (const p of glowing) rings.push({ x: p.x, y: p.y, born: now + p.phase * 60, life: 2400, max: 110, kind: 'threat' })
      lastRingAt = now
    }

    rings = rings.filter((r) => now - r.born < r.life)
    for (const r of rings) {
      const k = (now - r.born) / r.life
      if (k < 0) continue
      const e = 1 - Math.pow(1 - k, 3)
      ctx.globalAlpha = boost((1 - k) * (r.kind === 'wave' ? 0.35 : 0.6))
      ctx.strokeStyle = `rgb(${r.kind === 'threat' ? colors.threat : r.kind === 'warn' ? colors.warn : colors.safe})`
      ctx.lineWidth = r.kind === 'wave' ? 1 : 1.2
      ctx.beginPath()
      ctx.arc(r.x, r.y, e * r.max, 0, Math.PI * 2)
      ctx.stroke()
    }
    ctx.globalAlpha = 1
  }

  // Wächter-Ereignis: kurzer Lichtring an zufälliger Stelle
  $effect(() => {
    if (pulse !== lastPulse) {
      lastPulse = pulse
      if (pts.length) {
        const p = pts[Math.floor(Math.random() * pts.length)]
        rings.push({ x: p.x, y: p.y, born: performance.now(), life: 1600, max: 70, kind: 'safe' })
        ctl?.kick()
      }
    }
  })

  // Neuer Fund während der Prüfung: Druckwelle an der Front, Glutpunkt bleibt stehen
  $effect(() => {
    if (threats > lastThreats && (mode === 'scanning' || mode === 'paused') && W > 0) {
      const x = Math.max(20, Math.min(W - 20, shownFront * (W + 120) - 60))
      const y = H * (0.25 + Math.random() * 0.45)
      hot = [...hot, { x, y, phase: Math.random() * 6 }].slice(-6)
      const now = performance.now()
      rings.push({ x, y, born: now, life: 1500, max: 200, kind: 'threat' })
      rings.push({ x, y, born: now + 180, life: 1500, max: 120, kind: 'threat' })
    }
    if (threats === 0) hot = []
    lastThreats = threats
  })

  // Zustandswechsel: Welle; Ende einer Prüfung: Lichtwelle über das ganze Feld
  $effect(() => {
    const m = mode
    if (lastMode !== null && m !== lastMode && W > 0) {
      const now = performance.now()
      if ((lastMode === 'scanning' || lastMode === 'paused') && (m === 'safe' || m === 'threat' || m === 'warn')) bloomAt = now
      else rings.push({ x: W * 0.18, y: H * 0.72, born: now, life: 1800, max: Math.hypot(W, H), kind: m === 'paused' ? 'warn' : 'wave' })
    }
    lastMode = m
    ctl?.kick()
  })

  $effect(() => {
    void progress
    void scanned
    void segmentIndex
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

  function onMove(e: PointerEvent) {
    const r = host.getBoundingClientRect()
    pointer = { x: e.clientX - r.left, y: e.clientY - r.top, active: true }
    ctl?.kick()
  }
</script>

<div class="scene" bind:this={host} onpointermove={onMove} onpointerleave={() => (pointer = { ...pointer, active: false })} aria-hidden="true">
  <canvas bind:this={canvas}></canvas>
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
</style>

// Gemeinsame Grundlagen der vier Statusbilder (Feld, Orbit, Terminal, Blaupause)

import type { Segment } from '../lib/types'

export type SceneMode = 'safe' | 'warn' | 'threat' | 'counting' | 'scanning' | 'paused' | 'setup'

export interface SceneProps {
  mode: SceneMode
  progress?: number
  segments?: Segment[]
  segmentIndex?: number
  scanned?: number
  threats?: number
  pulse?: number
  labels?: string[]
}

export interface Colors {
  dot: string
  safe: string
  warn: string
  threat: string
  text: string
  bg: string
  // Heller Grund: dunkle Punkte leuchten dort nicht von selbst. Die Looks zeichnen dann runde,
  // zarte Punkte, und was sich bewegt, färbt sich mit weichem Hof (light). gain hebt Linien und Beschriftungen an.
  gain: number
  light: boolean
}

// Farben aus den CSS-Variablen des aktiven Farbschemas
export function readColors(prev?: Colors): Colors {
  const cs = getComputedStyle(document.documentElement)
  const v = (n: string, f: string) => cs.getPropertyValue(n).trim() || f
  return {
    dot: v('--field-dot-rgb', prev?.dot ?? '221,228,224'),
    safe: v('--safe-rgb', prev?.safe ?? '143,227,184'),
    warn: v('--warn-rgb', prev?.warn ?? '232,193,112'),
    threat: v('--threat-rgb', prev?.threat ?? '255,107,87'),
    text: v('--text', '#dde4e0'),
    bg: v('--bg', '#151a19'),
    gain: parseFloat(v('--scene-gain', '1')) || 1,
    light: v('--scene-light', '0') === '1',
  }
}

// Weicher Schein als vorgezeichnetes Bild je Farbe: Verlauf von der Mitte bis ganz durchsichtig am Rand
const glowCache = new Map<string, HTMLCanvasElement>()
export function softGlow(rgb: string): HTMLCanvasElement {
  let c = glowCache.get(rgb)
  if (c) return c
  c = document.createElement('canvas')
  c.width = c.height = 64
  const g = c.getContext('2d')!
  const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32)
  grad.addColorStop(0, `rgba(${rgb},0.55)`)
  grad.addColorStop(0.35, `rgba(${rgb},0.22)`)
  grad.addColorStop(0.7, `rgba(${rgb},0.06)`)
  grad.addColorStop(1, `rgba(${rgb},0)`)
  g.fillStyle = grad
  g.fillRect(0, 0, 64, 64)
  glowCache.set(rgb, c)
  return c
}

// Bewegung reduziert: Systemvorgabe oder Einstellung „Ruhig“
export function motionReduced(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches || document.documentElement.dataset.motion === 'ruhig'
}

export interface Band {
  start: number
  end: number
  label: string
  files: number
}

// Bereiche als Anteile 0..1; Wurzel der Dateizahl, damit kleine Bereiche sichtbar bleiben
export function bands(segments: Segment[] | undefined, labels: string[]): Band[] {
  if (!segments || segments.length === 0) return []
  const weights = segments.map((s) => Math.max(Math.sqrt(Math.max(1, s.files)), 1))
  const sum = weights.reduce((a, b) => a + b, 0)
  const minShare = Math.min(0.035, 1 / segments.length)
  const shares = weights.map((w) => Math.max(w / sum, minShare))
  const total = shares.reduce((a, b) => a + b, 0)
  let acc = 0
  return segments.map((s, i) => {
    const start = acc / total
    acc += shares[i]
    return { start, end: acc / total, label: labels[i] ?? s.label, files: s.files }
  })
}

// Position der Prüffront 0..1 über die Bereiche hinweg
export function frontPosition(segments: Segment[] | undefined, b: Band[], index: number | undefined, scanned: number | undefined, progress: number): number {
  if (!segments || segments.length === 0 || b.length === 0) return progress
  const i = Math.min(Math.max(0, index ?? 0), segments.length - 1)
  const before = segments.slice(0, i).reduce((a, s) => a + s.files, 0)
  const frac = segments[i].files > 0 ? Math.min(1, Math.max(0, ((scanned ?? 0) - before) / segments[i].files)) : 1
  return b[i].start + (b[i].end - b[i].start) * frac
}

// Gleichmäßiger Zufall mit festem Startwert (gleiches Bild bei jedem Aufbau)
export function seeded(seed = 1337) {
  let s = seed
  return () => {
    s = (s * 16807) % 2147483647
    return (s - 1) / 2147483646
  }
}

export function smooth(e0: number, e1: number, x: number) {
  const t = Math.min(1, Math.max(0, (x - e0) / (e1 - e0)))
  return t * t * (3 - 2 * t)
}

/** Zeichenschleife mit Pause bei unsichtbarem Fenster und ruhiger Bewegung */
export function loop(host: HTMLElement, frame: (now: number, reduced: boolean) => void) {
  let raf = 0
  let visible = true
  let alive = true
  let reduced = motionReduced()
  const tick = (now: number) => {
    raf = 0
    if (!alive || !visible || document.hidden) return
    frame(now, reduced)
    if (!reduced) raf = requestAnimationFrame(tick)
  }
  const kick = () => {
    if (!raf && alive && visible && !document.hidden) raf = requestAnimationFrame(tick)
  }
  const io = new IntersectionObserver((e) => {
    visible = e[0]?.isIntersecting ?? true
    kick()
  })
  io.observe(host)
  const mo = new MutationObserver(() => {
    reduced = motionReduced()
    kick()
  })
  mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-motion', 'data-theme', 'data-palette'] })
  document.addEventListener('visibilitychange', kick)
  kick()
  return {
    kick,
    stop() {
      alive = false
      cancelAnimationFrame(raf)
      io.disconnect()
      mo.disconnect()
      document.removeEventListener('visibilitychange', kick)
    },
  }
}

/** Canvas an die Größe des Elternelements anpassen */
export function fitCanvas(host: HTMLElement, canvas: HTMLCanvasElement) {
  const r = host.getBoundingClientRect()
  const W = Math.max(1, Math.floor(r.width))
  const H = Math.max(1, Math.floor(r.height))
  const dpr = Math.min(2, window.devicePixelRatio || 1)
  canvas.width = Math.floor(W * dpr)
  canvas.height = Math.floor(H * dpr)
  canvas.style.width = `${W}px`
  canvas.style.height = `${H}px`
  return { W, H, dpr }
}

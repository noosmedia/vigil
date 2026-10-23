// Anzeigehilfen: Zahlen, Größen, Zeiten und Zeitplan in der eingestellten Sprache

import type { Day, ScheduleEntry } from './types'
import { i18n, t } from './i18n.svelte'

const tag = () => (i18n.locale === 'de' ? 'de-DE' : 'en-GB')

export function num(n: number): string {
  return new Intl.NumberFormat(tag()).format(Math.round(n))
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toLocaleString(tag(), { maximumFractionDigits: v < 10 ? 1 : 0 })} ${units[i]}`
}

export function duration(secs: number): string {
  if (!isFinite(secs) || secs < 0) return t('time.unknown')
  if (secs < 60) return t('time.secondsShort', { n: Math.max(1, Math.round(secs)) })
  const m = Math.round(secs / 60)
  if (m < 60) return t('time.minutes', { n: m })
  return t('time.hoursMinutes', { h: Math.floor(m / 60), m: m % 60 })
}

// Relative Zeitangabe wie "vor 3 Std." oder "in 2 Tagen"
export function relative(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return t('time.never')
  const time = new Date(iso).getTime()
  if (isNaN(time)) return t('time.unknown')
  const diff = (time - now) / 1000
  const abs = Math.abs(diff)
  const past = diff < 0
  if (abs < 60) return past ? t('time.justNow') : t('time.soon')
  let text: string
  if (abs < 3600) text = t('time.minutes', { n: Math.round(abs / 60) })
  else if (abs < 86400) text = t('time.hours', { n: Math.round(abs / 3600) })
  else {
    const d = Math.round(abs / 86400)
    text = d === 1 ? t('time.day') : t('time.days', { n: d })
  }
  return past ? t('time.ago', { t: text }) : t('time.in', { t: text })
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return t('time.unknown')
  const d = new Date(iso)
  if (isNaN(d.getTime())) return t('time.unknown')
  return d.toLocaleString(tag(), { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export function dateOnly(iso: string | null | undefined): string {
  if (!iso) return t('time.unknown')
  const d = new Date(iso)
  return isNaN(d.getTime()) ? t('time.unknown') : d.toLocaleDateString(tag(), { day: '2-digit', month: '2-digit', year: 'numeric' })
}

export function clock(iso: string): string {
  return new Date(iso).toLocaleTimeString(tag(), { hour: '2-digit', minute: '2-digit' })
}

export const DAY_IDS: Day[] = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']

const JS_DAY: Record<Day, number> = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 }

// Nächster Termin eines Zeitplans, oder null wenn ausgeschaltet
export function nextRun(entry: ScheduleEntry, now = new Date()): Date | null {
  if (!entry.enabled || entry.days.length === 0) return null
  const [h, m] = entry.time.split(':').map(Number)
  const allowed = new Set(entry.days.map((d) => JS_DAY[d]))
  for (let i = 0; i < 8; i++) {
    const c = new Date(now)
    c.setDate(now.getDate() + i)
    c.setHours(h, m, 0, 0)
    if (c.getTime() > now.getTime() && allowed.has(c.getDay())) return c
  }
  return null
}

export function kindLabel(kind: string): string {
  return t(`kind.${kind}`)
}

export function money(cents: number, currency: string): string {
  return new Intl.NumberFormat(tag(), { style: 'currency', currency: currency.toUpperCase() }).format(cents / 100)
}

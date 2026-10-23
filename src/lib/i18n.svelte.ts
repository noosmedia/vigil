// Zweisprachigkeit: aktuelle Sprache, Übersetzungsfunktion und Auswahl zweisprachiger Helferfelder

import de from '../i18n/de'
import en from '../i18n/en'

export type Locale = 'de' | 'en'

type Dict = Record<string, string>

const dicts: Record<Locale, Dict> = { de: flatten(de), en: flatten(en) }

/** Läuft Vigil unter Windows? Dann gelten die Texte unter `win.*` vor den allgemeinen. */
export const isWindows = typeof navigator !== 'undefined' && navigator.userAgent.includes('Windows')

// Verschachtelte Wörterbücher in "a.b.c"-Schlüssel umwandeln
function flatten(obj: object, prefix = '', out: Dict = {}): Dict {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k
    if (typeof v === 'string') out[key] = v
    else flatten(v as object, key, out)
  }
  return out
}

class I18n {
  locale = $state<Locale>('de')
}

export const i18n = new I18n()

// Sprache aus Einstellung bestimmen; "system" folgt der Sprache des Systems
export function setLanguage(pref: string | undefined) {
  const sys: Locale = (navigator.language || 'de').toLowerCase().startsWith('de') ? 'de' : 'en'
  i18n.locale = pref === 'de' || pref === 'en' ? pref : sys
  document.documentElement.lang = i18n.locale
}

/** Text zum Schlüssel, mit Platzhaltern {name} */
export function t(key: string, vars?: Record<string, string | number>): string {
  const d = dicts[i18n.locale]
  const text = (isWindows ? d[`win.${key}`] ?? dicts.de[`win.${key}`] : undefined) ?? d[key] ?? dicts.de[key] ?? key
  if (!vars) return text
  return text.replace(/\{(\w+)\}/g, (_, name) => (vars[name] !== undefined ? String(vars[name]) : `{${name}}`))
}

/** Einzahl oder Mehrzahl: Schlüssel.one / Schlüssel.many mit {n} */
export function tn(key: string, n: number, vars?: Record<string, string | number>): string {
  const formatted = new Intl.NumberFormat(i18n.locale === 'de' ? 'de-DE' : 'en-US').format(n)
  return t(`${key}.${n === 1 ? 'one' : 'many'}`, { n: formatted, ...vars })
}

/** Zweisprachiges Feld eines Helfer-Objekts: obj.title bzw. obj.titleEn */
export function loc<T extends object>(obj: T | null | undefined, field: string): string {
  if (!obj) return ''
  const rec = obj as Record<string, unknown>
  if (i18n.locale === 'en') {
    const en = rec[`${field}En`]
    if (typeof en === 'string' && en) return en
  }
  const v = rec[field]
  return typeof v === 'string' ? v : ''
}

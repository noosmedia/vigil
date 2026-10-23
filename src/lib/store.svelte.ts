// Zentraler Zustand der Oberfläche: holt Daten aus dem Tauri-Teil und hält sie aktuell

import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { isHint } from './types'
import type { AppInfo, HelperResult, LicenseInfo, Live, OpenThreat, Report, Settings, Snapshot, UpdateInfo, WatcherEvent } from './types'
import { toasts } from './toast.svelte'
import { loc, setLanguage, t, tn } from './i18n.svelte'

export type Page = 'overview' | 'scan' | 'findings' | 'system' | 'history' | 'pro' | 'settings'

export type Status = 'loading' | 'setup' | 'scanning' | 'counting' | 'paused' | 'busy' | 'threat' | 'warn' | 'safe'

const ACTIVE = new Set(['counting', 'scanning', 'paused', 'running'])

class AppStore {
  snap = $state<Snapshot | null>(null)
  reports = $state<Report[]>([])
  openThreats = $state<OpenThreat[]>([])
  loadError = $state<string | null>(null)
  page = $state<Page>('overview')
  proPage = $state<string | null>(null)
  pulse = $state(0)
  pending = $state<Record<string, boolean>>({})
  update = $state<UpdateInfo | null>(null)
  // Laufendes Update: welcher Teil (vigil, pro), Phase und Bytes
  updateProgress = $state<{ part: string; phase: string; done: number; total: number; step: number; steps: number } | null>(null)
  license = $state<LicenseInfo | null>(null)
  info = $state<AppInfo | null>(null)
  autostart = $state<boolean | null>(null)
  // Zuletzt gemeldeter Fund (für die Flug-Animation in die Quarantäne)
  lastProEvent = $state<Record<string, unknown> | null>(null)

  private liveTimer = 0
  private fullTimer = 0

  get job() {
    return this.snap?.state?.job ?? null
  }

  get jobActive(): boolean {
    const j = this.job
    return !!j && ACTIVE.has(j.phase)
  }

  get scanActive(): boolean {
    const j = this.job
    return this.jobActive && !!j && ['quick', 'full', 'custom'].includes(j.kind)
  }

  get proActive(): boolean {
    return !!this.license?.active && !!this.license?.proInstalled
  }

  // Neueres Pro auf dem Lizenzserver, nur bei aktiver Pro-Lizenz; sonst null
  get proUpdateVersion(): string | null {
    const l = this.license
    if (!l?.active || !l.proInstalled || !l.availableVersion || !l.proVersion) return null
    const x = l.availableVersion.split('.').map((n) => parseInt(n, 10) || 0)
    const y = l.proVersion.split('.').map((n) => parseInt(n, 10) || 0)
    for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0) ? l.availableVersion : null
    return null
  }

  // Irgendein Update verfügbar: Vigil selbst oder (nur mit Pro) Vigil Pro
  get anyUpdate(): boolean {
    return !!this.update?.available || !!this.proUpdateVersion
  }

  // Gesamtzustand, aus dem Feld, Statuswort und Farben abgeleitet werden
  get status(): Status {
    const s = this.snap
    if (!s) return 'loading'
    if (!s.installed) return 'setup'
    if (this.scanActive) {
      const p = this.job!.phase
      return p === 'counting' ? 'counting' : p === 'paused' ? 'paused' : 'scanning'
    }
    if (this.threatCount > 0) return 'threat'
    if (this.problems.length > 0) return 'warn'
    if (this.jobActive) return 'busy'
    return 'safe'
  }

  // Echte Bedrohungen; Hinweise der Heuristik zählen getrennt
  get threatCount(): number {
    return this.openThreats.filter((o) => !o.hint).length + (this.snap?.watcherEvents.filter((e) => e.verdict === 'infected' && !e.handled).length ?? 0)
  }

  get hintCount(): number {
    return this.openThreats.filter((o) => o.hint).length + (this.snap?.watcherEvents.filter((e) => e.verdict === 'hint' && !e.handled).length ?? 0)
  }

  // Hinweise ausblenden (ohne Passwort, nur für diesen Benutzer)
  async dismissHints(items: { path: string; sha256: string | null }[]) {
    try {
      await invoke('dismiss_hints', { items })
      toasts.show('success', tn('findings.hints.dismissed', items.length))
      await this.refresh()
    } catch (e) {
      toasts.show('error', t('common.notDone'), String(e))
    }
  }

  // Kurze Liste der Punkte, die den Schutz gerade schwächen
  get problems(): string[] {
    const s = this.snap
    if (!s || !s.installed) return []
    const out: string[] = []
    if (!s.services.clamd) out.push(t('problems.clamd'))
    if (!s.services.freshclam) out.push(t('problems.freshclam'))
    const age = this.signatureAgeHours
    if (age !== null && age > 48) out.push(t('problems.sigOld', { n: Math.round(age / 24) }))
    for (const it of s.system?.items ?? []) {
      if (it.status === 'critical') out.push(loc(it, 'title'))
    }
    return out
  }

  get signatureAgeHours(): number | null {
    const d = this.snap?.signatures?.date
    if (!d) return null
    const time = new Date(d).getTime()
    if (isNaN(time)) return null
    return (Date.now() - time) / 3600000
  }

  get lastScan(): Report | null {
    return this.reports.find((r) => ['quick', 'full', 'custom'].includes(r.kind)) ?? null
  }

  async init() {
    await this.refresh()
    this.schedule()
    this.refreshMeta()
    // Ereignisse aus dem Tauri-Teil: Wächterfunde, Pro, Tray-Navigation, Fehler des Helfers
    await listen<{ part: string; phase: string; done: number; total: number; step: number; steps: number }>('update-progress', (e) => {
      this.updateProgress = e.payload
    })
    await listen<WatcherEvent>('watcher-event', (e) => {
      this.pulse++
      if (this.snap) {
        this.snap.watcherEvents = [e.payload, ...this.snap.watcherEvents].slice(0, 100)
        this.snap.watcherLast = e.payload
      }
      if (e.payload.verdict === 'infected') {
        toasts.show('error', t('common.watcherHit'), t('common.watcherHitDetail', { sig: e.payload.detail ?? '', path: e.payload.path }))
        this.page = 'findings'
      }
    })
    await listen<Record<string, unknown>>('pro-event', (e) => {
      this.lastProEvent = e.payload
      if (e.payload.type === 'usb-progress' || e.payload.type === 'realtime-status') this.pulse++
    })
    await listen<string>('navigate', (e) => {
      this.page = e.payload as Page
    })
    await listen<string>('helper-failed', (e) => {
      if (e.payload) toasts.show('error', t('common.jobNotStarted'), e.payload)
      this.refreshLive()
    })
  }

  // Version, Updates, Lizenz und Autostart; seltener als der Live-Zustand
  async refreshMeta(forceUpdate = false) {
    try {
      const [info, update, license, autostart] = await Promise.all([
        invoke<AppInfo>('app_info'),
        invoke<UpdateInfo>('check_update', { force: forceUpdate }),
        invoke<LicenseInfo>('license_status'),
        invoke<boolean>('get_autostart'),
      ])
      this.info = info
      this.update = update
      this.license = license
      this.autostart = autostart
    } catch (e) {
      console.warn('Metadaten nicht lesbar', e)
    }
  }

  private schedule() {
    clearTimeout(this.liveTimer)
    const ms = this.jobActive ? 400 : 2500
    this.liveTimer = window.setTimeout(async () => {
      await this.refreshLive()
      this.schedule()
    }, ms)
    if (!this.fullTimer) {
      this.fullTimer = window.setInterval(() => {
        this.refresh()
        this.refreshMeta()
      }, 30000)
    }
  }

  async refresh() {
    try {
      const [snap, reports, openThreats] = await Promise.all([
        invoke<Snapshot>('snapshot'),
        invoke<Report[]>('reports'),
        invoke<OpenThreat[]>('open_threats'),
      ])
      // Darstellung folgt immer den gespeicherten Einstellungen (auch bei Änderung von außen)
      if (!this.snap || JSON.stringify(this.snap.settings) !== JSON.stringify(snap.settings)) applyAppearance(snap.settings)
      this.snap = snap
      this.reports = reports
      this.openThreats = openThreats
      this.loadError = null
    } catch (e) {
      this.loadError = String(e)
    }
  }

  private jobKey(): string {
    const j = this.snap?.state?.job
    return j ? `${j.id}:${j.phase}` : ''
  }

  async refreshLive() {
    try {
      const live = await invoke<Live>('live')
      if (!this.snap) return this.refresh()
      const before = this.jobKey()
      const wasActive = this.jobActive
      Object.assign(this.snap, live)
      const after = this.jobKey()
      // Ein Auftrag ist fertig geworden: alles neu laden und Ergebnis melden
      if (before !== after && wasActive && this.job && !ACTIVE.has(this.job.phase)) {
        await this.refresh()
        this.announce()
      }
    } catch (e) {
      this.loadError = String(e)
    }
  }

  private announce() {
    const j = this.job
    if (!j) return
    if (j.phase === 'failed') {
      toasts.show('error', t('common.jobFailed'), loc(j, 'message') || t('common.noMessage'))
      return
    }
    if (j.phase === 'cancelled') {
      toasts.show('info', t('common.cancelled'))
      return
    }
    if (j.kind === 'systemcheck') toasts.show('success', t('common.systemcheckDone'))
    else if (j.kind === 'update') toasts.show('success', t('common.sigUpdated'), loc(j, 'message') || undefined)
    else {
      const threats = j.threats.filter((x) => !isHint(x)).length
      const hints = j.threats.length - threats
      if (threats) toasts.show('error', tn('common.scanDoneThreats', threats), hints ? tn('common.hintsFound', hints) : undefined)
      else toasts.show('success', t('common.scanDoneClean'), hints ? tn('common.hintsFound', hints) : undefined)
    }
  }

  // Lange Aufträge (Prüfung, Systemcheck, Update) starten, ohne auf das Ende zu warten
  async startJob(kind: 'quick' | 'full' | 'custom' | 'systemcheck' | 'update' | 'cancel', paths: string[] = []) {
    const key = `job:${kind}`
    this.pending = { ...this.pending, [key]: true }
    try {
      await invoke('start_job', { kind, paths })
      setTimeout(() => this.refreshLive(), 600)
    } catch (e) {
      toasts.show('error', t('common.jobNotStarted'), String(e))
    } finally {
      setTimeout(() => {
        this.pending = { ...this.pending, [key]: false }
      }, 900)
    }
  }

  startScan(kind: 'quick' | 'full') {
    if (this.scanActive) {
      toasts.show('info', t('scan.running'))
      this.page = 'overview'
      return
    }
    this.page = 'overview'
    return this.startJob(kind)
  }

  // Prüfung anhalten oder fortsetzen (ohne Passwort)
  async togglePause() {
    const paused = this.job?.phase === 'paused'
    this.pending = { ...this.pending, pause: true }
    try {
      const res = await invoke<HelperResult>(paused ? 'resume_job' : 'pause_job')
      if (res.ok) toasts.show('info', t(paused ? 'common.resumed' : 'common.paused'))
      else if (res.message) toasts.show('error', t('common.notDone'), res.message)
      await this.refreshLive()
    } catch (e) {
      toasts.show('error', t('common.notDone'), String(e))
    } finally {
      this.pending = { ...this.pending, pause: false }
    }
  }

  // Kurze Aufträge mit Passwortabfrage: Quarantäne, Freigabe, Einstellungen
  async helper(key: string, args: string[], success: string): Promise<boolean> {
    this.pending = { ...this.pending, [key]: true }
    try {
      const res = await invoke<HelperResult>('run_helper', { args })
      if (res.ok) {
        toasts.show('success', success)
        await this.refresh()
        return true
      }
      if (res.message) toasts.show('error', t('common.notDone'), res.message)
      return false
    } catch (e) {
      toasts.show('error', t('common.notDone'), String(e))
      return false
    } finally {
      this.pending = { ...this.pending, [key]: false }
    }
  }

  async saveSettings(next: Settings) {
    try {
      applyAppearance(next)
      if (this.snap) this.snap.settings = next
      await invoke('save_settings', { settings: next })
    } catch (e) {
      toasts.show('error', t('settings.notSaved'), String(e))
    }
  }
}

export const app = new AppStore()

// Darstellung setzen: Thema, Farbschema, Look, Schrift, Bewegung, Sprache
let mq: MediaQueryList | null = null
export function applyAppearance(s: Settings) {
  const root = document.documentElement
  mq ??= window.matchMedia('(prefers-color-scheme: dark)')
  const resolve = () => (s.theme === 'system' ? (mq!.matches ? 'dark' : 'light') : s.theme)
  root.dataset.theme = resolve()
  root.dataset.palette = s.palette || 'graphit'
  root.dataset.look = s.look || 'feld'
  root.dataset.font = s.font || 'bricolage'
  root.dataset.motion = s.motion || 'voll'
  mq.onchange = () => {
    root.dataset.theme = resolve()
  }
  setLanguage(s.language)
}

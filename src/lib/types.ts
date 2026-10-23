// Datenformate, wie sie Helfer und App austauschen (Gegenstück zu crates/vigil-core/src/types.rs)

export type JobKind = 'quick' | 'full' | 'custom' | 'systemcheck' | 'update'
export type JobPhase = 'counting' | 'scanning' | 'paused' | 'running' | 'finished' | 'cancelled' | 'failed'
export type ThreatAction = 'none' | 'quarantined' | 'deleted' | 'allowed' | 'restored'

export interface Threat {
  id: string
  path: string
  signature: string
  size: number
  sha256: string | null
  action: ThreatAction
  quarantineId: string | null
  severity?: 'threat' | 'hint'
}

/** Heuristische Erkennung (nur ein Hinweis)? Ältere Berichte haben kein Feld severity. */
export function isHint(t: { signature: string; severity?: string }): boolean {
  return t.severity === 'hint' || t.signature.startsWith('Heuristics.')
}

export interface Segment {
  label: string
  labelEn?: string | null
  path: string | null
  files: number
}

export interface Job {
  id: string
  kind: JobKind
  trigger: 'manual' | 'schedule'
  phase: JobPhase
  startedAt: string
  finishedAt: string | null
  paths: string[]
  engine: string
  total: number
  counted: boolean
  scanned: number
  skipped: number
  errors: number
  bytes: number
  current: string
  currentEn?: string | null
  threats: Threat[]
  message: string | null
  messageEn?: string | null
  segments?: Segment[]
  segmentIndex?: number
}

export interface Report extends Job {
  durationSecs: number
  filesPerSecond?: number
}

export interface ScanState {
  updatedAt: string
  job: Job | null
}

export interface QuarantineItem {
  id: string
  originalPath: string
  signature: string
  size: number
  sha256: string
  quarantinedAt: string
  reportId: string | null
  threatId: string | null
}

export type CheckStatus = 'ok' | 'info' | 'warn' | 'critical'

export interface CheckItem {
  id: string
  category: 'schutz' | 'updates' | 'netz' | 'rootkit' | 'haertung'
  status: CheckStatus
  title: string
  titleEn?: string | null
  detail: string
  detailEn?: string | null
  fix: { action: string; label: string; labelEn?: string | null } | null
  list: string[]
  listEn?: string[] | null
}

export interface SystemReport {
  checkedAt: string
  signatures: { version: number; date: string; ageHours: number; engine: string } | null
  hardeningIndex: number | null
  items: CheckItem[]
}

export type Day = 'mon' | 'tue' | 'wed' | 'thu' | 'fri' | 'sat' | 'sun'

export interface ScheduleEntry {
  enabled: boolean
  time: string
  days: Day[]
}

export interface Config {
  schedule: { quick: ScheduleEntry; full: ScheduleEntry; systemcheck: ScheduleEntry }
  scan: { includeMounts: boolean; excludePaths: string[]; onThreat: 'report' | 'quarantine' }
  allowlist: { sha256: string; path: string; signature: string; addedAt: string }[]
  updates?: { auto: boolean; time: string }
  // Wie oft nach neuen Virendaten gesucht wird (Stunden) und ob die kostenlosen Zusatzquellen genutzt werden
  signatureIntervalHours?: number
  extraSignatures?: boolean
}

export type Look = 'feld' | 'orbit' | 'terminal' | 'blaupause'
export type Palette = 'graphit' | 'tinte' | 'glut' | 'fjord' | 'moos'
export type FontId = 'bricolage' | 'archivo' | 'syne' | 'unbounded' | 'instrument' | 'bigshoulders'

export interface Settings {
  theme: 'system' | 'dark' | 'light'
  watcherEnabled: boolean
  watcherPaths: string[]
  notifications: boolean
  language: 'system' | 'de' | 'en'
  look: Look
  palette: Palette
  font: FontId
  motion: 'voll' | 'ruhig'
  updateNotify: boolean
}

export interface WatcherEvent {
  at: string
  path: string
  verdict: 'clean' | 'infected' | 'hint' | 'skipped' | 'error'
  detail: string | null
  handled: boolean
}

export interface Signatures {
  version: number
  date: string | null
  engine: string
  // Wann zuletzt nach neuen Virendaten gesucht wurde
  checkedAt: string | null
}

export interface Services {
  clamd: boolean
  freshclam: boolean
}

export interface Live {
  installed: boolean
  dev: boolean
  state: ScanState | null
  signatures: Signatures | null
  services: Services
  watcherActive: boolean
  watcherLast: WatcherEvent | null
}

export interface Snapshot extends Live {
  setupCommand: string | null
  system: SystemReport | null
  quarantine: QuarantineItem[]
  config: Config
  settings: Settings
  watcherEvents: WatcherEvent[]
}

// Fund aus einem Bericht, für den noch keine Maßnahme getroffen wurde
export interface OpenThreat {
  reportId: string
  reportKind: JobKind
  foundAt: string
  threat: Threat
  hint: boolean
}

export interface HelperResult {
  ok: boolean
  message: string
}

export interface RawResult {
  ok: boolean
  stdout: string
  stderr: string
  code: number
}

export interface UpdateInfo {
  current: string
  latest: string | null
  available: boolean
  notes: string | null
  notesEn: string | null
  publishedAt: string | null
  checkedAt: string | null
  error: string | null
}

export interface LicenseInfo {
  active: boolean
  key: string | null
  plan: string | null
  periodEnd: string | null
  cancelAtPeriodEnd: boolean
  features: string[]
  proInstalled: boolean
  proVersion: string | null
  availableVersion: string | null
  agentRunning: boolean
  error: string | null
}

export interface AppInfo {
  version: string
  license: string
  repo: string
}

export interface Plan {
  amount: number
  currency: string
  taxIncluded: boolean
}

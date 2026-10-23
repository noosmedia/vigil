//! Datentypen der JSON-Dateien zwischen Helfer und App (camelCase).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Aufträge (state.json, Berichte)
// ---------------------------------------------------------------------------

/// Art des Auftrags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobKind {
    Quick,
    Full,
    Custom,
    Systemcheck,
    Update,
}

impl JobKind {
    /// Name wie im JSON.
    pub fn as_str(&self) -> &'static str {
        match self {
            JobKind::Quick => "quick",
            JobKind::Full => "full",
            JobKind::Custom => "custom",
            JobKind::Systemcheck => "systemcheck",
            JobKind::Update => "update",
        }
    }

    /// Dateiprüfungen (erzeugen Berichte und lassen sich abbrechen).
    pub fn is_scan(&self) -> bool {
        matches!(self, JobKind::Quick | JobKind::Full | JobKind::Custom)
    }
}

/// Auslöser des Auftrags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trigger {
    Manual,
    Schedule,
}

/// Phase des Auftrags. Dateiprüfungen: counting, scanning, paused, finished, cancelled, failed.
/// Systemcheck und Update: running, finished, failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Counting,
    Scanning,
    /// Angehalten (`vigil-scan pause`); `resume` setzt die vorherige Phase fort.
    Paused,
    Running,
    Finished,
    Cancelled,
    Failed,
}

impl Phase {
    /// Endphase erreicht?
    pub fn is_final(&self) -> bool {
        matches!(self, Phase::Finished | Phase::Cancelled | Phase::Failed)
    }
}

/// Prüfmotor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineKind {
    Clamd,
    Clamscan,
}

/// Maßnahme zu einem Fund.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatAction {
    None,
    Quarantined,
    Deleted,
    Allowed,
    Restored,
}

/// Schwere eines Funds: echte Bedrohung oder nur ein Hinweis aus der Heuristik von ClamAV.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Threat,
    Hint,
}

/// Heuristische Erkennungen (Signaturname beginnt mit „Heuristics.“) gelten als Hinweis,
/// z. B. Phishing-Merkmale in gespeicherten Mails oder auffällig gebaute Archive.
pub fn severity_of(signature: &str) -> Severity {
    if signature.starts_with("Heuristics.") {
        Severity::Hint
    } else {
        Severity::Threat
    }
}

/// Ein Fund (in state.json und im Bericht).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Threat {
    pub id: String,
    pub path: String,
    pub signature: String,
    pub size: u64,
    pub sha256: String,
    pub action: ThreatAction,
    pub quarantine_id: Option<String>,
    /// Fehlt in Berichten vor 0.2.0; dann entscheidet der Signaturname (siehe `is_hint`)
    #[serde(default)]
    pub severity: Severity,
}

impl Threat {
    /// Nur ein Hinweis? Berücksichtigt auch ältere Berichte ohne Feld `severity`.
    pub fn is_hint(&self) -> bool {
        self.severity == Severity::Hint || severity_of(&self.signature) == Severity::Hint
    }
}

/// Bereich für die Prüfanimation: direkter Unterordner einer Prüfwurzel oder (Schnellprüfung)
/// ein Zielpunkt. `path` ist null bei „Laufende Programme“ und „Weitere“.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Segment {
    pub label: String,
    pub label_en: String,
    pub path: Option<String>,
    pub files: u64,
}

/// Laufender oder letzter Auftrag. Felder ab 0.2 haben Standardwerte, damit
/// Zustände und Berichte von 0.1 lesbar bleiben.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub id: String,
    pub kind: JobKind,
    pub trigger: Trigger,
    pub phase: Phase,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub paths: Vec<String>,
    pub engine: Option<EngineKind>,
    pub total: u64,
    pub counted: bool,
    pub scanned: u64,
    pub skipped: u64,
    pub errors: u64,
    pub bytes: u64,
    /// Aktuelle Datei (Prüfung) oder aktueller Schritt (Systemcheck, Update).
    pub current: Option<String>,
    /// Englische Fassung von `current` (bei Dateipfaden gleich `current`).
    #[serde(default)]
    pub current_en: Option<String>,
    pub threats: Vec<Threat>,
    pub message: Option<String>,
    #[serde(default)]
    pub message_en: Option<String>,
    /// Bereiche in Prüfreihenfolge (leer bei Systemcheck und Update).
    #[serde(default)]
    pub segments: Vec<Segment>,
    /// Index des aktuell geprüften Bereichs.
    #[serde(default)]
    pub segment_index: u32,
}

impl Job {
    /// Setzt die Meldung in beiden Sprachen.
    pub fn set_message(&mut self, t: &crate::i18n::Text) {
        self.message = Some(t.de_text());
        self.message_en = Some(t.en_text());
    }

    /// Setzt den aktuellen Schritt in beiden Sprachen.
    pub fn set_current(&mut self, t: Option<&crate::i18n::Text>) {
        self.current = t.map(|t| t.de.clone());
        self.current_en = t.map(|t| t.en.clone());
    }

    /// Setzt die aktuelle Datei (gleich in beiden Sprachen).
    pub fn set_current_path(&mut self, p: String) {
        self.current_en = Some(p.clone());
        self.current = Some(p);
    }
}

/// Inhalt von state.json. `job` ist null, wenn noch nie etwas lief.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub updated_at: String,
    pub job: Option<Job>,
}

/// Inhalt von reports/<id>.json: der fertige Auftrag plus Dauer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    #[serde(flatten)]
    pub job: Job,
    pub duration_secs: u64,
    /// Geprüfte Dateien je Sekunde in der Prüfphase (ohne Pausen).
    #[serde(default)]
    pub files_per_second: f64,
}

// ---------------------------------------------------------------------------
// Quarantäne (quarantine.json)
// ---------------------------------------------------------------------------

/// Eintrag im Quarantäne-Verzeichnis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: String,
    pub signature: String,
    pub size: u64,
    pub sha256: String,
    pub quarantined_at: String,
    pub report_id: Option<String>,
    pub threat_id: Option<String>,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// Inhalt von quarantine.json.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineIndex {
    #[serde(default)]
    pub items: Vec<QuarantineItem>,
}

// ---------------------------------------------------------------------------
// Systemcheck (system.json)
// ---------------------------------------------------------------------------

/// Stand der Virensignaturen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureInfo {
    pub version: u64,
    pub date: String,
    pub age_hours: f64,
    pub engine: Option<String>,
}

/// Bereich eines Prüfpunkts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Schutz,
    Updates,
    Netz,
    Rootkit,
    Haertung,
}

/// Bewertung eines Prüfpunkts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Info,
    Warn,
    Critical,
}

/// Behebung zu einem Prüfpunkt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fix {
    pub action: String,
    pub label: String,
    #[serde(default)]
    pub label_en: String,
}

/// Ein Prüfpunkt im Systemcheck.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckItem {
    pub id: String,
    pub category: Category,
    pub status: CheckStatus,
    pub title: String,
    #[serde(default)]
    pub title_en: String,
    pub detail: String,
    #[serde(default)]
    pub detail_en: String,
    pub fix: Option<Fix>,
    pub list: Vec<String>,
    /// Englische Fassung von `list` (gleiche Länge; Einträge ohne eigenen Text sind gleich).
    #[serde(default)]
    pub list_en: Vec<String>,
}

/// Inhalt von system.json.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemReport {
    pub checked_at: String,
    pub signatures: Option<SignatureInfo>,
    pub hardening_index: Option<u32>,
    pub items: Vec<CheckItem>,
}

// ---------------------------------------------------------------------------
// Konfiguration (config.json)
// ---------------------------------------------------------------------------

/// Wochentag im Zeitplan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Day {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl Day {
    /// Alle Tage in Wochenreihenfolge.
    pub const ALL: [Day; 7] = [Day::Mon, Day::Tue, Day::Wed, Day::Thu, Day::Fri, Day::Sat, Day::Sun];

    /// Schreibweise für systemd (OnCalendar).
    pub fn systemd_name(&self) -> &'static str {
        match self {
            Day::Mon => "Mon",
            Day::Tue => "Tue",
            Day::Wed => "Wed",
            Day::Thu => "Thu",
            Day::Fri => "Fri",
            Day::Sat => "Sat",
            Day::Sun => "Sun",
        }
    }
}

/// Ein Zeitplan-Eintrag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleEntry {
    pub enabled: bool,
    pub time: String,
    pub days: Vec<Day>,
}

/// Zeitpläne der drei Timer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Schedule {
    pub quick: ScheduleEntry,
    pub full: ScheduleEntry,
    pub systemcheck: ScheduleEntry,
}

impl Default for Schedule {
    fn default() -> Self {
        Schedule {
            quick: ScheduleEntry { enabled: true, time: "12:30".into(), days: Day::ALL.to_vec() },
            full: ScheduleEntry { enabled: true, time: "13:00".into(), days: vec![Day::Sun] },
            systemcheck: ScheduleEntry { enabled: true, time: "12:00".into(), days: Day::ALL.to_vec() },
        }
    }
}

/// Verhalten bei einem Fund.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnThreat {
    #[default]
    Report,
    Quarantine,
}

/// Einstellungen der Dateiprüfung.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScanSettings {
    pub include_mounts: bool,
    pub exclude_paths: Vec<String>,
    pub on_threat: OnThreat,
}

/// Freigegebene Datei (nach sha256).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowEntry {
    pub sha256: String,
    pub path: String,
    pub signature: String,
    pub added_at: String,
}

/// Automatische Updates von Vigil selbst (Timer `vigil-selfupdate.timer`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateSettings {
    pub auto: bool,
    pub time: String,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        UpdateSettings { auto: false, time: "11:00".into() }
    }
}

/// Erlaubte Abstände in Stunden für die Suche nach neuen Virendaten (`signatureIntervalHours`).
pub const SIGNATURE_INTERVALS: [u32; 4] = [1, 2, 4, 8];

/// Inhalt von config.json. Fehlende Felder erhalten die Standardwerte.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    pub schedule: Schedule,
    pub scan: ScanSettings,
    pub allowlist: Vec<AllowEntry>,
    pub updates: UpdateSettings,
    /// Zusätzliche Signaturen von Sanesecurity laden (Timer `vigil-extrasigs.timer`). Standard an.
    pub extra_signatures: bool,
    /// Abstand in Stunden für die Suche nach neuen Virendaten (1, 2, 4 oder 8). Gilt für
    /// freshclam (`Checks` = 24 / Stunden) und für die zusätzlichen Signaturen. Standard 1.
    pub signature_interval_hours: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            schedule: Schedule::default(),
            scan: ScanSettings::default(),
            allowlist: Vec::new(),
            updates: UpdateSettings::default(),
            extra_signatures: true,
            signature_interval_hours: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Zusätzliche Signaturen (extra-signatures.json)
// ---------------------------------------------------------------------------

/// Ergebnis des letzten Abrufs einer zusätzlichen Quelle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtraStatus {
    /// Neue Daten wurden übernommen.
    Updated,
    /// Abgerufen, nichts hat sich geändert.
    Current,
    /// Nicht abgerufen, weil der letzte Abruf zu kurz zurückliegt (Vorgabe der Quelle).
    Waiting,
    /// Teilweise übernommen; für die übrigen Dateien bleibt der bisherige Stand.
    Partial,
    /// Fehlgeschlagen; der bisherige Stand bleibt.
    Failed,
    /// Ausgeschaltet, eigene Dateien sind entfernt.
    Off,
    /// Eingeschaltet, aber noch nie abgerufen.
    #[default]
    Pending,
}

impl ExtraStatus {
    /// Name wie im JSON.
    pub fn as_str(&self) -> &'static str {
        match self {
            ExtraStatus::Updated => "updated",
            ExtraStatus::Current => "current",
            ExtraStatus::Waiting => "waiting",
            ExtraStatus::Partial => "partial",
            ExtraStatus::Failed => "failed",
            ExtraStatus::Off => "off",
            ExtraStatus::Pending => "pending",
        }
    }
}

/// Eine übernommene Datenbankdatei einer zusätzlichen Quelle.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExtraFile {
    /// Name bei der Quelle, z. B. `phish.ndb`.
    pub name: String,
    /// Name im Datenbankordner von clamd, z. B. `vigil-sanesecurity-phish.ndb`.
    pub installed: String,
    /// Von ClamAV geladene Signaturen dieser Datei.
    pub signatures: u64,
    pub size: u64,
    pub sha256: String,
    /// Zeitpunkt, an dem sich der Inhalt zuletzt geändert hat.
    pub changed_at: Option<String>,
}

/// Stand einer zusätzlichen Quelle.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExtraSource {
    /// Kennung, z. B. `sanesecurity`.
    pub id: String,
    pub name: String,
    /// Webseite der Quelle.
    pub url: String,
    /// Letzter Abrufversuch (auch wenn er fehlschlug).
    pub last_attempt: Option<String>,
    /// Letzter erfolgreicher Abruf.
    pub last_success: Option<String>,
    /// Letzte Übernahme neuer Daten.
    pub last_change: Option<String>,
    /// Frühester Zeitpunkt für den nächsten Abruf (Vorgabe der Quelle).
    pub next_allowed: Option<String>,
    /// Summe der geladenen Signaturen aller übernommenen Dateien.
    pub signatures: u64,
    pub files: Vec<ExtraFile>,
    pub status: ExtraStatus,
    /// Meldung zum letzten Lauf.
    pub message: Option<String>,
    pub message_en: Option<String>,
    /// Letzter Fehler (bleibt bis zum nächsten fehlerfreien Lauf stehen).
    pub error: Option<String>,
    pub error_en: Option<String>,
    /// Zeitpunkt des letzten Fehlers.
    pub error_at: Option<String>,
}

/// Inhalt von extra-signatures.json im Datenordner.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExtraSignatures {
    pub updated_at: String,
    /// Stand von `extraSignatures` in config.json beim letzten Schreiben.
    pub enabled: bool,
    /// Stand von `signatureIntervalHours` beim letzten Schreiben.
    pub interval_hours: u32,
    /// Letzte Suche von freshclam nach neuen ClamAV-Daten (aus dem Journal oder dem
    /// freshclam-Protokoll), `null`, wenn nicht ermittelbar.
    pub freshclam_last_check: Option<String>,
    pub sources: Vec<ExtraSource>,
}

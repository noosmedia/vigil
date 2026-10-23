//! Systemcheck unter Windows (Gegenstück zu `systemcheck.rs` unter Linux): Virensignaturen,
//! Vigil-Dienst und clamd, Windows Update, Microsoft Defender, Firewall, BitLocker, offene Ports.
//! Abfragen laufen über PowerShell mit JSON-Ausgabe. Ergebnis in system.json, Fortschritt als
//! Auftrag in state.json (gleiches Format wie unter Linux, ohne Härtungsindex).

use crate::clamd;
use crate::cmd;
use crate::fsutil;
use crate::i18n::Text;
use crate::paths;
use crate::state::{new_job, StateWriter};
use crate::sysinfo;
use crate::tr;
use crate::types::{Category, CheckItem, CheckStatus, Fix, Job, JobKind, Phase, SystemReport, Trigger};
use serde_json::Value;
use std::time::Duration;

/// Ein Prüfschritt liefert einen oder mehrere Prüfpunkte.
type CheckFn = fn() -> Vec<CheckItem>;

const T_SHORT: Duration = Duration::from_secs(90);
/// Die Suche nach Windows-Updates kann einige Minuten dauern.
const T_UPDATES: Duration = Duration::from_secs(10 * 60);

/// Kennung der Kategorie „Sicherheitsupdates“ bei Windows Update.
const SECURITY_CATEGORY: &str = "0fa1201d-4330-4fa8-8ae9-b877473b6441";
/// Kennung der Kategorie „Definitionsupdates“ (Virendaten von Defender): spielt Windows selbst
/// ein und zeigt sie nicht als offenes Update; ihr Alter steht beim Prüfpunkt Defender.
const DEFINITION_CATEGORY: &str = "e0789628-ce08-4437-be74-2495b842f43b";

/// Liest system.json (`None`, wenn noch kein Systemcheck lief).
pub fn read_system() -> Result<Option<SystemReport>, Text> {
    fsutil::read_json(&paths::system_path())
}

fn item(id: &str, category: Category, status: CheckStatus, title: Text, detail: Text) -> CheckItem {
    CheckItem {
        id: id.into(),
        category,
        status,
        title: title.de_text(),
        title_en: title.en_text(),
        detail: detail.de_text(),
        detail_en: detail.en_text(),
        fix: None,
        list: Vec::new(),
        list_en: Vec::new(),
    }
}

/// Setzt die Liste; Einträge ohne Übersetzung sind in beiden Sprachen gleich.
fn set_list(i: &mut CheckItem, list: Vec<Text>) {
    i.list = list.iter().map(|t| t.de.clone()).collect();
    i.list_en = list.into_iter().map(|t| t.en).collect();
}

fn fix(action: &str, label: Text) -> Option<Fix> {
    Some(Fix { action: action.into(), label: label.de, label_en: label.en })
}

fn not_checked(id: &str, cat: Category, what: &Text, why: &Text) -> CheckItem {
    let why = Text::new(why.de.trim(), why.en.trim());
    item(id, cat, CheckStatus::Info, tr!("{}: konnte nicht geprüft werden", "{}: could not be checked", *what), why)
}

/// Führt ein PowerShell-Skript aus und liest dessen JSON-Ausgabe (UTF-8).
pub fn powershell(script: &str, timeout: Duration) -> Result<Value, Text> {
    let full = format!(
        "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; {script}"
    );
    let out = cmd::run_named("powershell", &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &full], timeout)?;
    if !out.success() {
        return Err(out.error_text());
    }
    let text = out.stdout.trim().trim_start_matches('\u{feff}');
    if text.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(text).map_err(|e| tr!("Antwort von PowerShell nicht lesbar: {}", "PowerShell answer not readable: {}", e))
}

/// JSON-Wert als Liste (ConvertTo-Json liefert bei einem Eintrag ein Objekt statt einer Liste).
fn as_list(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Null => Vec::new(),
        other => vec![other.clone()],
    }
}

fn get_bool(v: &Value, key: &str) -> Option<bool> {
    match v.get(key)? {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => n.as_i64().map(|n| n != 0),
        _ => None,
    }
}

fn get_str(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Führt den Systemcheck als Auftrag `systemcheck` aus und schreibt system.json.
pub fn run_systemcheck(trigger: Trigger) -> Job {
    let mut writer = StateWriter::new();
    let mut job = new_job(JobKind::Systemcheck, trigger, Vec::new());
    let steps: [(Text, CheckFn); 7] = [
        (tr!("Virensignaturen", "Virus signatures"), check_signatures),
        (tr!("Vigil-Dienst und ClamAV", "Vigil service and ClamAV"), check_services),
        (tr!("Windows Update", "Windows Update"), check_updates),
        (tr!("Microsoft Defender", "Microsoft Defender"), check_defender),
        (tr!("Firewall", "Firewall"), check_firewall),
        (tr!("Laufwerksverschlüsselung (BitLocker)", "Drive encryption (BitLocker)"), check_bitlocker),
        (tr!("Offene Ports", "Open ports"), check_ports),
    ];
    job.total = steps.len() as u64;
    job.counted = true;
    writer.force(&job);

    let mut items = Vec::new();
    for (label, f) in steps {
        job.set_current(Some(&label));
        writer.force(&job);
        items.extend(f());
        job.scanned += 1;
    }

    let report = SystemReport { checked_at: crate::now_rfc3339(), signatures: sysinfo::signature_info(), hardening_index: None, items };
    job.set_current(None);
    job.finished_at = Some(crate::now_rfc3339());
    match fsutil::write_json(&paths::system_path(), &report, 0o644) {
        Ok(()) => {
            let warn = report.items.iter().filter(|i| i.status == CheckStatus::Warn).count();
            let crit = report.items.iter().filter(|i| i.status == CheckStatus::Critical).count();
            job.phase = Phase::Finished;
            let warnings = match warn {
                1 => tr!("1 Warnung", "1 warning"),
                n => tr!("{} Warnungen", "{} warnings", n),
            };
            job.set_message(&tr!("Systemcheck abgeschlossen: {} kritisch, {}.", "System check finished: {} critical, {}.", crit, warnings));
        }
        Err(e) => {
            job.phase = Phase::Failed;
            job.set_message(&tr!("Der Systemcheck konnte nicht gespeichert werden: {}", "Could not save the system check: {}", e));
        }
    }
    writer.force(&job);
    job
}

// ---------------------------------------------------------------------------
// Signaturen (wie unter Linux)
// ---------------------------------------------------------------------------

fn check_signatures() -> Vec<CheckItem> {
    let upd = fix("update-signatures", tr!("Signaturen aktualisieren", "Update signatures"));
    let mut it = match sysinfo::signature_info() {
        None => {
            let dir = sysinfo::database_dir();
            let mut i = item(
                "signatures",
                Category::Schutz,
                CheckStatus::Critical,
                tr!("Keine Virensignaturen gefunden", "No virus signatures found"),
                tr!(
                    "Im Ordner {} liegen keine Signaturen. Ohne Signaturen erkennt ClamAV nichts.",
                    "There are no signatures in the folder {}. Without signatures ClamAV detects nothing.",
                    dir.display()
                ),
            );
            i.fix = upd;
            return vec![i];
        }
        Some(s) => {
            let days = s.age_hours / 24.0;
            let (status, title) = if s.age_hours > 7.0 * 24.0 {
                (CheckStatus::Critical, tr!("Virensignaturen sind {:.0} Tage alt", "Virus signatures are {:.0} days old", days))
            } else if s.age_hours > 48.0 {
                (CheckStatus::Warn, tr!("Virensignaturen sind {:.0} Stunden alt", "Virus signatures are {:.0} hours old", s.age_hours))
            } else {
                (CheckStatus::Ok, tr!("Virensignaturen sind aktuell", "Virus signatures are up to date"))
            };
            let engine = s.engine.clone().map(Text::same).unwrap_or_else(|| tr!("unbekannt", "unknown"));
            item(
                "signatures",
                Category::Schutz,
                status,
                title,
                tr!("Version {} vom {}, ClamAV {}.", "Version {} from {}, ClamAV {}.", s.version, s.date, engine),
            )
        }
    };
    if it.status != CheckStatus::Ok {
        it.fix = upd;
    }
    vec![it]
}

// ---------------------------------------------------------------------------
// Vigil-Dienst und clamd
// ---------------------------------------------------------------------------

fn check_services() -> Vec<CheckItem> {
    if clamd::ping(&clamd::clamd_socket()) {
        return vec![item(
            "services",
            Category::Schutz,
            CheckStatus::Ok,
            tr!("Vigil-Dienst und ClamAV laufen", "Vigil service and ClamAV are running"),
            tr!("Der Prüfdienst clamd ist bereit.", "The scanning service clamd is ready."),
        )];
    }
    let mut i = item(
        "services",
        Category::Schutz,
        CheckStatus::Warn,
        tr!("Der Prüfdienst von ClamAV läuft nicht", "The ClamAV scanning service is not running"),
        tr!(
            "Ohne clamd sind Prüfungen deutlich langsamer. Beim ersten Start lädt Vigil zuerst die Virendaten, das kann einige Minuten dauern.",
            "Without clamd scans are much slower. On first start Vigil downloads the virus data first, which can take a few minutes."
        ),
    );
    i.fix = fix("services-enable", tr!("Dienst neu starten", "Restart service"));
    vec![i]
}

// ---------------------------------------------------------------------------
// Windows Update
// ---------------------------------------------------------------------------

fn check_updates() -> Vec<CheckItem> {
    let what = tr!("Windows Update", "Windows Update");
    let script = format!(
        "$s=New-Object -ComObject Microsoft.Update.Session; \
         $r=$s.CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0\"); \
         $u=@($r.Updates | Where-Object {{ -not ($_.Categories | Where-Object {{ $_.CategoryID -eq '{DEFINITION_CATEGORY}' }}) }} | ForEach-Object {{ [pscustomobject]@{{ t=$_.Title; s=[bool]($_.Categories | Where-Object {{ $_.CategoryID -eq '{SECURITY_CATEGORY}' }}) }} }}); \
         $reboot=Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'; \
         [pscustomobject]@{{ updates=$u; reboot=$reboot }} | ConvertTo-Json -Compress -Depth 4"
    );
    let v = match powershell(&script, T_UPDATES) {
        Ok(v) => v,
        Err(e) => return vec![not_checked("updates", Category::Updates, &what, &e)],
    };
    let updates = as_list(v.get("updates").unwrap_or(&Value::Null));
    let (sec, other): (Vec<&Value>, Vec<&Value>) = updates.iter().partition(|u| get_bool(u, "s").unwrap_or(false));
    let reboot = get_bool(&v, "reboot").unwrap_or(false);
    let open_wu = fix("open-update-manager", tr!("Windows Update öffnen", "Open Windows Update"));
    let mut items = Vec::new();
    if updates.is_empty() {
        items.push(item(
            "updates",
            Category::Updates,
            CheckStatus::Ok,
            tr!("Windows ist aktuell", "Windows is up to date"),
            tr!("Windows Update meldet keine ausstehenden Updates.", "Windows Update reports no pending updates."),
        ));
    } else {
        let status = if sec.is_empty() { CheckStatus::Info } else { CheckStatus::Warn };
        let title = if sec.is_empty() && updates.len() == 1 {
            tr!("1 Update verfügbar", "1 update available")
        } else if sec.is_empty() {
            tr!("{} Updates verfügbar", "{} updates available", updates.len())
        } else if updates.len() == 1 {
            tr!("1 Sicherheitsupdate verfügbar", "1 security update available")
        } else {
            tr!(
                "{} Updates verfügbar, davon {} Sicherheitsupdates",
                "{} updates available, {} of them security updates",
                updates.len(),
                sec.len()
            )
        };
        let mut i = item(
            "updates",
            Category::Updates,
            status,
            title,
            tr!("Updates schließen Sicherheitslücken. Installieren über Windows Update.", "Updates close security holes. Install them via Windows Update."),
        );
        let list: Vec<Text> = sec
            .iter()
            .map(|u| tr!("Sicherheit: {}", "Security: {}", get_str(u, "t")))
            .chain(other.iter().map(|u| Text::same(get_str(u, "t"))))
            .collect();
        set_list(&mut i, list);
        i.fix = open_wu.clone();
        items.push(i);
    }
    if reboot {
        let mut i = item(
            "reboot",
            Category::Updates,
            CheckStatus::Warn,
            tr!("Neustart für Updates nötig", "Restart required for updates"),
            tr!(
                "Installierte Updates werden erst nach einem Neustart wirksam.",
                "Installed updates only take effect after a restart."
            ),
        );
        i.fix = open_wu;
        items.push(i);
    }
    items
}

// ---------------------------------------------------------------------------
// Microsoft Defender
// ---------------------------------------------------------------------------

fn check_defender() -> Vec<CheckItem> {
    let script = "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,IsTamperProtected | ConvertTo-Json -Compress";
    let open_sec = fix("open-windows-security", tr!("Windows-Sicherheit öffnen", "Open Windows Security"));
    let v = match powershell(script, T_SHORT) {
        Ok(v) => v,
        Err(_) => {
            return vec![item(
                "defender",
                Category::Schutz,
                CheckStatus::Info,
                tr!("Microsoft Defender ist nicht aktiv", "Microsoft Defender is not active"),
                tr!(
                    "Windows meldet keinen Zustand von Defender. Das ist normal, wenn ein anderer Virenschutz installiert ist.",
                    "Windows reports no Defender status. This is normal when another antivirus is installed."
                ),
            )]
        }
    };
    let enabled = get_bool(&v, "AntivirusEnabled").unwrap_or(false) && get_bool(&v, "AMServiceEnabled").unwrap_or(false);
    let realtime = get_bool(&v, "RealTimeProtectionEnabled").unwrap_or(false);
    let age = v.get("AntivirusSignatureAge").and_then(Value::as_i64).unwrap_or(0);
    let mut i = if !enabled {
        item(
            "defender",
            Category::Schutz,
            CheckStatus::Info,
            tr!("Microsoft Defender ist ausgeschaltet", "Microsoft Defender is turned off"),
            tr!(
                "Vigil prüft weiter nach Zeitplan und Downloads, ein Echtzeitschutz für alle Dateien fehlt aber.",
                "Vigil keeps scanning on schedule and checks downloads, but real-time protection for all files is missing."
            ),
        )
    } else if !realtime {
        item(
            "defender",
            Category::Schutz,
            CheckStatus::Warn,
            tr!("Echtzeitschutz von Defender ist aus", "Defender real-time protection is off"),
            tr!(
                "Defender prüft Dateien nicht beim Öffnen. Einschalten in der Windows-Sicherheit.",
                "Defender does not scan files when they are opened. Turn it on in Windows Security."
            ),
        )
    } else if age > 7 {
        item(
            "defender",
            Category::Schutz,
            CheckStatus::Warn,
            tr!("Defender-Virendaten sind {} Tage alt", "Defender virus data is {} days old", age),
            tr!("Defender aktualisiert sich über Windows Update.", "Defender updates itself via Windows Update."),
        )
    } else {
        item(
            "defender",
            Category::Schutz,
            CheckStatus::Ok,
            tr!("Microsoft Defender ist aktiv", "Microsoft Defender is active"),
            tr!(
                "Echtzeitschutz eingeschaltet, Virendaten {} Tage alt. Vigil arbeitet daneben.",
                "Real-time protection on, virus data {} days old. Vigil works alongside it.",
                age
            ),
        )
    };
    if i.status != CheckStatus::Ok {
        i.fix = open_sec;
    }
    vec![i]
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

fn check_firewall() -> Vec<CheckItem> {
    let what = tr!("Firewall", "Firewall");
    let v = match powershell("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress", T_SHORT) {
        Ok(v) => v,
        Err(e) => return vec![not_checked("firewall", Category::Netz, &what, &e)],
    };
    let profiles = as_list(&v);
    if profiles.is_empty() {
        return vec![not_checked("firewall", Category::Netz, &what, &tr!("Keine Profile gefunden.", "No profiles found."))];
    }
    let name_de = |n: &str| match n {
        "Domain" => "Domäne".to_string(),
        "Private" => "Privat".to_string(),
        "Public" => "Öffentlich".to_string(),
        o => o.to_string(),
    };
    let off: Vec<Text> = profiles
        .iter()
        .filter(|p| !get_bool(p, "Enabled").unwrap_or(false))
        .map(|p| {
            let n = get_str(p, "Name");
            Text::new(format!("Profil {} ist aus", name_de(&n)), format!("Profile {n} is off"))
        })
        .collect();
    if off.is_empty() {
        return vec![item(
            "firewall",
            Category::Netz,
            CheckStatus::Ok,
            tr!("Firewall ist eingeschaltet", "Firewall is turned on"),
            tr!("Die Windows-Firewall ist für alle Netzwerkprofile aktiv.", "The Windows firewall is active for all network profiles."),
        )];
    }
    let mut i = item(
        "firewall",
        Category::Netz,
        CheckStatus::Warn,
        tr!("Firewall ist teilweise ausgeschaltet", "Firewall is partly turned off"),
        tr!(
            "Eingehende Verbindungen werden in diesen Profilen nicht gefiltert. Beim Einschalten gelten die Standardregeln von Windows.",
            "Incoming connections are not filtered in these profiles. When turned on, the Windows default rules apply."
        ),
    );
    set_list(&mut i, off);
    i.fix = fix("firewall-enable", tr!("Firewall einschalten", "Turn on firewall"));
    vec![i]
}

// ---------------------------------------------------------------------------
// BitLocker
// ---------------------------------------------------------------------------

fn check_bitlocker() -> Vec<CheckItem> {
    let script = "Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object MountPoint,@{n='p';e={[int]$_.ProtectionStatus}},EncryptionPercentage | ConvertTo-Json -Compress";
    let v = match powershell(script, T_SHORT) {
        Ok(v) => v,
        Err(_) => {
            return vec![item(
                "bitlocker",
                Category::Haertung,
                CheckStatus::Info,
                tr!("BitLocker ist nicht verfügbar", "BitLocker is not available"),
                tr!(
                    "Diese Windows-Ausgabe bietet BitLocker nicht an oder der Zustand ist nicht abfragbar.",
                    "This Windows edition does not offer BitLocker or its state cannot be queried."
                ),
            )]
        }
    };
    let drive = get_str(&v, "MountPoint");
    let on = v.get("p").and_then(Value::as_i64) == Some(1);
    if on {
        return vec![item(
            "bitlocker",
            Category::Haertung,
            CheckStatus::Ok,
            tr!("Systemlaufwerk ist verschlüsselt", "System drive is encrypted"),
            tr!("BitLocker schützt {}.", "BitLocker protects {}.", drive),
        )];
    }
    vec![item(
        "bitlocker",
        Category::Haertung,
        CheckStatus::Info,
        tr!("Systemlaufwerk ist nicht verschlüsselt", "System drive is not encrypted"),
        tr!(
            "Bei Verlust oder Diebstahl des Geräts sind die Daten auf {} lesbar. Empfohlen für Notebooks.",
            "If the device is lost or stolen, the data on {} can be read. Recommended for laptops.",
            drive
        ),
    )]
}

// ---------------------------------------------------------------------------
// Offene Ports
// ---------------------------------------------------------------------------

fn check_ports() -> Vec<CheckItem> {
    let what = tr!("Offene Ports", "Open ports");
    let script = "$p=@{}; Get-Process | ForEach-Object { $p[[int]$_.Id]=$_.ProcessName }; \
        $t=@(Get-NetTCPConnection -State Listen | ForEach-Object { [pscustomobject]@{ k='TCP'; a=$_.LocalAddress; o=$_.LocalPort; n=$p[[int]$_.OwningProcess] } }); \
        $u=@(Get-NetUDPEndpoint | ForEach-Object { [pscustomobject]@{ k='UDP'; a=$_.LocalAddress; o=$_.LocalPort; n=$p[[int]$_.OwningProcess] } }); \
        ConvertTo-Json -Compress -InputObject @($t+$u)";
    let v = match powershell(script, T_SHORT) {
        Ok(v) => v,
        Err(e) => return vec![not_checked("ports", Category::Netz, &what, &e)],
    };
    let mut list: Vec<String> = Vec::new();
    for e in as_list(&v) {
        let host = get_str(&e, "a");
        let ip = host.split('%').next().unwrap_or(&host).parse::<std::net::IpAddr>().ok();
        // Loopback und Multicast sind keine offenen Ports nach außen
        if ip.map(|ip| ip.is_loopback() || ip.is_multicast()).unwrap_or(true) {
            continue;
        }
        let host = if host.contains(':') { format!("[{host}]") } else { host };
        let name = get_str(&e, "n");
        let entry = if name.is_empty() {
            format!("{} {host}:{}", get_str(&e, "k"), get_str(&e, "o"))
        } else {
            format!("{} {host}:{} ({name})", get_str(&e, "k"), get_str(&e, "o"))
        };
        if !list.contains(&entry) {
            list.push(entry);
        }
    }
    if list.is_empty() {
        return vec![item(
            "ports",
            Category::Netz,
            CheckStatus::Ok,
            tr!("Keine offenen Ports nach außen", "No ports open to the outside"),
            tr!("Kein Dienst lauscht außerhalb von Loopback.", "No service is listening outside of loopback."),
        )];
    }
    let mut i = item(
        "ports",
        Category::Netz,
        CheckStatus::Info,
        tr!("{} Dienste lauschen im Netzwerk", "{} services are listening on the network", list.len()),
        tr!(
            "Diese Dienste sind von anderen Geräten aus erreichbar, sofern die Firewall sie nicht blockiert.",
            "These services can be reached from other devices unless the firewall blocks them."
        ),
    );
    set_list(&mut i, list.into_iter().map(Text::same).collect());
    vec![i]
}

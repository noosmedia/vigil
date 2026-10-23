//! Systemcheck: Signaturen, ClamAV-Dienste, Systemupdates, Firewall, offene Ports,
//! rkhunter, Lynis. Ergebnis in system.json, Fortschritt als Auftrag in state.json.
//! Prüfungen, die root brauchen, enden ohne Rechte als Hinweis statt mit einem Absturz.

use crate::cmd::{self, CmdOutput};
use crate::fsutil;
use crate::i18n::Text;
use crate::paths;
use crate::state::{new_job, StateWriter};
use crate::sysinfo;
use crate::tr;
use crate::types::{Category, CheckItem, CheckStatus, Fix, Job, JobKind, Phase, SystemReport, Trigger};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Ein Prüfschritt liefert einen oder mehrere Prüfpunkte.
type CheckFn = fn() -> Vec<CheckItem>;

const T_SHORT: Duration = Duration::from_secs(60);
const T_LONG: Duration = Duration::from_secs(20 * 60);

/// Liest system.json (`None`, wenn noch kein Systemcheck lief).
pub fn read_system() -> Result<Option<SystemReport>, Text> {
    fsutil::read_json(&paths::system_path())
}

fn is_root() -> bool {
    // SAFETY: geteuid hat keine Vorbedingungen
    unsafe { libc::geteuid() == 0 }
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

fn same_list(v: Vec<String>) -> Vec<Text> {
    v.into_iter().map(Text::same).collect()
}

fn fix(action: &str, label: Text) -> Option<Fix> {
    Some(Fix { action: action.into(), label: label.de, label_en: label.en })
}

/// Führt den Systemcheck als Auftrag `systemcheck` aus und schreibt system.json.
pub fn run_systemcheck(trigger: Trigger) -> Job {
    let mut writer = StateWriter::new();
    let mut job = new_job(JobKind::Systemcheck, trigger, Vec::new());
    // Fortschritt in Schritten: total = Anzahl Schritte, scanned = erledigte Schritte
    let steps: [(Text, CheckFn); 7] = [
        (tr!("Virensignaturen", "Virus signatures"), check_signatures),
        (tr!("ClamAV-Dienste", "ClamAV services"), check_services),
        (tr!("Systemupdates", "System updates"), check_updates),
        (tr!("Firewall", "Firewall"), check_firewall),
        (tr!("Offene Ports", "Open ports"), check_ports),
        (tr!("Rootkit-Suche (rkhunter)", "Rootkit scan (rkhunter)"), check_rkhunter),
        (tr!("Systemhärtung (Lynis)", "System hardening (Lynis)"), check_lynis),
    ];
    job.total = steps.len() as u64;
    job.counted = true;
    LAST_HARDENING.with(|h| h.set(None));
    writer.force(&job);

    let mut items = Vec::new();
    for (label, f) in steps {
        job.set_current(Some(&label));
        writer.force(&job);
        items.extend(f());
        job.scanned += 1;
    }

    let report = SystemReport {
        checked_at: crate::now_rfc3339(),
        signatures: sysinfo::signature_info(),
        hardening_index: LAST_HARDENING.with(|h| h.get()),
        items,
    };
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
            job.set_message(&tr!(
                "Systemcheck abgeschlossen: {} kritisch, {}.",
                "System check finished: {} critical, {}.",
                crit,
                warnings
            ));
        }
        Err(e) => {
            job.phase = Phase::Failed;
            job.set_message(&tr!(
                "Der Systemcheck konnte nicht gespeichert werden: {}",
                "Could not save the system check: {}",
                e
            ));
        }
    }
    writer.force(&job);
    job
}

thread_local! {
    // Härtungsindex aus dem Lynis-Lauf (wird von check_lynis gesetzt)
    static LAST_HARDENING: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

// ---------------------------------------------------------------------------
// Signaturen
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
                (
                    CheckStatus::Warn,
                    tr!("Virensignaturen sind {:.0} Stunden alt", "Virus signatures are {:.0} hours old", s.age_hours),
                )
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
// Dienste
// ---------------------------------------------------------------------------

fn check_services() -> Vec<CheckItem> {
    let mut inactive = Vec::new();
    for svc in ["clamav-freshclam", "clamav-daemon"] {
        let state = match cmd::run_named("systemctl", &["is-active", svc], T_SHORT) {
            Ok(o) => Text::same(o.stdout.trim()),
            Err(e) => e,
        };
        let state = if state.is_empty() { tr!("unbekannt", "unknown") } else { state };
        if state.de != "active" {
            inactive.push(tr!("{}: {}", "{}: {}", svc, state));
        }
    }
    if inactive.is_empty() {
        return vec![item(
            "services",
            Category::Schutz,
            CheckStatus::Ok,
            tr!("ClamAV-Dienste laufen", "ClamAV services are running"),
            tr!("clamav-freshclam und clamav-daemon sind aktiv.", "clamav-freshclam and clamav-daemon are active."),
        )];
    }
    let mut i = item(
        "services",
        Category::Schutz,
        CheckStatus::Warn,
        tr!("ClamAV-Dienste laufen nicht vollständig", "ClamAV services are not fully running"),
        tr!(
            "Ohne clamav-freshclam veralten die Signaturen, ohne clamav-daemon sind Prüfungen deutlich langsamer.",
            "Without clamav-freshclam the signatures become outdated, without clamav-daemon scans are much slower."
        ),
    );
    set_list(&mut i, inactive);
    i.fix = fix("services-enable", tr!("Dienste einschalten", "Turn on services"));
    vec![i]
}

// ---------------------------------------------------------------------------
// Systemupdates
// ---------------------------------------------------------------------------

/// Wertet `apt list --upgradable` aus: (Sicherheitsupdates, übrige Updates) als Paketzeilen.
pub fn parse_apt_upgradable(out: &str) -> (Vec<String>, Vec<String>) {
    let mut sec = Vec::new();
    let mut other = Vec::new();
    for line in out.lines() {
        // Format: paket/noble-updates,noble-security 1.2-3 amd64 [upgradable from: 1.2-2]
        let Some((name, rest)) = line.split_once('/') else { continue };
        if name.trim().is_empty() || line.starts_with("Listing") || line.starts_with("WARNING") {
            continue;
        }
        let mut parts = rest.split_whitespace();
        let suites = parts.next().unwrap_or("");
        let version = parts.next().unwrap_or("");
        let entry = format!("{name} {version}").trim().to_string();
        if suites.split(',').any(|s| s.ends_with("-security")) {
            sec.push(entry);
        } else {
            other.push(entry);
        }
    }
    (sec, other)
}

fn check_updates() -> Vec<CheckItem> {
    let what = tr!("Systemupdates", "System updates");
    // /usr/bin/apt direkt, unter Linux Mint liegt in /usr/local/bin ein Wrapper
    let out = match cmd::run(Path::new("/usr/bin/apt"), &["list", "--upgradable"], T_SHORT) {
        Ok(o) if o.success() => o,
        Ok(o) => return vec![not_checked("updates", Category::Updates, &what, &o.error_text())],
        Err(e) => return vec![not_checked("updates", Category::Updates, &what, &e)],
    };
    let (sec, other) = parse_apt_upgradable(&out.stdout);
    let open_fix = fix("open-update-manager", tr!("Aktualisierungsverwaltung öffnen", "Open Update Manager"));
    if sec.is_empty() && other.is_empty() {
        return vec![item(
            "updates",
            Category::Updates,
            CheckStatus::Ok,
            tr!("Das System ist aktuell", "The system is up to date"),
            tr!("Es stehen keine Updates aus.", "There are no pending updates."),
        )];
    }
    let (status, title) = if !sec.is_empty() {
        (
            CheckStatus::Warn,
            tr!(
                "{} Sicherheitsupdates und {} weitere Updates verfügbar",
                "{} security updates and {} other updates available",
                sec.len(),
                other.len()
            ),
        )
    } else {
        (CheckStatus::Info, tr!("{} Updates verfügbar", "{} updates available", other.len()))
    };
    let mut i = item(
        "updates",
        Category::Updates,
        status,
        title,
        tr!(
            "Stand der Paketquellen der Aktualisierungsverwaltung. Sicherheitsupdates sollten zeitnah eingespielt werden.",
            "Based on the package sources of the Update Manager. Security updates should be installed promptly."
        ),
    );
    let list = sec
        .iter()
        .map(|s| tr!("{} (Sicherheitsupdate)", "{} (security update)", s))
        .chain(other.into_iter().map(Text::same))
        .collect();
    set_list(&mut i, list);
    i.fix = open_fix;
    vec![i]
}

fn not_checked(id: &str, cat: Category, what: &Text, why: &Text) -> CheckItem {
    let why = Text::new(why.de.trim(), why.en.trim());
    item(id, cat, CheckStatus::Info, tr!("{}: konnte nicht geprüft werden", "{}: could not be checked", *what), why)
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

fn check_firewall() -> Vec<CheckItem> {
    let what = tr!("Firewall", "Firewall");
    let Some(ufw) = cmd::find_program("ufw") else {
        return vec![item(
            "firewall",
            Category::Netz,
            CheckStatus::Warn,
            tr!("Firewall (ufw) ist nicht installiert", "Firewall (ufw) is not installed"),
            tr!("Das Paket ufw fehlt.", "The ufw package is missing."),
        )];
    };
    // Mit root: tatsächlicher Zustand; ohne root: eingestellter Zustand aus ufw.conf
    let active = if is_root() {
        match cmd::run(&ufw, &["status"], T_SHORT) {
            Ok(o) if o.success() => Some(o.stdout.contains("Status: active")),
            Ok(o) => return vec![not_checked("firewall", Category::Netz, &what, &o.error_text())],
            Err(e) => return vec![not_checked("firewall", Category::Netz, &what, &e)],
        }
    } else {
        fs::read_to_string("/etc/ufw/ufw.conf").ok().map(|t| {
            t.lines().any(|l| l.trim().replace(' ', "").eq_ignore_ascii_case("ENABLED=yes"))
        })
    };
    match active {
        Some(true) => vec![item(
            "firewall",
            Category::Netz,
            CheckStatus::Ok,
            tr!("Firewall ist eingeschaltet", "Firewall is turned on"),
            tr!("ufw ist aktiv.", "ufw is active."),
        )],
        Some(false) => {
            let mut i = item(
                "firewall",
                Category::Netz,
                CheckStatus::Warn,
                tr!("Firewall ist ausgeschaltet", "Firewall is turned off"),
                tr!(
                    "Eingehende Verbindungen werden nicht gefiltert. Beim Einschalten werden eingehende Verbindungen standardmäßig abgelehnt.",
                    "Incoming connections are not filtered. When turned on, incoming connections are denied by default."
                ),
            );
            i.fix = fix("firewall-enable", tr!("Firewall einschalten", "Turn on firewall"));
            vec![i]
        }
        None => vec![not_checked(
            "firewall",
            Category::Netz,
            &what,
            &tr!("Zustand von ufw nicht lesbar.", "The state of ufw is not readable."),
        )],
    }
}

// ---------------------------------------------------------------------------
// Offene Ports
// ---------------------------------------------------------------------------

/// Wertet `ss -tulpnH` aus und liefert nur Ports, die nicht nur auf Loopback lauschen.
pub fn parse_ss(out: &str) -> Vec<String> {
    let mut v = Vec::new();
    for line in out.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 {
            continue;
        }
        let proto = cols[0];
        let local = cols[4];
        let Some((addr, port)) = local.rsplit_once(':') else { continue };
        let host = addr.split('%').next().unwrap_or(addr).trim_start_matches('[').trim_end_matches(']');
        // Loopback und Multicast (z. B. mDNS-Empfänger) sind keine offenen Ports nach außen
        let multicast = host.parse::<std::net::IpAddr>().map(|ip| ip.is_multicast()).unwrap_or(false);
        if host.starts_with("127.") || host == "::1" || host == "localhost" || addr.ends_with("%lo") || multicast {
            continue;
        }
        let host = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
        let process = cols
            .get(6..)
            .map(|r| r.join(" "))
            .and_then(|p| p.split("((\"").nth(1).map(|s| s.split('"').next().unwrap_or("").to_string()))
            .filter(|p| !p.is_empty());
        let entry = match process {
            Some(p) => format!("{proto} {host}:{port} ({p})"),
            None => format!("{proto} {host}:{port}"),
        };
        if !v.contains(&entry) {
            v.push(entry);
        }
    }
    v
}

fn check_ports() -> Vec<CheckItem> {
    let what = tr!("Offene Ports", "Open ports");
    let out = match cmd::run_named("ss", &["-tulpnH"], T_SHORT) {
        Ok(o) if o.success() => o,
        Ok(o) => return vec![not_checked("ports", Category::Netz, &what, &o.error_text())],
        Err(e) => return vec![not_checked("ports", Category::Netz, &what, &e)],
    };
    let list = parse_ss(&out.stdout);
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
    set_list(&mut i, same_list(list));
    vec![i]
}

// ---------------------------------------------------------------------------
// rkhunter
// ---------------------------------------------------------------------------

/// Fasst rkhunter-Warnungen zusammen (Folgezeilen gehören zur vorherigen Warnung).
pub fn parse_rkhunter(out: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for line in out.lines() {
        if let Some(w) = line.strip_prefix("Warning:") {
            v.push(w.trim().to_string());
        } else if line.starts_with(char::is_whitespace) && !line.trim().is_empty() {
            if let Some(last) = v.last_mut() {
                last.push(' ');
                last.push_str(line.trim());
            }
        }
    }
    v
}

fn check_rkhunter() -> Vec<CheckItem> {
    let what = tr!("Rootkit-Suche", "Rootkit scan");
    let Some(rk) = cmd::find_program("rkhunter") else {
        return vec![item(
            "rkhunter",
            Category::Rootkit,
            CheckStatus::Warn,
            tr!("rkhunter ist nicht installiert", "rkhunter is not installed"),
            tr!("Die Rootkit-Suche ist nicht verfügbar.", "The rootkit scan is not available."),
        )];
    };
    if !is_root() {
        return vec![not_checked(
            "rkhunter",
            Category::Rootkit,
            &what,
            &tr!("rkhunter benötigt Administratorrechte.", "rkhunter needs administrator rights."),
        )];
    }
    // Einmalig den Ausgangsstand erfassen, wenn noch keine Datenbank existiert
    let mut note = Text::default();
    if !Path::new("/var/lib/rkhunter/db/rkhunter.dat").exists() {
        let failed = |e: Text| {
            tr!(
                "Der Ausgangsstand konnte nicht erfasst werden: {}",
                "The baseline could not be recorded: {}",
                e
            )
        };
        note = match cmd::run(&rk, &["--propupd", "--nocolors"], T_LONG) {
            Ok(o) if o.success() => tr!("Der Ausgangsstand wurde erstmals erfasst.", "The baseline was recorded for the first time."),
            Ok(o) => failed(o.error_text()),
            Err(e) => failed(e),
        };
    }
    let out = match cmd::run(&rk, &["--check", "--sk", "--nocolors", "--rwo"], T_LONG) {
        Ok(o) => o,
        Err(e) => return vec![not_checked("rkhunter", Category::Rootkit, &what, &e)],
    };
    let warnings = parse_rkhunter(&out.stdout);
    if warnings.is_empty() && !matches!(out.code, Some(0) | Some(1)) {
        let why = tr!("rkhunter: {}", "rkhunter: {}", out.error_text());
        return vec![not_checked("rkhunter", Category::Rootkit, &what, &why)];
    }
    if warnings.is_empty() {
        return vec![item(
            "rkhunter",
            Category::Rootkit,
            CheckStatus::Ok,
            tr!("Keine Auffälligkeiten bei der Rootkit-Suche", "No anomalies found by the rootkit scan"),
            Text::join(&[tr!("rkhunter hat nichts gemeldet.", "rkhunter reported nothing."), note]),
        )];
    }
    let mut i = item(
        "rkhunter",
        Category::Rootkit,
        CheckStatus::Warn,
        tr!("rkhunter meldet {} Auffälligkeiten", "rkhunter reports {} anomalies", warnings.len()),
        Text::join(&[
            tr!(
                "Oft sind das harmlose Änderungen durch Systemupdates. Den Ausgangsstand nur neu erfassen, wenn die Änderungen erklärbar sind.",
                "These are often harmless changes caused by system updates. Only record the baseline again if the changes can be explained."
            ),
            note,
        ]),
    );
    set_list(&mut i, same_list(warnings));
    i.fix = fix("rkhunter-baseline", tr!("Ausgangsstand neu erfassen", "Record baseline again"));
    vec![i]
}

// ---------------------------------------------------------------------------
// Lynis
// ---------------------------------------------------------------------------

/// Ergebnis aus lynis-report.dat.
#[derive(Debug, Default, PartialEq)]
pub struct LynisReport {
    pub hardening_index: Option<u32>,
    pub warnings: Vec<String>,
    pub suggestions: Vec<String>,
}

/// Wertet `/var/log/lynis-report.dat` aus (`hardening_index`, `warning[]`, `suggestion[]`).
pub fn parse_lynis_report(text: &str) -> LynisReport {
    let mut r = LynisReport::default();
    let entry = |v: &str| -> String {
        // Format: TEST-ID|Text|Details|Lösung|
        let f: Vec<&str> = v.split('|').collect();
        let id = f.first().copied().unwrap_or("").trim();
        let text = f.get(1).copied().unwrap_or("").trim();
        let details = f.get(2).copied().unwrap_or("").trim();
        let mut s = text.to_string();
        if !details.is_empty() && details != "-" {
            s.push_str(&format!(" ({details})"));
        }
        if !id.is_empty() {
            s.push_str(&format!(" [{id}]"));
        }
        s
    };
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("hardening_index=") {
            r.hardening_index = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("warning[]=") {
            r.warnings.push(entry(v));
        } else if let Some(v) = line.strip_prefix("suggestion[]=") {
            r.suggestions.push(entry(v));
        }
    }
    r
}

fn check_lynis() -> Vec<CheckItem> {
    let what = tr!("Systemhärtung", "System hardening");
    let Some(lynis) = cmd::find_program("lynis") else {
        return vec![item(
            "lynis-warnings",
            Category::Haertung,
            CheckStatus::Warn,
            tr!("Lynis ist nicht installiert", "Lynis is not installed"),
            tr!("Die Prüfung der Systemhärtung ist nicht verfügbar.", "The system hardening check is not available."),
        )];
    };
    if !is_root() {
        return vec![not_checked(
            "lynis-warnings",
            Category::Haertung,
            &what,
            &tr!("Lynis benötigt Administratorrechte.", "Lynis needs administrator rights."),
        )];
    }
    let report_path = Path::new("/var/log/lynis-report.dat");
    let started = SystemTime::now() - Duration::from_secs(2);
    let out: CmdOutput = match cmd::run(&lynis, &["audit", "system", "--quick", "--no-colors", "--quiet"], T_LONG) {
        Ok(o) => o,
        Err(e) => return vec![not_checked("lynis-warnings", Category::Haertung, &what, &e)],
    };
    // Nur einen frisch geschriebenen Bericht verwenden
    let fresh = fs::metadata(report_path).and_then(|m| m.modified()).map(|t| t >= started).unwrap_or(false);
    if !fresh {
        let why = tr!(
            "Lynis hat keinen neuen Bericht geschrieben: {}",
            "Lynis did not write a new report: {}",
            out.error_text()
        );
        return vec![not_checked("lynis-warnings", Category::Haertung, &what, &why)];
    }
    let text = match fs::read_to_string(report_path) {
        Ok(t) => t,
        Err(e) => {
            let why = tr!("{}: {}", "{}: {}", report_path.display(), e);
            return vec![not_checked("lynis-warnings", Category::Haertung, &what, &why)];
        }
    };
    let r = parse_lynis_report(&text);
    LAST_HARDENING.with(|h| h.set(r.hardening_index));

    let idx = r
        .hardening_index
        .map(|i| tr!("Härtungsindex {} von 100.", "Hardening index {} out of 100.", i))
        .unwrap_or_default();
    let mut w = if r.warnings.is_empty() {
        item(
            "lynis-warnings",
            Category::Haertung,
            CheckStatus::Ok,
            tr!("Lynis meldet keine Warnungen", "Lynis reports no warnings"),
            idx.clone(),
        )
    } else {
        item(
            "lynis-warnings",
            Category::Haertung,
            CheckStatus::Warn,
            tr!("Lynis meldet {} Warnungen", "Lynis reports {} warnings", r.warnings.len()),
            idx.clone(),
        )
    };
    set_list(&mut w, same_list(r.warnings));
    let mut s = if r.suggestions.is_empty() {
        item(
            "lynis-suggestions",
            Category::Haertung,
            CheckStatus::Ok,
            tr!("Keine Vorschläge zur Härtung", "No hardening suggestions"),
            idx,
        )
    } else {
        item(
            "lynis-suggestions",
            Category::Haertung,
            CheckStatus::Info,
            tr!("{} Vorschläge zur Härtung", "{} hardening suggestions", r.suggestions.len()),
            tr!(
                "Empfehlungen von Lynis. Nicht jeder Vorschlag passt zu einem Arbeitsplatzrechner.",
                "Recommendations from Lynis. Not every suggestion suits a desktop computer."
            ),
        )
    };
    set_list(&mut s, same_list(r.suggestions));
    vec![w, s]
}

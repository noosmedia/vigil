//! Dateiprüfung: Zählphase, dann Prüfphase mit parallelen clamd-Verbindungen (zFILDES,
//! Ausweichweg zINSTREAM), clamscan als Ausweichweg ohne clamd. Die Prüfwurzeln werden in
//! Bereiche zerlegt (Segmente für die Prüfanimation), die in fester Reihenfolge gezählt und
//! geprüft werden. Schreibt state.json und am Ende den Bericht.

use crate::clamd::{self, Verdict, MAX_SCAN_SIZE};
use crate::config;
use crate::engine::{self, Engine};
use crate::fsutil::{self, sha256_reader};
use crate::i18n::Text;
use crate::paths;
use crate::quarantine;
use crate::quick::{self, Homes, Target};
use crate::reports;
use crate::state::{new_job, StateWriter};
use crate::sysinfo;
use crate::tr;
use crate::types::{
    Config, EngineKind, Job, JobKind, OnThreat, Phase, Report, Segment, Threat, ThreatAction, Trigger,
};
use std::collections::HashMap;
#[cfg(unix)]
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, ErrorKind, Read};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

/// Immer ausgeschlossen (`/dev` außer `/dev/shm`).
#[cfg(unix)]
pub const ALWAYS_EXCLUDED: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/var/lib/vigil",
    "/var/lib/clamav",
    "/swapfile",
    "/swap.img",
];

/// Immer ausgeschlossen unter Windows: Auslagerungs- und Ruhezustandsdateien sowie
/// Systemwiederherstellung auf jedem Laufwerk (gesperrt oder nicht lesbar).
#[cfg(windows)]
fn always_excluded() -> Vec<PathBuf> {
    let mut v = Vec::new();
    for (root, _) in crate::win::drives() {
        for n in ["pagefile.sys", "swapfile.sys", "hiberfil.sys", "DumpStack.log.tmp", "System Volume Information"] {
            v.push(root.join(n));
        }
    }
    v
}

#[cfg(unix)]
fn always_excluded() -> Vec<PathBuf> {
    ALWAYS_EXCLUDED.iter().map(PathBuf::from).collect()
}

/// Höchstzahl der Bereiche in state.json; ab dem 24. wird zu „Weitere“ zusammengefasst.
pub const MAX_SEGMENTS: usize = 24;

/// Höchstzahl paralleler clamd-Verbindungen (zusätzlich begrenzt durch die Zahl der CPUs).
pub const MAX_CONNECTIONS: usize = 12;

/// Auftrag für eine Dateiprüfung.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub kind: JobKind,
    pub trigger: Trigger,
    /// Nur bei `custom`: absolute Pfade.
    pub paths: Vec<PathBuf>,
}

/// Ausschlussliste.
#[derive(Clone)]
struct Exclusions {
    list: Vec<PathBuf>,
}

impl Exclusions {
    fn new(cfg: &Config, kind: JobKind) -> Self {
        let mut list: Vec<PathBuf> = always_excluded();
        // Im Testbetrieb liegen Daten und Signaturen woanders
        list.push(paths::data_dir());
        list.push(sysinfo::database_dir());
        list.extend(cfg.scan.exclude_paths.iter().map(PathBuf::from));
        if kind == JobKind::Full && !cfg.scan.include_mounts {
            #[cfg(unix)]
            {
                list.push("/mnt".into());
                list.push("/media".into());
            }
            // Windows: USB-Laufwerke, Netzlaufwerke und CDs nur mit includeMounts
            #[cfg(windows)]
            list.extend(
                crate::win::drives().into_iter().filter(|(_, k)| *k != crate::win::DRIVE_FIXED).map(|(r, _)| r),
            );
        }
        Exclusions { list }
    }

    fn is_excluded(&self, p: &Path) -> bool {
        self.list.iter().any(|e| {
            paths::starts_with(p, e) && !(e.as_os_str() == "/dev" && p.starts_with("/dev/shm"))
        })
    }
}

/// Startordner bei vollständiger und benutzerdefinierter Prüfung. Verschachtelte Ordner
/// werden nur einmal geprüft.
fn roots_for(req: &ScanRequest) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = match req.kind {
        #[cfg(unix)]
        JobKind::Full => vec!["/".into(), "/dev/shm".into()],
        // Windows: alle Laufwerke außer CDs und virtuellen RAM-Laufwerken (externe schließt
        // die Ausschlussliste ohne includeMounts aus)
        #[cfg(windows)]
        JobKind::Full => crate::win::drives().into_iter().filter(|(_, k)| matches!(k, 2..=4)).map(|(r, _)| r).collect(),
        _ => req.paths.clone(),
    };
    roots.retain(|p| std::fs::symlink_metadata(p).is_ok());
    roots.sort();
    roots.dedup();
    let all = roots.clone();
    roots.retain(|r| !all.iter().any(|o| o != r && r.starts_with(o) && !(o.as_os_str() == "/" && r.starts_with("/dev"))));
    roots
}

// ---------------------------------------------------------------------------
// Bereiche
// ---------------------------------------------------------------------------

/// Woher die Dateien eines Bereichs kommen.
#[derive(Clone)]
enum Source {
    /// Ganzer Baum ab diesem Pfad (Ordner oder einzelne Datei).
    Tree(PathBuf),
    /// Nur Dateien direkt in diesem Ordner.
    Shallow(PathBuf),
    /// Feste Dateiliste (Programme laufender Prozesse).
    Files(Vec<PathBuf>),
}

/// Ein Bereich der Prüfung. Bereiche werden in Listenreihenfolge gezählt und geprüft.
struct Area {
    label: Text,
    path: Option<PathBuf>,
    source: Source,
    files: u64,
}

/// Ein Eintrag beim Durchlauf eines Bereichs.
enum Entry {
    File(PathBuf),
    Error,
}

/// Dateien eines Bereichs (ohne Verfolgen von Verknüpfungen, ausgeschlossene Pfade entfallen).
fn entries<'a>(src: &'a Source, excl: &'a Exclusions) -> Box<dyn Iterator<Item = Entry> + 'a> {
    let walk = |w: WalkDir| {
        let excl = excl.clone();
        w.follow_links(false).into_iter().filter_entry(move |e| !excl.is_excluded(e.path())).filter_map(|r| match r {
            Ok(e) if e.file_type().is_file() => Some(Entry::File(e.into_path())),
            Ok(_) => None,
            Err(_) => Some(Entry::Error),
        })
    };
    match src {
        Source::Tree(p) => Box::new(walk(WalkDir::new(p))),
        Source::Shallow(p) => Box::new(walk(WalkDir::new(p).min_depth(1).max_depth(1))),
        Source::Files(list) => Box::new(list.iter().filter_map(|p| match std::fs::symlink_metadata(p) {
            Ok(m) if m.is_file() => Some(Entry::File(p.clone())),
            Ok(_) => None,
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(_) => Some(Entry::Error),
        })),
    }
}

/// Bereiche einer Prüfung und die Wurzeln für `paths` (in Prüfreihenfolge).
fn plan(req: &ScanRequest, excl: &Exclusions, homes: &Homes) -> (Vec<Area>, Vec<String>) {
    let mut areas = Vec::new();
    let mut roots = Vec::new();
    if req.kind == JobKind::Quick {
        // Schnellprüfung: jeder Zielpunkt ist ein Bereich
        for t in quick::targets(homes, |p| excl.is_excluded(p)) {
            match t {
                Target::Path(p) => {
                    roots.push(paths::display(&p));
                    areas.push(Area { label: Text::same(homes.label(&p)), path: Some(p.clone()), source: Source::Tree(p), files: 0 });
                }
                Target::Programs(list) => {
                    roots.extend(list.iter().map(|p| paths::display(p)));
                    areas.push(Area { label: quick::programs_label(), path: None, source: Source::Files(list), files: 0 });
                }
            }
        }
        return (areas, roots);
    }
    // Sonst: Dateien direkt in der Wurzel, dann jeder direkte Unterordner (nach Namen sortiert)
    for root in roots_for(req) {
        roots.push(paths::display(&root));
        if excl.is_excluded(&root) {
            continue;
        }
        let area = |p: &Path, source: Source| Area { label: Text::same(homes.label(p)), path: Some(p.to_path_buf()), source, files: 0 };
        let is_dir = std::fs::symlink_metadata(&root).map(|m| m.is_dir()).unwrap_or(false);
        let children = is_dir.then(|| std::fs::read_dir(&root).ok()).flatten();
        match children {
            Some(rd) => {
                let mut kids: Vec<PathBuf> = rd
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                    .map(|e| e.path())
                    .filter(|p| !excl.is_excluded(p))
                    .collect();
                kids.sort();
                areas.push(area(&root, Source::Shallow(root.clone())));
                for k in kids {
                    areas.push(area(&k, Source::Tree(k.clone())));
                }
            }
            // Datei oder unlesbarer Ordner: als Ganzes (Lesefehler zählt der Durchlauf)
            None => areas.push(area(&root, Source::Tree(root.clone()))),
        }
    }
    (areas, roots)
}

/// Segmente für state.json: Bereiche mit Dateien, höchstens 24, der Rest als „Weitere“.
/// Dazu je Bereich der Index seines Segments (leere Bereiche zählen zum vorherigen).
fn segment_view(areas: &[Area]) -> (Vec<Segment>, Vec<u32>) {
    let visible: Vec<usize> = (0..areas.len()).filter(|&i| areas[i].files > 0).collect();
    let keep = if visible.len() > MAX_SEGMENTS { MAX_SEGMENTS - 1 } else { visible.len() };
    let mut segs = Vec::with_capacity(keep + 1);
    let mut map = vec![u32::MAX; areas.len()];
    let mut other = 0u64;
    for (k, &i) in visible.iter().enumerate() {
        if k < keep {
            let a = &areas[i];
            segs.push(Segment {
                label: a.label.de.clone(),
                label_en: a.label.en.clone(),
                path: a.path.as_deref().map(paths::display),
                files: a.files,
            });
            map[i] = k as u32;
        } else {
            other += areas[i].files;
            map[i] = keep as u32;
        }
    }
    if visible.len() > keep {
        let t = tr!("Weitere", "Other");
        segs.push(Segment { label: t.de, label_en: t.en, path: None, files: other });
    }
    let mut last = 0;
    for m in map.iter_mut() {
        if *m == u32::MAX {
            *m = last;
        } else {
            last = *m;
        }
    }
    (segs, map)
}

// ---------------------------------------------------------------------------
// Abbruch und Pause
// ---------------------------------------------------------------------------

/// Prüft Abbruch und Pause alle 200 Aufrufe, zusätzlich spätestens alle 0,5 s.
/// Beim Anhalten wird die Phase `paused` gesetzt (und clamscan per SIGSTOP angehalten),
/// beim Fortsetzen die vorherige Phase wiederhergestellt.
struct Control {
    n: u64,
    last: Instant,
    cancelled: bool,
    /// Für Arbeiter und Durchlauf: solange true, wird nichts Neues begonnen.
    paused: Arc<AtomicBool>,
    prev_phase: Phase,
    pause_started: Option<Instant>,
    paused_total: Duration,
    /// Laufender clamscan-Prozess (wird mit SIGSTOP/SIGCONT angehalten).
    #[cfg(unix)]
    child: Option<libc::pid_t>,
    /// Laufender clamscan-Prozess (wird über seine Threads angehalten).
    #[cfg(windows)]
    child: Option<u32>,
}

impl Control {
    fn new() -> Self {
        Control {
            n: 0,
            last: Instant::now(),
            cancelled: false,
            paused: Arc::new(AtomicBool::new(false)),
            prev_phase: Phase::Counting,
            pause_started: None,
            paused_total: Duration::ZERO,
            child: None,
        }
    }

    fn is_paused(&self) -> bool {
        self.pause_started.is_some()
    }

    /// Bisher pausierte Zeit (einschließlich einer laufenden Pause).
    fn paused_time(&self) -> Duration {
        self.paused_total + self.pause_started.map(|t| t.elapsed()).unwrap_or_default()
    }

    /// Liefert true, wenn abgebrochen werden soll. Schaltet Pause und Fortsetzen um.
    fn poll(&mut self, job: &mut Job, writer: &mut StateWriter) -> bool {
        self.n += 1;
        if self.cancelled || !(self.n.is_multiple_of(200) || self.last.elapsed() >= Duration::from_millis(500)) {
            return self.cancelled;
        }
        self.last = Instant::now();
        self.cancelled = crate::cancel_requested();
        if self.cancelled {
            return true;
        }
        let want = crate::pause_requested();
        if want && !self.is_paused() {
            self.prev_phase = job.phase;
            job.phase = Phase::Paused;
            self.pause_started = Some(Instant::now());
            self.paused.store(true, Ordering::Relaxed);
            self.stop_child();
            writer.force(job);
        } else if !want && self.is_paused() {
            self.resume(job);
            writer.force(job);
        }
        false
    }

    /// Setzt nach einer Pause fort (Phase, Arbeiter, clamscan).
    fn resume(&mut self, job: &mut Job) {
        if let Some(t) = self.pause_started.take() {
            self.paused_total += t.elapsed();
        }
        job.phase = self.prev_phase;
        self.paused.store(false, Ordering::Relaxed);
        self.continue_child();
    }

    /// Wartet während einer Pause (Zählphase). Liefert true bei Abbruch.
    fn wait_while_paused(&mut self, job: &mut Job, writer: &mut StateWriter) -> bool {
        while self.is_paused() && !self.cancelled {
            thread::sleep(Duration::from_millis(200));
            self.poll(job, writer);
        }
        self.cancelled
    }

    #[cfg(unix)]
    fn signal_child(&self, sig: libc::c_int) {
        if let Some(pid) = self.child {
            // SAFETY: kill hat keine Vorbedingungen; pid gehört zum eigenen Kindprozess
            unsafe { libc::kill(pid, sig) };
        }
    }

    /// Hält clamscan an (SIGSTOP, unter Windows alle Threads anhalten).
    fn stop_child(&self) {
        #[cfg(unix)]
        self.signal_child(libc::SIGSTOP);
        #[cfg(windows)]
        if let Some(pid) = self.child {
            crate::win::suspend_process(pid, false);
        }
    }

    /// Setzt clamscan fort (SIGCONT, unter Windows alle Threads fortsetzen).
    fn continue_child(&self) {
        #[cfg(unix)]
        self.signal_child(libc::SIGCONT);
        #[cfg(windows)]
        if let Some(pid) = self.child {
            crate::win::suspend_process(pid, true);
        }
    }
}

/// Wartet in Arbeiter-Threads, solange pausiert ist (und nicht abgebrochen).
fn wait_paused(paused: &AtomicBool, stop: &AtomicBool) {
    while paused.load(Ordering::Relaxed) && !stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
    }
}

// ---------------------------------------------------------------------------
// Ablauf
// ---------------------------------------------------------------------------

/// Fortschritt der Prüfphase je Bereich. Kommen während der Prüfung Dateien hinzu (nach
/// der Zählphase angelegt), werden `total` und die Dateizahl des Segments sofort nachgezogen,
/// damit `scanned + skipped + errors` nie über `total` liegt und die Prüffront nicht springt.
struct Progress {
    /// Segment je Bereich.
    map: Vec<u32>,
    /// Gezählte (bzw. nachgezogene) Dateien je Bereich.
    files: Vec<u64>,
    /// Bisher bearbeitete Einträge je Bereich.
    seen: Vec<u64>,
}

impl Progress {
    /// Vermerkt einen bearbeiteten Eintrag (geprüft, übersprungen oder Fehler) im Bereich.
    fn note(&mut self, job: &mut Job, area: usize) {
        let Some(seen) = self.seen.get_mut(area) else { return };
        *seen += 1;
        let seg = self.map[area];
        if *seen > self.files[area] {
            self.files[area] = *seen;
            job.total += 1;
            if let Some(s) = job.segments.get_mut(seg as usize) {
                s.files += 1;
            }
        }
        job.segment_index = job.segment_index.max(seg);
    }
}

/// Ergebnis einer Einzelprüfung.
enum Outcome {
    Clean,
    Infected { signature: String, sha256: String },
    Skipped,
    Error,
}

/// Meldungen der Threads an den Hauptthread.
enum Event {
    Done { path: PathBuf, size: u64, area: usize, outcome: Outcome },
    Skipped(usize),
    WalkError(usize),
    /// Muss über clamscan geprüft werden (clamd fehlt oder ist ausgefallen).
    Fallback(PathBuf, u64, usize),
}

/// Gemeinsamer Zustand der clamd-Arbeiter.
struct ClamdShared {
    socket: PathBuf,
    /// clamd ist ausgefallen: Rest über clamscan.
    down: AtomicBool,
    /// zFILDES verwenden (wird abgeschaltet, wenn clamd es ablehnt).
    fildes: AtomicBool,
    /// clamd hat zFILDES abgelehnt, es wurde zINSTREAM verwendet.
    fildes_rejected: AtomicBool,
}

/// Führt eine Dateiprüfung vollständig aus und liefert den fertigen Auftrag.
/// Die Endphase ist `finished`, `cancelled` oder `failed`.
pub fn run_scan(req: &ScanRequest) -> Job {
    let started = Instant::now();
    let mut writer = StateWriter::new();
    let mut notes: Vec<Text> = Vec::new();
    let cfg = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            notes.push(tr!(
                "Die Konfiguration ist unlesbar, es gelten die Standardwerte ({}).",
                "The configuration is unreadable, the default values apply ({}).",
                e
            ));
            Config::default()
        }
    };
    let excl = Exclusions::new(&cfg, req.kind);
    let homes = Homes::detect();
    let (mut areas, roots) = plan(req, &excl, &homes);
    let mut job = new_job(req.kind, req.trigger, roots);
    writer.force(&job);

    if job.paths.is_empty() {
        let e = if req.kind == JobKind::Quick {
            tr!("Keines der Ziele der Schnellprüfung existiert.", "None of the quick scan targets exists.")
        } else {
            tr!("Keiner der angegebenen Pfade existiert.", "None of the given paths exists.")
        };
        return finish(job, Phase::Failed, Some(e), notes, started, None, &mut writer);
    }

    // Zählphase: nur Metadaten aus dem Verzeichnis, Bereich für Bereich
    let mut ctl = Control::new();
    'count: for i in 0..areas.len() {
        let src = areas[i].source.clone();
        for entry in entries(&src, &excl) {
            if ctl.poll(&mut job, &mut writer) || ctl.wait_while_paused(&mut job, &mut writer) {
                break 'count;
            }
            if let Entry::File(_) = entry {
                areas[i].files += 1;
                job.total += 1;
                if writer.due() {
                    job.segments = segment_view(&areas).0;
                    writer.force(&job);
                }
            }
        }
    }
    let (segments, seg_map) = segment_view(&areas);
    let mut progress = Progress { map: seg_map, files: areas.iter().map(|a| a.files).collect(), seen: vec![0; areas.len()] };
    job.segments = segments;
    if ctl.cancelled {
        return finish(job, Phase::Cancelled, None, notes, started, None, &mut writer);
    }

    // Prüfphase
    job.counted = true;
    job.phase = Phase::Scanning;
    let engine = Engine::detect();
    job.engine = Some(engine.kind());
    writer.force(&job);

    let scan_started = Instant::now();
    let paused_before = ctl.paused_time();
    let result = scan_phase(&mut job, &areas, &mut progress, &excl, &engine, &cfg, &mut writer, &mut ctl, &mut notes);
    let active = scan_started.elapsed().saturating_sub(ctl.paused_time().saturating_sub(paused_before));
    match result {
        Err(e) => finish(job, Phase::Failed, Some(e), notes, started, Some(active), &mut writer),
        Ok(()) if ctl.cancelled => finish(job, Phase::Cancelled, None, notes, started, Some(active), &mut writer),
        Ok(()) => finish(job, Phase::Finished, None, notes, started, Some(active), &mut writer),
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_phase(
    job: &mut Job,
    areas: &[Area],
    progress: &mut Progress,
    excl: &Exclusions,
    engine: &Engine,
    cfg: &Config,
    writer: &mut StateWriter,
    ctl: &mut Control,
    notes: &mut Vec<Text>,
) -> Result<(), Text> {
    let stop = Arc::new(AtomicBool::new(false));
    let (ev_tx, ev_rx) = mpsc::channel::<Event>();
    let shared = Arc::new(ClamdShared {
        socket: match engine {
            Engine::Clamd(s) => s.clone(),
            Engine::Clamscan(_) => PathBuf::new(),
        },
        down: AtomicBool::new(false),
        // Testbetrieb: VIGIL_CLAMD_NO_FILDES=1 erzwingt zINSTREAM (Tempovergleich).
        // Unter Windows gibt es zFILDES nicht.
        fildes: AtomicBool::new(cfg!(unix) && paths::dev_value("VIGIL_CLAMD_NO_FILDES").is_none()),
        fildes_rejected: AtomicBool::new(false),
    });
    let use_clamd = matches!(engine, Engine::Clamd(_));

    // Arbeiter für clamd: min(12, CPUs) Verbindungen parallel
    let mut handles = Vec::new();
    let work_tx = if use_clamd {
        let n = thread::available_parallelism().map(|n| n.get()).unwrap_or(1).clamp(1, MAX_CONNECTIONS);
        let (tx, rx) = mpsc::sync_channel::<(PathBuf, usize)>(256);
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..n {
            let rx = Arc::clone(&rx);
            let ev = ev_tx.clone();
            let stop = Arc::clone(&stop);
            let paused = Arc::clone(&ctl.paused);
            let shared = Arc::clone(&shared);
            handles.push(thread::spawn(move || loop {
                let next = rx.lock().map(|r| r.recv());
                let Ok(Ok((path, area))) = next else { break };
                wait_paused(&paused, &stop);
                if stop.load(Ordering::Relaxed) {
                    continue;
                }
                let ev_out = scan_one_clamd(&shared, path, area);
                if ev.send(ev_out).is_err() {
                    break;
                }
            }));
        }
        Some(tx)
    } else {
        None
    };

    // Durchlauf in eigenem Thread, Bereich für Bereich in Planreihenfolge
    {
        let sources: Vec<Source> = areas.iter().map(|a| a.source.clone()).collect();
        let excl = excl.clone();
        let ev = ev_tx.clone();
        let stop = Arc::clone(&stop);
        let paused = Arc::clone(&ctl.paused);
        handles.push(thread::spawn(move || {
            for (area, src) in sources.iter().enumerate() {
                for entry in entries(src, &excl) {
                    wait_paused(&paused, &stop);
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let path = match entry {
                        Entry::File(p) => p,
                        Entry::Error => {
                            let _ = ev.send(Event::WalkError(area));
                            continue;
                        }
                    };
                    match &work_tx {
                        Some(tx) => {
                            if tx.send((path, area)).is_err() {
                                return;
                            }
                        }
                        None => {
                            // clamscan: Größe vorher prüfen, große Dateien überspringen
                            let size = std::fs::symlink_metadata(&path).map(|m| m.len()).unwrap_or(0);
                            let msg = if size > MAX_SCAN_SIZE { Event::Skipped(area) } else { Event::Fallback(path, size, area) };
                            let _ = ev.send(msg);
                        }
                    }
                }
            }
        }));
    }
    drop(ev_tx);

    // Hauptschleife: Ergebnisse auswerten, Zustand schreiben, Abbruch und Pause prüfen
    let mut fallback: Vec<(PathBuf, u64, usize)> = Vec::new();
    let mut tracker = ThreatTracker::new(cfg);
    loop {
        match ev_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(ev) => match ev {
                Event::Done { path, size, area, outcome } => {
                    progress.note(job, area);
                    job.set_current_path(paths::display(&path));
                    record(job, &mut tracker, engine, &shared.down, &path, size, outcome);
                }
                Event::Skipped(area) => {
                    progress.note(job, area);
                    job.skipped += 1;
                }
                Event::WalkError(area) => {
                    progress.note(job, area);
                    job.errors += 1;
                }
                Event::Fallback(p, s, a) => fallback.push((p, s, a)),
            },
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if ctl.poll(job, writer) {
            stop.store(true, Ordering::Relaxed);
        }
        writer.update(job);
    }
    for h in handles {
        let _ = h.join();
    }

    // Hinweise zum Motor
    if !use_clamd {
        notes.push(tr!(
            "clamd war nicht erreichbar, es wurde clamscan verwendet (langsamer).",
            "clamd was not reachable, clamscan was used instead (slower)."
        ));
    } else if shared.down.load(Ordering::Relaxed) {
        notes.push(tr!(
            "clamd ist während der Prüfung ausgefallen, der Rest wurde mit clamscan geprüft.",
            "clamd stopped working during the scan, the rest was scanned with clamscan."
        ));
    }
    if shared.fildes_rejected.load(Ordering::Relaxed) {
        notes.push(tr!(
            "clamd hat die direkte Dateiübergabe (FILDES) abgelehnt, die Dateien wurden stattdessen übertragen (INSTREAM).",
            "clamd refused the direct file handover (FILDES), the files were streamed instead (INSTREAM)."
        ));
    }
    // Ausweichweg clamscan für alle übrigen Dateien
    if !ctl.cancelled && !fallback.is_empty() {
        let bin = engine::clamscan_path();
        job.engine = Some(EngineKind::Clamscan);
        writer.force(job);
        run_clamscan(&bin, &fallback, progress, job, &mut tracker, writer, ctl)?;
    }
    if tracker.quarantine_failures > 0 {
        notes.push(tr!(
            "{} Fund(e) konnten nicht in die Quarantäne verschoben werden: {}",
            "{} finding(s) could not be moved to quarantine: {}",
            tracker.quarantine_failures,
            tracker.last_quarantine_error.clone().unwrap_or_default()
        ));
    }
    Ok(())
}

/// Prüft eine Datei über clamd (zFILDES, bei Ablehnung zINSTREAM).
/// Fällt clamd aus, wird die Datei für clamscan vorgemerkt.
fn scan_one_clamd(sh: &ClamdShared, path: PathBuf, area: usize) -> Event {
    let mut f = match clamd::open_for_scan(&path) {
        Ok(f) => f,
        // Verschwunden oder inzwischen eine Verknüpfung: überspringen
        Err(e) if e.kind() == ErrorKind::NotFound || clamd::is_link_error(&e) => return Event::Skipped(area),
        Err(_) => return Event::Done { path, size: 0, area, outcome: Outcome::Error },
    };
    let meta = match f.metadata() {
        Ok(m) => m,
        Err(_) => return Event::Done { path, size: 0, area, outcome: Outcome::Error },
    };
    if !meta.is_file() || meta.len() > MAX_SCAN_SIZE {
        return Event::Skipped(area);
    }
    let size = meta.len();
    if sh.down.load(Ordering::Relaxed) {
        return Event::Fallback(path, size, area);
    }
    let sock = &sh.socket;
    let mut attempt = 0;
    loop {
        use std::io::{Seek, SeekFrom};
        let result = if sh.fildes.load(Ordering::Relaxed) {
            match clamd::scan_fd(sock, &f) {
                Ok(v) => Ok(v),
                // clamd antwortet, lehnt FILDES aber ab: mit INSTREAM versuchen. Klappt das,
                // gilt FILDES als abgelehnt und wird für den Rest der Prüfung nicht mehr verwendet.
                Err(e) if clamd::ping(sock) => {
                    let _ = f.seek(SeekFrom::Start(0));
                    match clamd::scan_reader(sock, &mut f) {
                        Ok(v) => {
                            sh.fildes.store(false, Ordering::Relaxed);
                            sh.fildes_rejected.store(true, Ordering::Relaxed);
                            Ok(v)
                        }
                        Err(_) => Err(e),
                    }
                }
                Err(e) => Err(e),
            }
        } else {
            let _ = f.seek(SeekFrom::Start(0));
            clamd::scan_reader(sock, &mut f)
        };
        match result {
            Ok(Verdict::Clean) => return Event::Done { path, size, area, outcome: Outcome::Clean },
            Ok(Verdict::Skipped(_)) => return Event::Skipped(area),
            Ok(Verdict::Infected(signature)) => {
                let _ = f.seek(SeekFrom::Start(0));
                let sha256 = sha256_reader(&mut f).unwrap_or_default();
                return Event::Done { path, size, area, outcome: Outcome::Infected { signature, sha256 } };
            }
            Err(_) => {
                // clamd noch da? Dann war es ein Fehler mit dieser Datei
                if clamd::ping(sock) {
                    return Event::Done { path, size, area, outcome: Outcome::Error };
                }
                attempt += 1;
                if attempt >= 2 {
                    sh.down.store(true, Ordering::Relaxed);
                    return Event::Fallback(path, size, area);
                }
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

/// Zählt Ergebnisse und behandelt Funde (allowlist, onThreat).
struct ThreatTracker<'a> {
    cfg: &'a Config,
    quarantine_failures: u64,
    last_quarantine_error: Option<Text>,
}

impl<'a> ThreatTracker<'a> {
    fn new(cfg: &'a Config) -> Self {
        ThreatTracker { cfg, quarantine_failures: 0, last_quarantine_error: None }
    }
}

fn record(
    job: &mut Job,
    tracker: &mut ThreatTracker,
    engine: &Engine,
    clamd_down: &AtomicBool,
    path: &Path,
    size: u64,
    outcome: Outcome,
) {
    match outcome {
        Outcome::Clean => {
            job.scanned += 1;
            job.bytes += size;
        }
        Outcome::Skipped => job.skipped += 1,
        Outcome::Error => job.errors += 1,
        Outcome::Infected { signature, sha256 } => {
            job.scanned += 1;
            job.bytes += size;
            // Freigegebene Dateien (sha256 in der allowlist) zählen nicht als Fund
            if !sha256.is_empty() && tracker.cfg.allowlist.iter().any(|a| a.sha256 == sha256) {
                return;
            }
            let id = format!("t{}", job.threats.len() + 1);
            let severity = crate::types::severity_of(&signature);
            let mut threat = Threat {
                id: id.clone(),
                path: paths::display(path),
                signature,
                size,
                sha256,
                action: ThreatAction::None,
                quarantine_id: None,
                severity,
            };
            // Automatische Quarantäne nur für echte Bedrohungen, nie für Hinweise
            if tracker.cfg.scan.on_threat == OnThreat::Quarantine && severity == crate::types::Severity::Threat {
                let eng = if clamd_down.load(Ordering::Relaxed) {
                    Engine::Clamscan(engine::clamscan_path())
                } else {
                    engine.clone()
                };
                match quarantine::quarantine_path(&eng, path, Some(&job.id), Some(&id)) {
                    Ok(item) => {
                        threat.action = ThreatAction::Quarantined;
                        threat.quarantine_id = Some(item.id);
                        threat.sha256 = item.sha256;
                    }
                    Err(e) => {
                        tracker.quarantine_failures += 1;
                        tracker.last_quarantine_error = Some(e);
                    }
                }
            }
            job.threats.push(threat);
        }
    }
}

/// Prüft eine Dateiliste mit `clamscan --no-summary --stdout -f <liste>` und wertet
/// die Zeilen `pfad: OK` / `pfad: <Sig> FOUND` aus. Pausen halten clamscan mit SIGSTOP an.
fn run_clamscan(
    bin: &Path,
    files: &[(PathBuf, u64, usize)],
    progress: &mut Progress,
    job: &mut Job,
    tracker: &mut ThreatTracker,
    writer: &mut StateWriter,
    ctl: &mut Control,
) -> Result<(), Text> {
    // Liste schreiben; Pfade mit Zeilenumbruch passen nicht hinein und werden übersprungen
    let mut expected: HashMap<Vec<u8>, (u64, usize)> = HashMap::with_capacity(files.len());
    let mut list = Vec::new();
    for (p, s, a) in files {
        #[cfg(unix)]
        let b = p.as_os_str().as_bytes();
        // Windows: Liste in UTF-8; Pfade ohne gültige Darstellung werden übersprungen
        #[cfg(windows)]
        let b = p.to_str().unwrap_or("\n").as_bytes();
        if b.contains(&b'\n') {
            progress.note(job, *a);
            job.skipped += 1;
            continue;
        }
        list.extend_from_slice(b);
        list.push(b'\n');
        expected.insert(b.to_vec(), (*s, *a));
    }
    if expected.is_empty() {
        return Ok(());
    }
    let list_path = paths::data_dir().join("clamscan-list");
    fsutil::write_atomic(&list_path, &list, 0o600)?;

    let mut command = Command::new(bin);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(crate::win::CREATE_NO_WINDOW);
        crate::win::clamav::clamscan_args(&mut command);
    }
    let mut child = command
        .arg("--no-summary")
        .arg("--stdout")
        .arg("--follow-dir-symlinks=0")
        .arg("--follow-file-symlinks=0")
        .arg("-f")
        .arg(&list_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            let _ = std::fs::remove_file(&list_path);
            tr!(
                "Weder clamd noch clamscan ist verfügbar ({}: {}).",
                "Neither clamd nor clamscan is available ({}: {}).",
                bin.display(),
                e
            )
        })?;
    #[cfg(unix)]
    {
        ctl.child = Some(child.id() as libc::pid_t);
    }
    #[cfg(windows)]
    {
        ctl.child = Some(child.id());
    }
    // Pause schon vor dem Start angefordert: sofort anhalten
    if ctl.is_paused() {
        ctl.stop_child();
    }

    // stdout zeilenweise, stderr gesammelt (für Fehlermeldungen)
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let (line_tx, line_rx) = mpsc::channel::<Vec<u8>>();
    let reader = thread::spawn(move || {
        let mut r = BufReader::new(stdout);
        loop {
            let mut line = Vec::new();
            match r.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if line.last() == Some(&b'\n') {
                        line.pop();
                    }
                    if line_tx.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let err_reader = thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });

    let mut processed = 0u64;
    loop {
        match line_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(line) => {
                let Some(pos) = rfind(&line, b": ") else { continue };
                let (p, status) = (&line[..pos], &line[pos + 2..]);
                let Some((size, area)) = expected.remove(p) else { continue };
                processed += 1;
                #[cfg(unix)]
                let path = PathBuf::from(OsStr::from_bytes(p));
                #[cfg(windows)]
                let path = PathBuf::from(String::from_utf8_lossy(p).into_owned());
                progress.note(job, area);
                job.set_current_path(paths::display(&path));
                let status = String::from_utf8_lossy(status).trim().to_string();
                let outcome = if status == "OK" || status == "Empty file" {
                    Outcome::Clean
                } else if let Some(sig) = status.strip_suffix(" FOUND") {
                    let sha256 = clamd::open_for_scan(&path)
                        .ok()
                        .and_then(|mut f| sha256_reader(&mut f).ok())
                        .unwrap_or_default();
                    Outcome::Infected { signature: sig.trim().to_string(), sha256 }
                } else if status.ends_with("ERROR") {
                    Outcome::Error
                } else {
                    Outcome::Skipped
                };
                let clamscan_engine = Engine::Clamscan(bin.to_path_buf());
                let no = AtomicBool::new(false);
                record(job, tracker, &clamscan_engine, &no, &path, size, outcome);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if ctl.poll(job, writer) {
            let _ = child.kill();
            break;
        }
        writer.update(job);
    }
    let status = child.wait();
    ctl.child = None;
    let _ = reader.join();
    let err_text = err_reader.join().unwrap_or_default();
    let _ = std::fs::remove_file(&list_path);
    if ctl.cancelled {
        return Ok(());
    }
    // Nicht gemeldete Dateien zählen als Fehler
    for (_, area) in expected.values() {
        progress.note(job, *area);
        job.errors += 1;
    }
    let code = status.ok().and_then(|s| s.code());
    if processed == 0 && code != Some(0) && code != Some(1) {
        let c = code.map(|c| Text::same(c.to_string())).unwrap_or_else(|| tr!("unbekannt", "unknown"));
        return Err(tr!(
            "clamscan ist fehlgeschlagen (Exit-Code {}): {}",
            "clamscan failed (exit code {}): {}",
            c,
            err_text.trim()
        ));
    }
    Ok(())
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).rposition(|w| w == needle)
}

/// Schließt den Auftrag ab: Endphase, Meldung, Bericht, letzter Zustand.
/// `active` ist die Dauer der Prüfphase ohne Pausen (für `filesPerSecond`).
fn finish(
    mut job: Job,
    phase: Phase,
    error: Option<Text>,
    mut notes: Vec<Text>,
    started: Instant,
    active: Option<Duration>,
    writer: &mut StateWriter,
) -> Job {
    job.phase = phase;
    job.finished_at = Some(crate::now_rfc3339());
    job.set_current(None);
    let processed = job.scanned + job.skipped + job.errors;
    if job.counted && processed > job.total {
        job.total = processed;
    }
    // Bedrohungen und Hinweise getrennt nennen
    let n = job.threats.iter().filter(|t| !t.is_hint()).count();
    let hints = job.threats.len() - n;
    let head = match phase {
        Phase::Failed => {
            let e = error.unwrap_or_default();
            tr!("Prüfung fehlgeschlagen: {}", "Scan failed: {}", e)
        }
        Phase::Cancelled => Text::join(&[tr!("Prüfung abgebrochen.", "Scan cancelled."), found_text(n), hint_text(hints)]),
        _ if n == 0 => Text::join(&[tr!("Prüfung abgeschlossen. Keine Bedrohungen gefunden.", "Scan finished. No threats found."), hint_text(hints)]),
        _ => Text::join(&[tr!("Prüfung abgeschlossen.", "Scan finished."), found_text(n), hint_text(hints)]),
    };
    notes.insert(0, head);
    if job.errors > 0 && phase != Phase::Failed {
        notes.insert(1, match job.errors {
            1 => tr!("1 Datei oder Ordner konnte nicht gelesen werden.", "1 file or folder could not be read."),
            n => tr!("{} Dateien oder Ordner konnten nicht gelesen werden.", "{} files or folders could not be read.", n),
        });
    }
    job.set_message(&Text::join(&notes));
    let secs = active.map(|d| d.as_secs_f64()).unwrap_or(0.0);
    let files_per_second = if job.scanned > 0 && secs > 0.0 { (job.scanned as f64 / secs * 10.0).round() / 10.0 } else { 0.0 };
    let report = Report { job: job.clone(), duration_secs: started.elapsed().as_secs(), files_per_second };
    if let Err(e) = reports::write_report(&report) {
        let msg = Text::new(job.message.clone().unwrap_or_default(), job.message_en.clone().unwrap_or_default());
        job.set_message(&tr!(
            "{} Der Bericht konnte nicht gespeichert werden: {}",
            "{} The report could not be saved: {}",
            msg,
            e
        ));
    }
    writer.force(&job);
    job
}

fn hint_text(n: usize) -> Text {
    match n {
        0 => Text::default(),
        1 => tr!("1 Hinweis aus der Heuristik.", "1 heuristic notice."),
        _ => tr!("{} Hinweise aus der Heuristik.", "{} heuristic notices.", n),
    }
}

fn found_text(n: usize) -> Text {
    match n {
        0 => Text::default(),
        1 => tr!("1 Bedrohung gefunden.", "1 threat found."),
        _ => tr!("{} Bedrohungen gefunden.", "{} threats found.", n),
    }
}

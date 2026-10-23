//! clamd-Client über Unix-Socket. Der Helfer übergibt Dateien per `zFILDES` (offener
//! Dateideskriptor über SCM_RIGHTS), Ausweichweg und Download-Wächter der App nutzen `zINSTREAM`.
//!
//! Unter Windows läuft clamd (vom Vigil-Dienst gestartet) über TCP auf 127.0.0.1. Der „Socket“
//! ist dort die Adresse `127.0.0.1:<port>` als Pfad, damit alle Aufrufer gleich bleiben.
//! Dateien gehen immer per `zINSTREAM` an clamd (zFILDES gibt es unter Windows nicht).

use crate::i18n::Text;
use crate::paths;
use crate::tr;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use std::net::TcpStream as UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Dateien über dieser Größe werden übersprungen (wie StreamMaxLength von clamd).
pub const MAX_SCAN_SIZE: u64 = 25 * 1024 * 1024;

/// Standardsocket, falls clamd.conf fehlt oder keinen LocalSocket nennt.
#[cfg(unix)]
pub const DEFAULT_SOCKET: &str = "/var/run/clamav/clamd.ctl";

/// Konfiguration von clamd.
#[cfg(unix)]
pub const CLAMD_CONF: &str = "/etc/clamav/clamd.conf";

const CHUNK: usize = 64 * 1024;

/// Gründe für übersprungene Dateien (Deutsch, Englisch).
const SKIP_SYMLINK: (&str, &str) = ("Symbolische Verknüpfung", "Symbolic link");
const SKIP_NOT_REGULAR: (&str, &str) = ("Keine reguläre Datei", "Not a regular file");
const SKIP_TOO_BIG: (&str, &str) = ("Datei größer als 25 MB", "File larger than 25 MB");
const SKIP_CLAMD_LIMIT: (&str, &str) = ("Datei größer als die Grenze von clamd", "File larger than the clamd limit");
const SKIP_REASONS: [(&str, &str); 4] = [SKIP_SYMLINK, SKIP_NOT_REGULAR, SKIP_TOO_BIG, SKIP_CLAMD_LIMIT];

/// Ergebnis einer Prüfung.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Keine Bedrohung.
    Clean,
    /// Bedrohung mit Signaturname.
    Infected(String),
    /// Nicht geprüft, mit Grund auf Deutsch (z. B. zu groß); englisch über [`skip_reason_en`].
    Skipped(String),
}

/// Englische Fassung eines Grundes aus [`Verdict::Skipped`].
pub fn skip_reason_en(de: &str) -> String {
    SKIP_REASONS.iter().find(|(d, _)| *d == de).map(|(_, e)| e.to_string()).unwrap_or_else(|| de.to_string())
}

/// Pfad des clamd-Sockets: `LocalSocket` aus /etc/clamav/clamd.conf, sonst
/// `/var/run/clamav/clamd.ctl`. Im Testbetrieb überschreibt `VIGIL_CLAMD_SOCKET`.
#[cfg(unix)]
pub fn clamd_socket() -> PathBuf {
    if let Some(p) = paths::dev_override("VIGIL_CLAMD_SOCKET") {
        return p;
    }
    fs::read_to_string(CLAMD_CONF)
        .ok()
        .and_then(|t| parse_local_socket(&t))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

/// Adresse von clamd unter Windows: `127.0.0.1:<TCPSocket aus clamd.conf>` (Standard 3310).
/// Im Testbetrieb überschreibt `VIGIL_CLAMD_SOCKET` (z. B. `127.0.0.1:3311`).
#[cfg(windows)]
pub fn clamd_socket() -> PathBuf {
    if let Some(p) = paths::dev_override("VIGIL_CLAMD_SOCKET") {
        return p;
    }
    let port = fs::read_to_string(crate::win::clamav::clamd_conf())
        .ok()
        .and_then(|t| crate::win::clamav::conf_value(&t, "TCPSocket"))
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(crate::win::clamav::CLAMD_PORT);
    PathBuf::from(format!("127.0.0.1:{port}"))
}

/// Liest `LocalSocket` aus dem Text einer clamd.conf.
pub fn parse_local_socket(conf: &str) -> Option<PathBuf> {
    conf.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut it = l.splitn(2, char::is_whitespace);
            let key = it.next()?;
            let val = it.next()?.trim();
            (key == "LocalSocket" && !val.is_empty()).then(|| PathBuf::from(val))
        })
        .next_back()
}

/// Prüft eine Datei über clamd (zINSTREAM). Die Datei wird vom Aufrufer gelesen,
/// clamd braucht also keinen Zugriff darauf. Symbolische Verknüpfungen werden nicht verfolgt.
/// Fehlertext auf Deutsch; zweisprachig siehe [`scan_file_stream_text`].
pub fn scan_file_stream(socket: &Path, file: &Path) -> Result<Verdict, String> {
    scan_file_stream_text(socket, file).map_err(String::from)
}

/// Wie [`scan_file_stream`], mit Fehlertext in beiden Sprachen.
pub fn scan_file_stream_text(socket: &Path, file: &Path) -> Result<Verdict, Text> {
    #[cfg(unix)]
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(file);
    #[cfg(windows)]
    let opened = open_for_scan(file);
    let mut f = match opened {
        Ok(f) => f,
        Err(e) if is_link_error(&e) => return Ok(Verdict::Skipped(SKIP_SYMLINK.0.into())),
        Err(e) => {
            return Err(tr!("Die Datei {} konnte nicht geöffnet werden: {}", "Could not open the file {}: {}", file.display(), e))
        }
    };
    let meta = f
        .metadata()
        .map_err(|e| tr!("Die Datei {} ist nicht lesbar: {}", "The file {} is not readable: {}", file.display(), e))?;
    if !meta.is_file() {
        return Ok(Verdict::Skipped(SKIP_NOT_REGULAR.0.into()));
    }
    if meta.len() > MAX_SCAN_SIZE {
        return Ok(Verdict::Skipped(SKIP_TOO_BIG.0.into()));
    }
    scan_reader(socket, &mut f)
}

fn conn_err(socket: &Path, e: std::io::Error) -> Text {
    tr!("Fehler bei der Verbindung zu clamd ({}): {}", "Error in the connection to clamd ({}): {}", socket.display(), e)
}

/// Prüft beliebige Daten über clamd (zINSTREAM).
pub fn scan_reader<R: Read>(socket: &Path, reader: &mut R) -> Result<Verdict, Text> {
    let mut s = connect(socket)?;
    let io_err = |e: std::io::Error| conn_err(socket, e);

    s.write_all(b"zINSTREAM\0").map_err(io_err)?;
    let mut buf = vec![0u8; CHUNK];
    let mut write_failed = None;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(tr!("Die Datei konnte nicht gelesen werden: {}", "Could not read the file: {}", e)),
        };
        if n == 0 {
            break;
        }
        let len = (n as u32).to_be_bytes();
        // Unter Windows (TCP) Länge und Daten in einem Stück senden, sonst bremst die
        // Verzögerung kleiner Pakete jede Datei aus; unter Linux wie bisher
        #[cfg(windows)]
        let sent = {
            let mut frame = Vec::with_capacity(4 + n);
            frame.extend_from_slice(&len);
            frame.extend_from_slice(&buf[..n]);
            s.write_all(&frame)
        };
        #[cfg(unix)]
        let sent = s.write_all(&len).and_then(|_| s.write_all(&buf[..n]));
        if let Err(e) = sent {
            // clamd schließt die Verbindung z. B. bei Überschreitung von StreamMaxLength
            write_failed = Some(e);
            break;
        }
    }
    if write_failed.is_none() {
        if let Err(e) = s.write_all(&[0, 0, 0, 0]) {
            write_failed = Some(e);
        }
    }

    let reply = read_reply(&mut s);
    match (reply, write_failed) {
        (Ok(r), _) if !r.is_empty() => parse_reply(&r),
        (_, Some(e)) => Err(io_err(e)),
        (Ok(_), None) => Err(no_answer(socket)),
        (Err(e), None) => Err(io_err(e)),
    }
}

fn no_answer(socket: &Path) -> Text {
    tr!("clamd ({}) hat keine Antwort geliefert.", "clamd ({}) did not answer.", socket.display())
}

/// Prüft eine geöffnete Datei über clamd (zFILDES): Der Dateideskriptor wird per SCM_RIGHTS
/// übergeben, clamd liest die Datei direkt. Nur über Unix-Sockets möglich. Lehnt clamd das ab
/// (z. B. fehlende Rechte), liefert die Funktion einen Fehler; der Aufrufer weicht dann auf
/// [`scan_reader`] aus.
#[cfg(unix)]
pub fn scan_fd(socket: &Path, file: &File) -> Result<Verdict, Text> {
    let mut s = connect(socket)?;
    let io_err = |e: std::io::Error| conn_err(socket, e);
    s.write_all(b"zFILDES\0").map_err(io_err)?;
    send_fd(&s, file.as_raw_fd()).map_err(io_err)?;
    let reply = read_reply(&mut s).map_err(io_err)?;
    if reply.is_empty() {
        return Err(no_answer(socket));
    }
    parse_reply(&reply)
}

/// zFILDES gibt es unter Windows nicht; der Scanner nutzt dort immer [`scan_reader`].
#[cfg(windows)]
pub fn scan_fd(socket: &Path, _file: &File) -> Result<Verdict, Text> {
    Err(tr!("clamd ({}) kann unter Windows keine Dateideskriptoren übernehmen.", "clamd ({}) cannot take file descriptors on Windows.", socket.display()))
}

/// Sendet ein Byte mit dem Dateideskriptor als SCM_RIGHTS-Zusatzdaten.
#[cfg(unix)]
fn send_fd(s: &UnixStream, fd: RawFd) -> std::io::Result<()> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
    // Puffer für genau einen Deskriptor; u64 sorgt für die nötige Ausrichtung von cmsghdr
    let fd_size = std::mem::size_of::<libc::c_int>() as u32;
    // SAFETY: CMSG_SPACE und CMSG_LEN rechnen nur
    let (space, len) = unsafe { (libc::CMSG_SPACE(fd_size) as usize, libc::CMSG_LEN(fd_size) as usize) };
    let mut cbuf = vec![0u64; space.div_ceil(8)];
    // SAFETY: msghdr ist ein einfacher C-Datentyp, alle Zeiger zeigen auf lebende Puffer
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = len as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>(), fd);
        loop {
            if libc::sendmsg(s.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) >= 0 {
                return Ok(());
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

/// Ist clamd erreichbar (PING/PONG)?
pub fn ping(socket: &Path) -> bool {
    command(socket, "zPING").map(|r| r == "PONG").unwrap_or(false)
}

/// Versionstext von clamd, z. B. `ClamAV 1.5.4/28161/Thu Oct 22 06:24:00 2026`.
pub fn version(socket: &Path) -> Result<String, Text> {
    command(socket, "zVERSION")
}

/// Bittet clamd, die Datenbanken neu zu laden (`zRELOAD`). Antwort `RELOADING` bei Erfolg,
/// `COMMAND UNAVAILABLE`, wenn `EnableReloadCommand` in clamd.conf ausgeschaltet ist.
pub fn reload(socket: &Path) -> Result<String, Text> {
    command(socket, "zRELOAD")
}

/// Sendet einen einfachen Befehl und liefert die Antwort.
fn command(socket: &Path, cmd: &str) -> Result<String, Text> {
    let mut s = connect(socket)?;
    let mut msg = cmd.as_bytes().to_vec();
    msg.push(0);
    s.write_all(&msg).map_err(|e| conn_err(socket, e))?;
    read_reply(&mut s).map_err(|e| conn_err(socket, e))
}

fn connect(socket: &Path) -> Result<UnixStream, Text> {
    let unreachable = |e: std::io::Error| tr!("clamd ist nicht erreichbar ({}): {}", "clamd is not reachable ({}): {}", socket.display(), e);
    #[cfg(unix)]
    let s = UnixStream::connect(socket).map_err(unreachable)?;
    // Windows: TCP nur zur eigenen Maschine, kurze Zeitgrenze für den Verbindungsaufbau
    #[cfg(windows)]
    let s = {
        let addr: std::net::SocketAddr = socket
            .to_str()
            .and_then(|a| a.parse().ok())
            .filter(|a: &std::net::SocketAddr| a.ip().is_loopback())
            .ok_or_else(|| unreachable(std::io::Error::from(ErrorKind::InvalidInput)))?;
        let s = UnixStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(unreachable)?;
        // Kleine Pakete (Befehl, Endmarke) sofort senden statt bis zu 200 ms zu warten
        let _ = s.set_nodelay(true);
        s
    };
    // Lange Lesezeit: Archive können bei clamd eine Weile dauern
    let _ = s.set_read_timeout(Some(Duration::from_secs(300)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(60)));
    Ok(s)
}

/// Liest die Antwort bis zum Nullbyte oder Verbindungsende.
fn read_reply(s: &mut UnixStream) -> std::io::Result<String> {
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = match s.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                if out.is_empty() {
                    return Err(e);
                }
                break;
            }
        };
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if out.contains(&0) || out.len() > 64 * 1024 {
            break;
        }
    }
    if let Some(pos) = out.iter().position(|b| *b == 0) {
        out.truncate(pos);
    }
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

/// Wertet eine Antwort aus, z. B. `stream: OK`, `stream: Eicar FOUND`, `fd[10]: OK`,
/// `INSTREAM size limit exceeded. ERROR`.
fn parse_reply(reply: &str) -> Result<Verdict, Text> {
    let body = match reply.strip_prefix("stream: ") {
        Some(b) => b,
        None if reply.starts_with("fd[") => reply.split_once("]: ").map(|(_, b)| b).unwrap_or(reply),
        None => reply,
    };
    if body == "OK" {
        return Ok(Verdict::Clean);
    }
    if let Some(sig) = body.strip_suffix(" FOUND") {
        return Ok(Verdict::Infected(sig.trim().to_string()));
    }
    if body.contains("size limit exceeded") {
        return Ok(Verdict::Skipped(SKIP_CLAMD_LIMIT.0.into()));
    }
    Err(tr!("clamd meldet einen Fehler: {}", "clamd reports an error: {}", reply))
}

/// Fehler „symbolische Verknüpfung“ von [`open_for_scan`]?
pub(crate) fn is_link_error(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    return e.raw_os_error() == Some(libc::ELOOP);
    #[cfg(windows)]
    return e.raw_os_error() == Some(ERROR_STOPPED_ON_SYMLINK);
}

/// Windows-Fehler 681 (ERROR_STOPPED_ON_SYMLINK) kennzeichnet eine übersprungene Verknüpfung.
#[cfg(windows)]
const ERROR_STOPPED_ON_SYMLINK: i32 = 681;

/// Öffnet eine Datei zum Prüfen ohne Verfolgen von Verknüpfungen (Windows). Andere Programme
/// dürfen die Datei währenddessen weiter lesen, schreiben und löschen.
#[cfg(windows)]
pub(crate) fn open_for_scan(path: &Path) -> std::io::Result<File> {
    // FILE_FLAG_OPEN_REPARSE_POINT, Freigabe Lesen, Schreiben, Löschen
    let f = OpenOptions::new().read(true).share_mode(7).custom_flags(0x0020_0000).open(path)?;
    if f.metadata()?.file_type().is_symlink() {
        return Err(std::io::Error::from_raw_os_error(ERROR_STOPPED_ON_SYMLINK));
    }
    Ok(f)
}

/// Öffnet eine Datei zum Prüfen ohne Verfolgen symbolischer Verknüpfungen.
/// Als root zusätzlich mit O_NOATIME, damit Zugriffszeiten unverändert bleiben.
#[cfg(unix)]
pub(crate) fn open_for_scan(path: &Path) -> std::io::Result<File> {
    let base = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    match OpenOptions::new().read(true).custom_flags(base | libc::O_NOATIME).open(path) {
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
            OpenOptions::new().read(true).custom_flags(base).open(path)
        }
        r => r,
    }
}

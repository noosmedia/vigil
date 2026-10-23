//! Windows-Schicht des Kerns: bekannte Ordner, Rechte (Administrator, SYSTEM), Zugriffsrechte
//! von Ordnern, Laufwerke, laufende Programme, Anhalten von Prozessen. Nur unter Windows gebaut;
//! die Linux-Teile bleiben in ihren eigenen Modulen unverändert.

pub mod clamav;
pub mod service;

use crate::i18n::Text;
use crate::tr;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf, Prefix};
use windows_sys::core::{GUID, PWSTR};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, IsWellKnownSid, TokenElevation, TokenUser,
    WinLocalSystemSid, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, Thread32First, Thread32Next, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, OpenThread, QueryFullProcessImageNameW, ResumeThread, SuspendThread,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
};
use windows_sys::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_ProgramData};

/// Startflag für Kindprozesse ohne Konsolenfenster (sonst blitzt bei jedem Aufruf ein Fenster auf).
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Laufwerksarten aus `GetDriveTypeW`.
pub const DRIVE_REMOVABLE: u32 = 2;
pub const DRIVE_FIXED: u32 = 3;

/// Zugriffsrechte für Ordner: nur SYSTEM und Administratoren, Besitzer Administratoren.
const SDDL_ADMIN_ONLY: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// Wie [`SDDL_ADMIN_ONLY`], zusätzlich Lesen für alle Benutzer (wie 0755 unter Linux).
const SDDL_USERS_READ: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

/// Text mit abschließendem Nullzeichen für Windows-Funktionen.
pub fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

/// Liest eine nullterminierte Zeichenkette aus einem Puffer.
fn from_wide_ptr(p: PWSTR) -> OsString {
    // SAFETY: p zeigt auf eine nullterminierte Zeichenkette von Windows
    unsafe {
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        OsString::from_wide(std::slice::from_raw_parts(p, n))
    }
}

/// Bekannter Ordner (z. B. ProgramData, Downloads). Liest den Pfad aus der Systemregistrierung,
/// nicht aus Umgebungsvariablen (die ein Benutzer für einen Prozess mit Administratorrechten
/// vorgeben könnte).
pub fn known_folder(id: &GUID) -> Option<PathBuf> {
    let mut p: PWSTR = std::ptr::null_mut();
    // SAFETY: gültige GUID, Ergebnis wird mit CoTaskMemFree freigegeben
    let hr = unsafe { SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut p) };
    if hr != 0 || p.is_null() {
        if !p.is_null() {
            unsafe { CoTaskMemFree(p as *const _) };
        }
        return None;
    }
    let s = from_wide_ptr(p);
    // SAFETY: von SHGetKnownFolderPath angelegt
    unsafe { CoTaskMemFree(p as *const _) };
    Some(PathBuf::from(s))
}

/// `C:\ProgramData`
pub fn program_data() -> PathBuf {
    known_folder(&FOLDERID_ProgramData).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

/// Systemordner (`C:\Windows\System32`) für Programme wie powershell.exe oder icacls.exe.
pub fn system_dir() -> PathBuf {
    let mut buf = [0u16; 512];
    // SAFETY: Puffer mit Länge
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return PathBuf::from(r"C:\Windows\System32");
    }
    PathBuf::from(OsString::from_wide(&buf[..n]))
}

/// Entfernt die Vorsilbe `\\?\` (bzw. `\\?\UNC\`), die `canonicalize` unter Windows liefert,
/// damit Pfade in Berichten und Vergleichen gleich aussehen wie im Explorer.
pub fn strip_verbatim(p: &Path) -> PathBuf {
    let s = p.as_os_str().to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        if rest.len() >= 2 && rest.as_bytes()[1] == b':' {
            return PathBuf::from(rest);
        }
    }
    p.to_path_buf()
}

/// Bestandteile eines Pfads in Kleinschreibung (Windows unterscheidet nicht nach Groß- und
/// Kleinschreibung), Laufwerk als `c:`.
fn lower_components(p: &Path) -> Vec<String> {
    p.components()
        .filter_map(|c| match c {
            Component::Prefix(px) => Some(match px.kind() {
                Prefix::Disk(d) | Prefix::VerbatimDisk(d) => format!("{}:", (d as char).to_ascii_lowercase()),
                _ => px.as_os_str().to_string_lossy().to_lowercase(),
            }),
            Component::RootDir => Some("\\".into()),
            Component::CurDir => None,
            Component::ParentDir => Some("..".into()),
            Component::Normal(n) => Some(n.to_string_lossy().to_lowercase()),
        })
        .collect()
}

/// Liegt `p` in `prefix` (oder ist gleich)? Ohne Unterschied der Groß- und Kleinschreibung.
pub fn starts_with_ci(p: &Path, prefix: &Path) -> bool {
    let (a, b) = (lower_components(p), lower_components(prefix));
    a.len() >= b.len() && a[..b.len()] == b[..]
}

/// Sind beide Pfade gleich (ohne Unterschied der Groß- und Kleinschreibung)?
pub fn eq_ci(a: &Path, b: &Path) -> bool {
    lower_components(a) == lower_components(b)
}

/// Token des eigenen Prozesses.
struct Token(HANDLE);

impl Token {
    fn own() -> Option<Token> {
        let mut h: HANDLE = std::ptr::null_mut();
        // SAFETY: Pseudohandle des eigenen Prozesses
        (unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h) } != 0).then_some(Token(h))
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: eigenes Handle
        unsafe { CloseHandle(self.0) };
    }
}

/// Läuft der Prozess mit vollen Administratorrechten (nach UAC-Bestätigung oder als Dienst)?
pub fn is_elevated() -> bool {
    let Some(t) = Token::own() else { return false };
    let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: Puffer passend zur Abfrage
    let ok = unsafe {
        GetTokenInformation(t.0, TokenElevation, (&mut e as *mut TOKEN_ELEVATION).cast(), size_of::<TOKEN_ELEVATION>() as u32, &mut len)
    };
    ok != 0 && e.TokenIsElevated != 0
}

/// Läuft der Prozess als LocalSystem (Vigil-Dienst)?
pub fn is_local_system() -> bool {
    let Some(t) = Token::own() else { return false };
    let mut buf = vec![0u64; 64];
    let mut len = 0u32;
    // SAFETY: ausreichend großer, ausgerichteter Puffer
    let ok = unsafe { GetTokenInformation(t.0, TokenUser, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut len) };
    if ok == 0 {
        return false;
    }
    // SAFETY: Puffer enthält TOKEN_USER
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    unsafe { IsWellKnownSid(user.User.Sid, WinLocalSystemSid) != 0 }
}

/// Setzt die Zugriffsrechte eines Ordners fest: Besitzer Administratoren, Vollzugriff für
/// SYSTEM und Administratoren, mit `users_read` zusätzlich Lesen für alle Benutzer. Geerbte
/// Rechte werden abgeschaltet, vorhandene Inhalte übernehmen die neuen Rechte. So kann kein
/// Benutzer einen vorher selbst angelegten Ordner unter ProgramData behalten.
pub fn set_dir_acl(path: &Path, users_read: bool) -> Result<(), Text> {
    let sddl = wide(OsStr::new(if users_read { SDDL_USERS_READ } else { SDDL_ADMIN_ONLY }));
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let err = |code: u32| {
        tr!(
            "Die Zugriffsrechte von {} konnten nicht gesetzt werden (Fehler {}).",
            "Could not set the access rights of {} (error {}).",
            path.display(),
            code
        )
    };
    // SAFETY: gültige Zeichenkette, Ergebnis wird mit LocalFree freigegeben
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) } == 0 {
        return Err(err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32));
    }
    let result = (|| {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut owner: PSID = std::ptr::null_mut();
        // SAFETY: gültiger Sicherheitsdeskriptor
        unsafe {
            if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0
                || GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) == 0
            {
                return Err(err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32));
            }
        }
        let name = wide(path.as_os_str());
        // SAFETY: gültige Zeiger aus dem Deskriptor
        let r = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                owner,
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        if r != 0 {
            return Err(err(r));
        }
        Ok(())
    })();
    // SAFETY: von ConvertStringSecurityDescriptorToSecurityDescriptorW angelegt
    unsafe { LocalFree(sd as _) };
    result
}

/// Laufwerke mit Wurzel (`C:\`) und Art (fest, Wechseldatenträger, Netz …).
pub fn drives() -> Vec<(PathBuf, u32)> {
    // SAFETY: keine Vorbedingungen
    let mask = unsafe { GetLogicalDrives() };
    (0..26u8)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| {
            let root = PathBuf::from(format!("{}:\\", (b'A' + i) as char));
            let w = wide(root.as_os_str());
            // SAFETY: gültige Zeichenkette
            let kind = unsafe { GetDriveTypeW(w.as_ptr()) };
            (root, kind)
        })
        .collect()
}

/// Liegt der Pfad auf einem Laufwerk, das nicht fest eingebaut ist (USB, Netz, CD)?
pub fn on_external_drive(p: &Path) -> bool {
    let Some(Component::Prefix(px)) = p.components().next() else { return false };
    let letter = match px.kind() {
        Prefix::Disk(d) | Prefix::VerbatimDisk(d) => d,
        // Netzpfade (\\server\freigabe) gelten als extern
        _ => return true,
    };
    let root = format!("{}:\\", letter as char);
    let w = wide(OsStr::new(&root));
    // SAFETY: gültige Zeichenkette
    unsafe { GetDriveTypeW(w.as_ptr()) != DRIVE_FIXED }
}

/// Snapshot-Handle von Toolhelp.
struct Snapshot(HANDLE);

impl Snapshot {
    fn new(flags: u32) -> Option<Snapshot> {
        // SAFETY: keine Vorbedingungen
        let h = unsafe { CreateToolhelp32Snapshot(flags, 0) };
        (h != INVALID_HANDLE_VALUE && !h.is_null()).then_some(Snapshot(h))
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        // SAFETY: eigenes Handle
        unsafe { CloseHandle(self.0) };
    }
}

/// Programmdatei eines Prozesses (`None`, wenn nicht abfragbar, z. B. geschützte Systemprozesse).
pub fn process_image(pid: u32) -> Option<PathBuf> {
    // SAFETY: Handle wird geschlossen
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 32768];
    let mut len = buf.len() as u32;
    // SAFETY: Puffer mit Länge
    let ok = unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
    unsafe { CloseHandle(h) };
    (ok != 0).then(|| PathBuf::from(OsString::from_wide(&buf[..len as usize])))
}

/// Kennungen und Programmnamen aller laufenden Prozesse.
pub fn processes() -> Vec<(u32, String)> {
    let Some(snap) = Snapshot::new(TH32CS_SNAPPROCESS) else { return Vec::new() };
    let mut out = Vec::new();
    // SAFETY: Struktur mit gesetzter Größe
    let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut ok = unsafe { Process32FirstW(snap.0, &mut e) } != 0;
    while ok {
        let n = e.szExeFile.iter().position(|c| *c == 0).unwrap_or(e.szExeFile.len());
        out.push((e.th32ProcessID, String::from_utf16_lossy(&e.szExeFile[..n])));
        ok = unsafe { Process32NextW(snap.0, &mut e) } != 0;
    }
    out
}

/// Hält alle Threads eines Prozesses an (`resume` false) oder setzt sie fort (wie SIGSTOP und
/// SIGCONT unter Linux, für den clamscan-Ausweichweg).
pub fn suspend_process(pid: u32, resume: bool) {
    let Some(snap) = Snapshot::new(TH32CS_SNAPTHREAD) else { return };
    // SAFETY: Struktur mit gesetzter Größe
    let mut e: THREADENTRY32 = unsafe { std::mem::zeroed() };
    e.dwSize = size_of::<THREADENTRY32>() as u32;
    let mut ok = unsafe { Thread32First(snap.0, &mut e) } != 0;
    while ok {
        if e.th32OwnerProcessID == pid {
            // SAFETY: Handle wird geschlossen
            let h = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, e.th32ThreadID) };
            if !h.is_null() {
                unsafe {
                    if resume {
                        ResumeThread(h);
                    } else {
                        SuspendThread(h);
                    }
                    CloseHandle(h);
                }
            }
        }
        ok = unsafe { Thread32Next(snap.0, &mut e) } != 0;
    }
}

# Vigil unter Windows

Vigil läuft unter Windows 10 und 11 (64 Bit) neben Microsoft Defender; es meldet sich nicht als Virenschutz im Sicherheitscenter an. Datenformate (state.json, Berichte, quarantine.json, system.json, config.json) und Helfer-Befehle sind dieselben wie unter Linux.

## Aufbau des Codes

Module, die sich grundlegend unterscheiden, haben unter Windows eine eigene Datei mit derselben Schnittstelle (`#[cfg_attr(windows, path = "win/…")]` in `crates/vigil-core/src/lib.rs`):

| Modul | Linux | Windows |
|---|---|---|
| `secure_fs` | `openat` mit `O_NOFOLLOW`, Inode-Vergleich | `win/secure_fs.rs`: keine Verknüpfung oder Abzweigung (Junction) im Pfad, Ordner bleibt während der Maßnahme geöffnet, tatsächlicher Pfad per `GetFinalPathNameByHandleW`, Löschen über das geprüfte Handle nach Vergleich von Laufwerk und Dateinummer |
| `systemcheck` | apt, ufw, ss, rkhunter, Lynis | `win/systemcheck.rs`: Windows Update, Defender, Firewall, BitLocker, offene Ports (PowerShell mit JSON), kein Härtungsindex |
| `schedule` | systemd-Timer mit Drop-ins | `win/schedule.rs`: der Vigil-Dienst prüft alle 30 s, was fällig ist (`schedule.json`), verpasste Läufe einmal nachholen |
| `update` | clamav-freshclam neu starten, Journal lesen | `win/update.rs`: freshclam einmal ausführen |
| `extrasigs` | Sanesecurity über rsync und gpgv | `win/extrasigs.rs`: unter Windows noch nicht verfügbar (Stand „aus“ mit Hinweis) |

Kleinere Unterschiede stehen mit `cfg` im Modul: Pfade (`paths.rs`), Sperren (`lock.rs`, unter Windows `File::lock` der Standardbibliothek), clamd über TCP (`clamd.rs`), Schnellprüfung (`quick.rs`), Quarantäne (`quarantine.rs`), Selbst-Update (`selfupdate.rs`), Pro-Rahmen (`pro.rs`). Gemeinsame Windows-Hilfen in `win/mod.rs`, mitgeliefertes ClamAV in `win/clamav.rs`, Festlegungen für Dienst und Pipe in `win/service.rs`.

## Pfade

| Zweck | Pfad | Zugriff |
|---|---|---|
| Programme | `C:\Program Files\Vigil\` (vigil.exe, vigil-helper.exe, `clamav\`, ab 0.4.1 `pro\` mit Vigil Pro) | Installer |
| Daten | `C:\ProgramData\Vigil\` (state.json, reports, system.json …) | SYSTEM und Administratoren voll, Benutzer lesen |
| Konfiguration | `C:\ProgramData\Vigil\config\config.json` | wie Daten |
| Quarantäne, Updates, Pro-Freigabe | `C:\ProgramData\Vigil\quarantine`, `updates`, `pro` | nur SYSTEM und Administratoren |
| ClamAV-Konfiguration und Virendaten | `C:\ProgramData\Vigil\clamav\` (`clamd.conf`, `freshclam.conf`, `db\`, Protokolle) | wie Daten |
| Ergebnisse nach UAC | `C:\ProgramData\Vigil\results\<kennung>.json` | wie Daten, älter als 1 h wird gelöscht |
| Zeitplan | `C:\ProgramData\Vigil\schedule.json` | wie Daten |
| Protokoll des Dienstes | `C:\ProgramData\Vigil\service.log` (höchstens 1 MB, dann `service.log.1`) | wie Daten |
| Benutzer | `%APPDATA%\Vigil\` (settings.json, license.json), `%LOCALAPPDATA%\Vigil\` (watcher.json, `cache\`, `state\status.json`) | Benutzer |

Die Zugriffsrechte setzt der Dienst bei jedem Start fest (Besitzer Administratoren, keine geerbten Rechte), damit ein Benutzer keinen vorher selbst angelegten Ordner unter ProgramData behält. ProgramData und der Installationsordner werden über die Systemregistrierung bzw. den Ort des laufenden Programms bestimmt, nie über Umgebungsvariablen.

## Rechte

- **Vigil-Dienst** `Vigil` (Anzeigename „Vigil Virenschutz“, `vigil-helper.exe service`, LocalSystem, automatischer Start, Neustart nach Absturz). Er übernimmt, was unter Linux `pkexec vigil-scan` ohne Passwort erlaubt: Die App schickt über die benannte Pipe `\\.\pipe\vigil-helper` eine JSON-Zeile `{"lang":"de","args":[…]}`, der Dienst prüft, dass der Befehl in `SCAN_COMMANDS` steht, startet `vigil-helper.exe --lang <lang> <args…>` und antwortet mit `{"code","stdout","stderr"}`. Pipe nur lokal (`PIPE_REJECT_REMOTE_CLIENTS`), Zugriff für angemeldete Benutzer; die App prüft vorher, dass die Pipe von einem Dienst in Sitzung 0 stammt (`GetNamedPipeServerSessionId`; dort laufen nur Dienste, die ein Administrator eingerichtet hat).
- **Alle anderen Befehle** (Quarantäne, Löschen, Freigeben, Einstellungen, Updates, Pro) startet die App über die UAC-Abfrage (`ShellExecuteExW` mit `runas`) als `vigil-helper.exe --result <kennung> --lang <lang> <args…>`. Ein so gestarteter Helfer hat keine Ausgabe für die App; er schreibt Exit-Code, stdout und stderr in die Ergebnisdatei. Abbruch der Abfrage gilt wie Code 126 bei pkexec (keine Meldung).
- Der Helfer läuft nur als SYSTEM oder mit erhöhten Rechten (`TokenElevation`), sonst Exit 3. Im Testbetrieb (`VIGIL_DEV=1`) entfällt die Prüfung.
- Zusätzliche Befehle nur unter Windows: `service` (nur für die Diensteverwaltung), `service-install`, `service-stop`, `service-remove` (für den Installer).

## Vigil-Dienst

- Beim Start: Ordner und Rechte festsetzen, `clamd.conf` und `freshclam.conf` schreiben, Stand der zusätzlichen Signaturen auf „unter Windows nicht verfügbar“.
- clamd aus `C:\Program Files\Vigil\clamav` als Kindprozess, TCP nur auf 127.0.0.1:3310, `StreamMaxLength 26M`. Fehlen Virendaten, lädt freshclam sie zuerst (rund 350 MB, beim ersten Start einige Minuten), danach alle 10 Minuten ein neuer Versuch. Fällt clamd aus, Neustart nach 10 s, 30 s, 1, 2, 5 Minuten.
- Zeitplan: Schnellprüfung, vollständige Prüfung, Systemcheck, automatische Updates zur eingestellten Zeit (mit niedriger Priorität), Virendaten im Abstand `signatureIntervalHours` (freshclam direkt, unabhängig von laufenden Prüfungen). freshclam meldet clamd das Neuladen selbst (`NotifyClamd`).
- Alle Kindprozesse laufen in einem Job-Objekt und enden mit dem Dienst. Beim Beenden wird eine laufende Prüfung über die Abbruchdatei sauber beendet (höchstens 15 s).

## Erkennung

- clamd über TCP mit `zINSTREAM` (zFILDES gibt es unter Windows nicht). clamscan bleibt Ausweichweg; Pausen halten ihn über seine Threads an.
- Schnellprüfung: je Benutzer unter `C:\Users` (ohne Vorlagen) Downloads, Desktop (auch in OneDrive), Autostart-Ordner, `AppData\Local\Temp`; dazu `C:\Windows\Temp`, gemeinsamer Autostart unter ProgramData, `C:\Windows\System32\Tasks`, Programme aller laufenden Prozesse.
- Vollständige Prüfung: alle festen Laufwerke; USB-, Netz- und CD-Laufwerke nur mit `includeMounts`. Immer ausgeschlossen: `pagefile.sys`, `swapfile.sys`, `hiberfil.sys`, `DumpStack.log.tmp`, `System Volume Information`, Datenordner von Vigil.
- Pfadvergleiche (Ausschlüsse, verschachtelte Ziele) ohne Unterschied der Groß- und Kleinschreibung.

## Quarantäne

Wie unter Linux (erneut prüfen, kopieren, Verzeichnis ergänzen, Original über das geprüfte Handle löschen). Die Kopie wird mit einem festen 16-Byte-Schlüssel umkodiert (XOR), damit Defender sie im Quarantäneordner nicht erkennt und löscht. Beim Wiederherstellen erbt die Datei die Rechte des Zielordners; `uid`, `gid` und `mode` sind 0.

## Systemcheck

Prüfpunkte: Virensignaturen (wie Linux), Vigil-Dienst und clamd (Maßnahme `services-enable`: Dienst neu starten), Windows Update (ausstehende Updates, Sicherheitsupdates getrennt, Neustart nötig; Maßnahme `open-update-manager` öffnet `ms-settings:windowsupdate`), Microsoft Defender (Echtzeitschutz, Alter der Virendaten; Maßnahme `open-windows-security`), Firewall je Profil (Maßnahme `firewall-enable`: `Set-NetFirewallProfile -All -Enabled True`), BitLocker des Systemlaufwerks (Hinweis, wenn aus oder nicht verfügbar), offene Ports (TCP und UDP außerhalb von Loopback mit Programmname). `hardeningIndex` ist `null`.

## Updates

Release-Datei `Vigil_X.Y.Z_x64-setup.exe` samt `.exe.sig` (Ed25519 wie die .deb). Der Helfer prüft Signatur, Produktname „Vigil“ und Version aus den Dateieigenschaften, vergleicht mit der eigenen Version und startet den Installer unbeaufsichtigt (`/S /R`) außerhalb des Job-Objekts; der Installer hält den Dienst an, ersetzt die Dateien, richtet den Dienst neu ein und startet Vigil für den angemeldeten Benutzer wieder. Die App beendet sich danach selbst. Der Update-Server bietet seit 0.4.0 die Windows-Dateien neben der .deb an (`/api/core/releases/latest` nennt vier Dateien, `/api/core/files/…` liefert sie).

## App

- Autostart über `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Vigil` (`"…\vigil.exe" --hidden`), beim ersten Start eingeschaltet (Markierung `%APPDATA%\Vigil\autostart-initialized`).
- Benachrichtigungen über das Benachrichtigungs-Plugin von Tauri (Infobereich).
- Fensterprogramm ohne Konsolenfenster (`windows_subsystem = "windows"` im Release-Build).
- Ist das Fenster versteckt oder minimiert, schaltet die App die WebView unsichtbar (`SetIsVisible(false)`), sonst laufen die Animationen unsichtbar weiter und nehmen einer Prüfung die Rechenzeit (unter WebView2 bleibt `document.hidden` sonst false).
- Sprache „System“ folgt der Sprache der Windows-Oberfläche.
- Download-Wächter auf dem Download-Ordner des Benutzers (bekannter Ordner).
- Texte mit anderer Bedeutung unter Windows stehen in `src/i18n/*.ts` unter `win.*` und haben dort Vorrang.
- Vigil Pro (ab 0.4.1): Beim Freischalten sendet die App `os` (`windows`), der Lizenzserver liefert dann das Windows-Paket (`vigil-pro.exe`, `vigil-pro-agent.exe`, `pro-ui.js`).

## Installer

NSIS-`.exe` aus Tauri, Einstellungen in `src-tauri/tauri.windows.conf.json`, Ergänzungen in `packaging/windows/hooks.nsh`: Installation für alle Benutzer, vor dem Kopieren `service-stop`, danach `service-install`, beim Deinstallieren `service-remove` und Autostart des Benutzers entfernen. Daten unter ProgramData bleiben beim Deinstallieren erhalten. Ab 0.4.1 entfernt der Installer beim Deinstallieren (nicht beim Update) auch `pro\` und die geplante Aufgabe `\Vigil\Vigil Pro Berichte`.

ClamAV für Windows liefert `packaging/windows/fetch-clamav.sh`: offizielles Paket von Cisco Talos (GitHub), Signatur mit dem fest eingetragenen Schlüssel geprüft, nur clamd, clamscan, freshclam, Bibliotheken samt Laufzeit von Microsoft, Zertifikate und Lizenztexte nach `target/clamav-win/`.

Bauen von Linux aus (mingw-w64, nsis, Rust-Ziel `x86_64-pc-windows-gnu`):

```bash
cargo tauri build --target x86_64-pc-windows-gnu
```

Ergebnis: `target/x86_64-pc-windows-gnu/release/bundle/nsis/Vigil_<version>_x64-setup.exe`. Der Installer ist nicht mit einem Zertifikat signiert; Windows SmartScreen warnt deshalb beim ersten Start.

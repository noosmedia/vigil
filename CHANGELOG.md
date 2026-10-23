# Changelog

## 0.4.1 (2026-10-23)

### Neu
- Vigil Pro gibt es jetzt auch für Windows 10 und 11: Updates für Programme über winget, Treiber und Firmware über Windows Update, USB-Wächter, erweiterter Echtzeitschutz, Mailschutz mit Passwörtern in der Windows-Anmeldeinformationsverwaltung, Härtung, Systempflege, Berichte und Geräteübersicht.

### Geändert
- Beim Freischalten von Vigil Pro meldet Vigil, ob es unter Linux oder Windows läuft, damit der Lizenzserver das passende Paket liefert.
- Windows: Beim Deinstallieren von Vigil werden auch die Dateien von Vigil Pro und dessen geplante Aufgabe entfernt.
- Unter Linux ändert sich nichts an der Bedienung.

---

### New
- Vigil Pro is now also available for Windows 10 and 11: program updates via winget, drivers and firmware via Windows Update, USB guard, extended real-time protection, mail protection with passwords in Windows Credential Manager, hardening, system cleanup, reports and device overview.

### Changed
- When activating Vigil Pro, Vigil reports whether it runs on Linux or Windows so that the license server delivers the matching package.
- Windows: Uninstalling Vigil also removes the Vigil Pro files and its scheduled task.
- Nothing changes in how Vigil works on Linux.

## 0.4.0 (2026-10-23)

### Neu
- Vigil gibt es jetzt auch für Windows 10 und 11: Installer mit eigenem Vigil-Dienst und mitgeliefertem ClamAV. Prüfungen nach Zeitplan, Download-Wächter, Quarantäne, Systemcheck (Windows Update, Microsoft Defender, Firewall, BitLocker, offene Ports) und Updates wie unter Linux. Vigil arbeitet neben Microsoft Defender.

### Geändert
- Unter Linux ändert sich nichts an der Bedienung.

---

### New
- Vigil is now also available for Windows 10 and 11: installer with its own Vigil service and bundled ClamAV. Scheduled scans, download watcher, quarantine, system check (Windows Update, Microsoft Defender, firewall, BitLocker, open ports) and updates as on Linux. Vigil works alongside Microsoft Defender.

### Changed
- Nothing changes in how Vigil works on Linux.

## 0.3.5 (2026-10-23)

### Neu
- Vigil Pro, Seite „Geräte“: Alle Geräte mit derselben Pro-Lizenz erscheinen mit Schutzstatus, offenen Funden, letzter Prüfung, Virendaten, Updates und Mailschutz. Die Meldungen werden auf dem Gerät verschlüsselt; der Lizenzserver kann sie nicht lesen.
- Die Abfrage von Servern ohne Oberfläche per SSH steht eingeklappt auf derselben Seite.

### Geändert
- Mailschutz: Phishing-Funde heißen „Als Phishing erkannt“ statt „Schadsoftware erkannt“.

---

### New
- Vigil Pro, page "Devices": all devices with the same Pro licence appear with protection status, open findings, last scan, virus data, updates and mail protection. Reports are encrypted on the device; the licence server cannot read them.
- Querying servers without a desktop via SSH is available, collapsed, on the same page.

### Changed
- Mail protection: phishing findings are now called "Detected as phishing" instead of "malware detected".

## 0.3.4 (2026-10-23)

### Neu
- Mailschutz: Nach dem Schützen prüft Vigil auch alle Mails, die schon im Postfach liegen, und verschiebt verdächtige in die Quarantäne.
- Mailschutz: Knopf „Postfach prüfen“ je Postfach, mit Fortschritt („1.234 von 5.678 geprüft, 2 in Quarantäne“) und Abbrechen. Mehrere Postfächer werden nacheinander geprüft.

---

### New
- Mail protection: after protecting a mailbox, Vigil also checks all mails already in it and moves suspicious ones to quarantine.
- Mail protection: "Check mailbox" button for each mailbox, with progress ("1,234 of 5,678 checked, 2 quarantined") and cancel. Several mailboxes are checked one after the other.

## 0.3.3 (2026-10-23)

### Neu
- Ein Knopf für alles: „Jetzt aktualisieren“ spielt Vigil und Vigil Pro nacheinander ein. Das Passwort wird nur einmal abgefragt.
- Während eines Updates zeigt Vigil einen Fortschrittsbalken mit Text („wird heruntergeladen“, „wird auf Echtheit geprüft“, „wird installiert“), und der Pfeil im Knopf bewegt sich.
- Ist nur Vigil Pro neu, steht oben rechts „Pro-Update verfügbar“.

---

### New
- One button for everything: "Update now" installs Vigil and Vigil Pro one after the other. The password is asked only once.
- During an update Vigil shows a progress bar with text ("downloading", "verifying", "installing"), and the arrow in the button moves.
- If only Vigil Pro is new, the top right shows "Pro update available".

## 0.3.2 (2026-10-23)

### Neu
- Gibt es ein Update, steht oben rechts auf jeder Seite „Update verfügbar“. Ein Klick führt direkt zu den Updates. Das gilt für Vigil selbst und, nur mit Pro-Lizenz, auch für Vigil Pro.
- Das Menü des Vigil-Symbols in der Taskleiste zeigt Updates ebenfalls an, auch für Vigil Pro. Ein neues Pro wird einmal per Benachrichtigung gemeldet.

### Geändert
- Der Punkt hinter „Pro“ in der Kopfleiste ist weg; dass Pro aktiv ist, zeigt schon das „Pro“ am Logo.

### Behoben
- In den Einstellungen fehlte das Leerzeichen in „Version 0.3.1 mit Vigil Pro“.
- Unter „Geschützt“ zählt die Übersicht nur noch offene Funde, keine erledigten oder gelöschten mehr.

---

### New
- When an update is available, "Update available" appears at the top right on every page. A click leads straight to the updates. This applies to Vigil itself and, only with a Pro licence, to Vigil Pro.
- The menu of the Vigil icon in the taskbar also shows updates, including Vigil Pro. A new Pro version is announced once with a notification.

### Changed
- The dot after "Pro" in the top bar is gone; the "Pro" next to the logo already shows that Pro is active.

### Fixed
- The settings were missing the space in "Version 0.3.1 with Vigil Pro".
- Below "Protected", the overview now only counts open findings, not resolved or deleted ones.

## 0.3.1 (2026-10-23)

### Neu
- Vigil und Vigil Pro tragen ab jetzt dieselbe Versionsnummer. In den Einstellungen steht „Version 0.3.1 mit Vigil Pro“.
- Updates kommen vom eigenen Update-Server und funktionieren aus der App heraus: „Nach Updates suchen“ prüft Vigil und Vigil Pro mit einem Klick.
- Gibt es ein neues Vigil Pro, zeigen die Pro-Seite und die Einstellungen einen Hinweis mit dem Knopf „Update einspielen“ und melden, wenn es fertig ist.
- Einstellungen, Bereich „Virendaten“: sofort nach neuen Virendaten suchen, festlegen, wie oft automatisch gesucht wird, und zusätzliche kostenlose Virendaten einschalten.
- Mailschutz: Die in Thunderbird und Evolution gefundenen Postfächer stehen direkt auf der Seite, jedes mit Passwortfeld und „Schützen“.
- Zusätzliche kostenlose Virendaten von Sanesecurity, stündlich und auf Echtheit geprüft, vor allem gegen neue Phishing-Mails und Schadprogramme.

### Geändert
- Oben rechts und auf der Übersicht steht jetzt, wann zuletzt nach neuen Virendaten gesucht wurde, und darunter, von wann die Daten sind.
- Das Fachwort „Signaturen“ heißt in der Oberfläche jetzt „Virendaten“.
- Im hellen Modus sind die Animationen der Übersicht deutlich kräftiger und gut zu sehen.

---

### New
- Vigil and Vigil Pro now share one version number. The settings show "Version 0.3.1 with Vigil Pro".
- Updates come from our own update server and work from within the app: "Check for updates" checks Vigil and Vigil Pro with one click.
- When a new Vigil Pro is available, the Pro page and the settings show a notice with an "Install update" button and report when it is done.
- Settings, section "Virus data": check for new virus data right away, choose how often Vigil checks automatically, and turn on additional free virus data.
- Mail protection: the mailboxes found in Thunderbird and Evolution are listed right on the page, each with a password field and "Protect".
- Additional free virus data from Sanesecurity, hourly and checked for authenticity, mainly against new phishing mails and malware.

### Changed
- The top bar and the overview now show when Vigil last checked for new virus data, and below that how old the data is.
- The technical term "signatures" is now called "virus data" in the interface.
- In light mode the animations on the overview are much stronger and easy to see.

## 0.2.2 (2026-10-23)

### Neu
- Systembenachrichtigungen für Meldungen von Vigil Pro, etwa vom neuen Mailschutz
- Mailschutz in der Übersicht der Pro-Funktionen

---

### New
- System notifications for messages from Vigil Pro, for example from the new mail protection
- Mail protection in the list of Pro features

## 0.2.1 (2026-10-23)

### Neu
- Kleines „PRO“ an der Wortmarke, sobald Vigil Pro freigeschaltet ist
- Heuristische Funde (z. B. Phishing-Merkmale in gespeicherten Mails) gelten als Hinweis: eigener Bereich unter Funde, nach Ordnern gruppiert, ausblendbar; kein roter Status, keine Fund-Benachrichtigung, keine automatische Quarantäne

### Geändert
- Mindestgröße des Fensters 1080 × 740
- Weicher Verlauf hinter dem Messwerk, damit die Zahlen vor dem Feld lesbar bleiben

### Behoben
- Orbit-Look wurde oben und unten abgeschnitten
- Unterlängen (g, p, y) im Statuswort wurden abgeschnitten

---

### New
- Small "PRO" next to the word mark once Vigil Pro is activated
- Heuristic detections (e.g. phishing traits in stored mails) count as notices: own section under Findings, grouped by folder, can be dismissed; no red status, no threat notification, no automatic quarantine

### Changed
- Minimum window size 1080 × 740
- Soft gradient behind the meter so the figures stay readable in front of the field

### Fixed
- Orbit look was clipped at the top and bottom
- Descenders (g, p, y) in the status word were clipped

## 0.2.0 (2026-10-23)

### Neu
- Deutsch und Englisch, umschaltbar in den Einstellungen
- Vier Looks, die die ganze App umgestalten: Feld, Orbit, Terminal, Blaupause
- Fünf Farbschemata (Graphit, Tinte, Glut, Fjord, Moos), je hell und dunkel, und sechs Schriften
- Prüfanimation mit den echten Ordnern als Bereiche, Teilchen, Druckwelle bei Funden und Lichtwelle am Ende
- Prüfungen pausieren und fortsetzen, in der App und im Tray
- Tray: Statusfarbe, drehendes Symbol und Prozentangabe während einer Prüfung, Live-Menü
- Einstellung „Mit dem System starten“
- Updates für Vigil selbst über GitHub, signiert, manuell oder automatisch
- Vigil Pro als Zusatz: Software-Center, Treiber und Firmware, USB-Wächter und erweiterter Echtzeitschutz, Härtungs-Assistent, Systempflege, Berichte, Rechner-Übersicht

### Geändert
- Schnellprüfung auf die Orte beschränkt, an denen sich Schadsoftware festsetzt; dauert wenige Minuten statt über einer Stunde
- Schnellere Prüfung über direkte Dateiübergabe an clamd

### Behoben
- Umlaute in großer Schrift wurden oben abgeschnitten

---

### New
- German and English, switchable in the settings
- Four looks that restyle the whole app: Field, Orbit, Terminal, Blueprint
- Five colour schemes (Graphite, Ink, Ember, Fjord, Moss), each light and dark, and six typefaces
- Scan animation with your real folders as sections, particles, a shock wave on findings and a light wave at the end
- Pause and resume scans, in the app and from the tray
- Tray: status colour, spinning icon and percentage during a scan, live menu
- Setting "Start with the system"
- Updates for Vigil itself via GitHub, signed, manual or automatic
- Vigil Pro add-on: software centre, drivers and firmware, USB guard and extended real-time protection, hardening assistant, system cleanup, reports, overview of several computers

### Changed
- Quick scan limited to the places where malware settles; takes a few minutes instead of over an hour
- Faster scanning by handing files directly to clamd

### Fixed
- Umlauts in large type were clipped at the top

## 0.1.0 (2026-10-23)

### Neu
- Erste Version: Prüfungen mit ClamAV nach Zeitplan, Download-Wächter, Quarantäne, Systemcheck mit Updates, Firewall, Ports, rkhunter und Lynis

; Vigil: Ergänzungen für den Windows-Installer (NSIS, von Tauri eingebunden).
; Der Vigil-Dienst (vigil-helper.exe service, LocalSystem) wird nach dem Kopieren eingerichtet
; und gestartet, vor einem Update angehalten und beim Deinstallieren entfernt. Daten unter
; C:\ProgramData\Vigil (Berichte, Quarantäne, Virendaten) bleiben beim Deinstallieren erhalten,
; wie unter Linux /var/lib/vigil.

!macro NSIS_HOOK_PREINSTALL
  ; Laufenden Dienst und ClamAV anhalten, damit sich die Dateien ersetzen lassen
  IfFileExists "$INSTDIR\vigil-helper.exe" 0 vigil_no_old
    nsExec::Exec '"$INSTDIR\vigil-helper.exe" service-stop'
    Pop $0
  vigil_no_old:
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Ordner mit festen Rechten, Konfiguration von ClamAV, Dienst anlegen und starten
  nsExec::ExecToLog '"$INSTDIR\vigil-helper.exe" service-install'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "Der Vigil-Dienst konnte nicht eingerichtet werden (Code $0). Bitte Vigil erneut installieren." /SD IDOK
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Dienst anhalten und entfernen (auch bei einer Neuinstallation über die alte Version)
  nsExec::Exec '"$INSTDIR\vigil-helper.exe" service-remove'
  Pop $0
  ${If} $UpdateMode <> 1
    ; Autostart des Benutzers entfernen; beim nächsten Installieren schaltet Vigil ihn wieder ein
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Vigil"
    SetShellVarContext current
    Delete "$APPDATA\Vigil\autostart-initialized"
    SetShellVarContext all
    ; Vigil Pro: geplante Aufgabe und Programmdateien entfernen (Freigabe und Daten unter ProgramData bleiben)
    nsExec::Exec '"$SYSDIR\schtasks.exe" /Delete /TN "\Vigil\Vigil Pro Berichte" /F'
    Pop $0
    RMDir /r "$INSTDIR\pro"
  ${EndIf}
!macroend

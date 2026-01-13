; NSIS hooks for Oxidize Windows installer
; These run during MSI/NSIS installation to set up the daemon service

!macro customInstall
  ; Install WinDivert files
  SetOutPath "$INSTDIR\WinDivert"
  File /r "${BUILD_RESOURCES_DIR}\WinDivert\*.*"
  
  ; Add WinDivert to PATH
  EnVar::AddValue "PATH" "$INSTDIR\WinDivert"
  
  ; Install and start the daemon service
  DetailPrint "Installing Oxidize daemon service..."
  
  ; Stop existing service if running
  nsExec::ExecToLog 'sc stop OxidizeDaemon'
  Sleep 1000
  nsExec::ExecToLog 'sc delete OxidizeDaemon'
  Sleep 500
  
  ; Create the service
  nsExec::ExecToLog 'sc create OxidizeDaemon binPath= "$INSTDIR\oxidize-daemon.exe" DisplayName= "Oxidize Network Relay Daemon" start= auto'
  
  ; Configure service recovery (restart on failure)
  nsExec::ExecToLog 'sc failure OxidizeDaemon reset= 86400 actions= restart/5000/restart/10000/restart/30000'
  
  ; Add firewall rule
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="Oxidize Daemon"'
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="Oxidize Daemon" dir=out action=allow program="$INSTDIR\oxidize-daemon.exe"'
  
  ; Start the service
  nsExec::ExecToLog 'sc start OxidizeDaemon'
  
  DetailPrint "Oxidize daemon service installed"
!macroend

!macro customUnInstall
  ; Stop and remove the daemon service
  DetailPrint "Removing Oxidize daemon service..."
  
  nsExec::ExecToLog 'sc stop OxidizeDaemon'
  Sleep 1000
  nsExec::ExecToLog 'sc delete OxidizeDaemon'
  
  ; Remove firewall rule
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="Oxidize Daemon"'
  
  ; Remove WinDivert from PATH
  EnVar::DeleteValue "PATH" "$INSTDIR\WinDivert"
  
  DetailPrint "Oxidize daemon service removed"
!macroend

; NSIS hooks for Oxidize Windows installer
; These run during NSIS installation to set up the daemon service

!macro customInstall
  ; Install and start the daemon service
  DetailPrint "Installing Oxidize daemon service..."
  
  ; Find the daemon binary (Tauri bundles sidecars with target triple suffix)
  ; The sidecar is named oxidize-daemon-x86_64-pc-windows-msvc.exe
  StrCpy $0 "$INSTDIR\oxidize-daemon-x86_64-pc-windows-msvc.exe"
  
  ; Stop existing service if running
  nsExec::ExecToLog 'sc stop OxidizeDaemon'
  Sleep 1000
  nsExec::ExecToLog 'sc delete OxidizeDaemon'
  Sleep 500
  
  ; Create the service using the sidecar path
  nsExec::ExecToLog 'sc create OxidizeDaemon binPath= "$0" DisplayName= "Oxidize Network Relay Daemon" start= auto'
  
  ; Configure service recovery (restart on failure)
  nsExec::ExecToLog 'sc failure OxidizeDaemon reset= 86400 actions= restart/5000/restart/10000/restart/30000'
  
  ; Add firewall rule
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="Oxidize Daemon"'
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="Oxidize Daemon" dir=out action=allow program="$0"'
  
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
  
  DetailPrint "Oxidize daemon service removed"
!macroend

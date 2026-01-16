; NSIS hooks for Oxidize Windows installer
; These run during NSIS installation to set up WinDivert and the daemon service

!macro customInstall
  ; Create WinDivert directory
  DetailPrint "Installing WinDivert driver..."
  CreateDirectory "$INSTDIR\WinDivert"
  
  ; Copy WinDivert files from resources
  SetOutPath "$INSTDIR\WinDivert"
  File "${BUILD_RESOURCES_DIR}\WinDivert\WinDivert.dll"
  File "${BUILD_RESOURCES_DIR}\WinDivert\WinDivert64.sys"
  File "${BUILD_RESOURCES_DIR}\WinDivert\WinDivert.lib"
  
  ; Add WinDivert to system PATH
  DetailPrint "Adding WinDivert to PATH..."
  nsExec::ExecToLog 'setx /M PATH "$INSTDIR\WinDivert;%PATH%"'
  
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
  
  DetailPrint "Oxidize daemon service installed with WinDivert"
!macroend

!macro customUnInstall
  ; Stop and remove the daemon service
  DetailPrint "Removing Oxidize daemon service..."
  
  nsExec::ExecToLog 'sc stop OxidizeDaemon'
  Sleep 1000
  nsExec::ExecToLog 'sc delete OxidizeDaemon'
  
  ; Remove firewall rule
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="Oxidize Daemon"'
  
  ; Remove WinDivert directory
  RMDir /r "$INSTDIR\WinDivert"
  
  DetailPrint "Oxidize daemon service and WinDivert removed"
!macroend

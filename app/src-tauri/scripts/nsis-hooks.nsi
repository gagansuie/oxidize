; NSIS hooks for Oxidize Windows installer
; These run during NSIS installation to set up WinDivert and the daemon service

!macro customInstall
  ; Download and install WinDivert
  DetailPrint "Downloading WinDivert driver..."
  CreateDirectory "$INSTDIR\WinDivert"
  
  ; Download WinDivert zip
  inetc::get /TIMEOUT=30000 "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip" "$TEMP\WinDivert.zip" /END
  Pop $0
  StrCmp $0 "OK" +3
    DetailPrint "Failed to download WinDivert: $0"
    Goto skipWinDivert
  
  ; Extract WinDivert
  DetailPrint "Extracting WinDivert..."
  nsisunz::UnzipToLog "$TEMP\WinDivert.zip" "$TEMP\WinDivert"
  
  ; Copy x64 files
  CopyFiles /SILENT "$TEMP\WinDivert\WinDivert-2.2.2-A\x64\*.*" "$INSTDIR\WinDivert"
  
  ; Cleanup temp files
  Delete "$TEMP\WinDivert.zip"
  RMDir /r "$TEMP\WinDivert"
  
  ; Add WinDivert to system PATH
  DetailPrint "Adding WinDivert to PATH..."
  nsExec::ExecToLog 'setx /M PATH "$INSTDIR\WinDivert;%PATH%"'
  
  skipWinDivert:
  
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
  
  ; Remove WinDivert directory
  RMDir /r "$INSTDIR\WinDivert"
  
  DetailPrint "Oxidize daemon service and WinDivert removed"
!macroend

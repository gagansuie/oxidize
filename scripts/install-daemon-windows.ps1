# Oxidize Daemon Installer for Windows
# This script installs the oxidize-daemon as a Windows service
# and sets up WinDivert driver for packet capture
# Run as Administrator

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

Write-Host "╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Oxidize Daemon Installer (Windows)  ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Configuration
$ServiceName = "OxidizeDaemon"
$ServiceDisplayName = "Oxidize Network Relay Daemon"
$InstallDir = "$env:ProgramFiles\Oxidize"
$DaemonExe = "$InstallDir\oxidize-daemon.exe"
$WinDivertDir = "$InstallDir\WinDivert"

# Find the daemon binary
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceBin = $null

$SearchPaths = @(
    "$ScriptDir\..\target\release\oxidize-daemon.exe",
    "$ScriptDir\..\daemon\target\release\oxidize-daemon.exe",
    ".\oxidize-daemon.exe"
)

foreach ($path in $SearchPaths) {
    if (Test-Path $path) {
        $SourceBin = (Resolve-Path $path).Path
        break
    }
}

if (-not $SourceBin) {
    Write-Host "Error: oxidize-daemon.exe not found" -ForegroundColor Red
    Write-Host "Please build first: cargo build --release -p oxidize-daemon"
    exit 1
}

Write-Host "→ Found daemon binary: $SourceBin" -ForegroundColor Green

# Stop existing service if running
Write-Host "→ Checking for existing service..."
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "  Stopping existing service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "  Removing existing service..."
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# Create install directory
Write-Host "→ Creating install directory..."
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Copy daemon binary
Write-Host "→ Installing daemon binary..."
Copy-Item -Path $SourceBin -Destination $DaemonExe -Force

# Download and install WinDivert
Write-Host "→ Setting up WinDivert driver..."
$WinDivertVersion = "2.2.2"
$WinDivertUrl = "https://github.com/basil00/WinDivert/releases/download/v$WinDivertVersion/WinDivert-$WinDivertVersion-A.zip"
$WinDivertZip = "$env:TEMP\WinDivert.zip"

if (-not (Test-Path $WinDivertDir)) {
    New-Item -ItemType Directory -Path $WinDivertDir -Force | Out-Null
}

# Check if WinDivert is already installed
$WinDivertDll = "$WinDivertDir\WinDivert.dll"
$WinDivertSys = "$WinDivertDir\WinDivert64.sys"

if (-not (Test-Path $WinDivertDll) -or -not (Test-Path $WinDivertSys)) {
    Write-Host "  Downloading WinDivert v$WinDivertVersion..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $WinDivertUrl -OutFile $WinDivertZip -UseBasicParsing
        
        Write-Host "  Extracting WinDivert..."
        Expand-Archive -Path $WinDivertZip -DestinationPath "$env:TEMP\WinDivert" -Force
        
        # Copy x64 files
        $ExtractedDir = "$env:TEMP\WinDivert\WinDivert-$WinDivertVersion-A\x64"
        Copy-Item -Path "$ExtractedDir\*" -Destination $WinDivertDir -Force -Recurse
        
        # Cleanup
        Remove-Item -Path $WinDivertZip -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:TEMP\WinDivert" -Recurse -Force -ErrorAction SilentlyContinue
        
        Write-Host "  ✓ WinDivert installed" -ForegroundColor Green
    }
    catch {
        Write-Host "  ⚠ Failed to download WinDivert: $_" -ForegroundColor Yellow
        Write-Host "  Please manually download from: https://github.com/basil00/WinDivert/releases"
        Write-Host "  And extract to: $WinDivertDir"
    }
} else {
    Write-Host "  ✓ WinDivert already installed" -ForegroundColor Green
}

# Add WinDivert to PATH for the service
Write-Host "→ Configuring environment..."
$MachinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($MachinePath -notlike "*$WinDivertDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$MachinePath;$WinDivertDir", "Machine")
    Write-Host "  ✓ Added WinDivert to system PATH" -ForegroundColor Green
}

# Create Windows service
Write-Host "→ Creating Windows service..."
$ServiceParams = @{
    Name = $ServiceName
    BinaryPathName = $DaemonExe
    DisplayName = $ServiceDisplayName
    Description = "Oxidize network relay daemon for low-latency gaming traffic optimization"
    StartupType = "Automatic"
}

New-Service @ServiceParams | Out-Null
Write-Host "  ✓ Service created" -ForegroundColor Green

# Configure service recovery options (restart on failure)
Write-Host "→ Configuring service recovery..."
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

# Add firewall rule
Write-Host "→ Configuring Windows Firewall..."
$FirewallRuleName = "Oxidize Daemon"
Remove-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $FirewallRuleName `
    -Direction Outbound `
    -Program $DaemonExe `
    -Action Allow `
    -Profile Any | Out-Null
Write-Host "  ✓ Firewall rule added" -ForegroundColor Green

# Start the service
Write-Host "→ Starting service..."
Start-Service -Name $ServiceName
Start-Sleep -Seconds 2

# Verify service is running
$service = Get-Service -Name $ServiceName
if ($service.Status -eq "Running") {
    Write-Host ""
    Write-Host "✅ Oxidize daemon installed and running!" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "⚠ Service installed but may not be running. Check Event Viewer for details." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Privileges configured at install-time:" -ForegroundColor Cyan
Write-Host "  • WinDivert driver installed for packet capture"
Write-Host "  • Windows service runs with SYSTEM privileges"
Write-Host "  • Firewall rule configured"
Write-Host ""
Write-Host "Commands:" -ForegroundColor Cyan
Write-Host "  Get-Service $ServiceName              - Check status"
Write-Host "  Stop-Service $ServiceName             - Stop daemon"
Write-Host "  Get-EventLog -LogName Application     - View logs"
Write-Host ""
Write-Host "Install location: $InstallDir" -ForegroundColor Gray

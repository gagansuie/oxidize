# Oxidize Complete Uninstaller for Windows
# Run as Administrator
# Usage: .\uninstall-windows.ps1 [--local-only] [--repo PATH]

#Requires -RunAsAdministrator

param(
    [switch]$LocalOnly,
    [string]$Repo
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              Oxidize Complete Uninstaller                  ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Configuration
$ServiceName = "OxidizeDaemon"
$InstallDir = "$env:ProgramFiles\Oxidize"
$WinDivertDir = "$InstallDir\WinDivert"
$AppDataDir = "$env:LOCALAPPDATA\com.oxidize.app"
$ConfigDir = "$env:APPDATA\Oxidize"

function Uninstall-LocalBuilds {
    param([string]$RepoPath)
    
    if (-not $RepoPath -or -not (Test-Path $RepoPath)) {
        return
    }
    
    Write-Host "→ Cleaning local builds in $RepoPath..." -ForegroundColor Yellow
    
    # Clean Rust target directories
    $TargetDir = Join-Path $RepoPath "target"
    if (Test-Path $TargetDir) {
        Write-Host "  Removing target\ directory..."
        Remove-Item -Path $TargetDir -Recurse -Force
    }
    
    # Clean Tauri app builds
    $TauriTarget = Join-Path $RepoPath "app\src-tauri\target"
    if (Test-Path $TauriTarget) {
        Write-Host "  Removing app\src-tauri\target\ directory..."
        Remove-Item -Path $TauriTarget -Recurse -Force
    }
    
    # Clean Tauri generated files
    $TauriGen = Join-Path $RepoPath "app\src-tauri\gen"
    if (Test-Path $TauriGen) {
        Write-Host "  Removing app\src-tauri\gen\ directory..."
        Remove-Item -Path $TauriGen -Recurse -Force
    }
    
    # Clean node_modules
    $NodeModules = Join-Path $RepoPath "app\node_modules"
    if (Test-Path $NodeModules) {
        Write-Host "  Removing app\node_modules\ directory..."
        Remove-Item -Path $NodeModules -Recurse -Force
    }
    
    # Clean HF downloads
    $HfDownload = Join-Path $RepoPath "hf_download"
    if (Test-Path $HfDownload) {
        Write-Host "  Removing hf_download\ directory..."
        Remove-Item -Path $HfDownload -Recurse -Force
    }
    
    Write-Host "  ✓ Local builds cleaned" -ForegroundColor Green
}

function Uninstall-System {
    # Stop and remove Windows service
    Write-Host "→ Stopping service..." -ForegroundColor Yellow
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Write-Host "→ Removing service..." -ForegroundColor Yellow
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 1
        Write-Host "  ✓ Service removed" -ForegroundColor Green
    } else {
        Write-Host "  Service not found (already removed)" -ForegroundColor Gray
    }
    
    # Remove firewall rule
    Write-Host "→ Removing firewall rule..." -ForegroundColor Yellow
    Remove-NetFirewallRule -DisplayName "Oxidize Daemon" -ErrorAction SilentlyContinue
    
    # Remove install directory (binaries + WinDivert)
    Write-Host "→ Removing program files..." -ForegroundColor Yellow
    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-Host "  ✓ Removed $InstallDir" -ForegroundColor Green
    }
    
    # Remove WinDivert from PATH
    Write-Host "→ Cleaning system PATH..." -ForegroundColor Yellow
    $MachinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($MachinePath -like "*$WinDivertDir*") {
        $NewPath = ($MachinePath -split ";" | Where-Object { $_ -ne $WinDivertDir }) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "Machine")
        Write-Host "  ✓ Removed WinDivert from PATH" -ForegroundColor Green
    }
    
    # Remove user app data
    Write-Host "→ Removing user app data..." -ForegroundColor Yellow
    if (Test-Path $AppDataDir) {
        Remove-Item -Path $AppDataDir -Recurse -Force
        Write-Host "  ✓ Removed $AppDataDir" -ForegroundColor Green
    }
    
    # Remove config directory
    if (Test-Path $ConfigDir) {
        Remove-Item -Path $ConfigDir -Recurse -Force
        Write-Host "  ✓ Removed $ConfigDir" -ForegroundColor Green
    }
}

# Main
if ($LocalOnly) {
    Write-Host "Local-only mode: cleaning build artifacts only" -ForegroundColor Yellow
    
    if ($Repo) {
        Uninstall-LocalBuilds -RepoPath $Repo
    } else {
        # Try to detect repo from script location
        $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        $RepoDir = Split-Path -Parent $ScriptDir
        $CargoToml = Join-Path $RepoDir "Cargo.toml"
        
        if (Test-Path $CargoToml) {
            Uninstall-LocalBuilds -RepoPath $RepoDir
        } else {
            Write-Host "Could not detect oxidize repo. Use -Repo PATH" -ForegroundColor Red
            exit 1
        }
    }
    
    Write-Host ""
    Write-Host "✅ Local builds cleaned!" -ForegroundColor Green
    exit 0
}

# Full uninstall
Uninstall-System

# Clean local builds if repo specified
if ($Repo) {
    Uninstall-LocalBuilds -RepoPath $Repo
}

# Try to detect and clean repo from script location
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoDir = Split-Path -Parent $ScriptDir
$CargoToml = Join-Path $RepoDir "Cargo.toml"

if (Test-Path $CargoToml) {
    $CargoContent = Get-Content $CargoToml -Raw
    if ($CargoContent -like "*oxidize*") {
        Uninstall-LocalBuilds -RepoPath $RepoDir
    }
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "           ✅ Oxidize Completely Uninstalled!              " -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "Removed:" -ForegroundColor Cyan
Write-Host "  • Windows service (OxidizeDaemon)"
Write-Host "  • Program files ($InstallDir)"
Write-Host "  • WinDivert driver"
Write-Host "  • Firewall rules"
Write-Host "  • User app data"
Write-Host "  • Local builds (if detected)"
Write-Host ""
Write-Host "Your system is clean!" -ForegroundColor Green
Write-Host ""

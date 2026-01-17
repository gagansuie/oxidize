use anyhow::{Context, Result};
use std::process::Command;
use tracing::{info, warn};

#[cfg(unix)]
const DAEMON_SOCKET: &str = "/var/run/oxidize/daemon.sock";

#[cfg(windows)]
const DAEMON_PIPE: &str = r"\\.\pipe\oxidize-daemon";

/// Check if the daemon is running
pub async fn is_daemon_running() -> bool {
    #[cfg(unix)]
    {
        std::path::Path::new(DAEMON_SOCKET).exists()
    }
    #[cfg(windows)]
    {
        std::path::Path::new(DAEMON_PIPE).exists()
    }
}

/// Find the daemon binary path
fn find_daemon_binary() -> Option<String> {
    // Check same directory as client binary first
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            #[cfg(windows)]
            let daemon_name = "oxidize-daemon.exe";
            #[cfg(not(windows))]
            let daemon_name = "oxidize-daemon";

            let daemon_path = exe_dir.join(daemon_name);
            if daemon_path.exists() {
                return Some(daemon_path.to_string_lossy().to_string());
            }
        }
    }

    // Check system paths
    let system_paths = ["/usr/bin/oxidize-daemon", "/usr/local/bin/oxidize-daemon"];

    for path in system_paths {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }

    None
}

/// Install and start the daemon with elevated privileges
#[cfg(target_os = "linux")]
pub fn install_daemon() -> Result<()> {
    let daemon_bin = find_daemon_binary()
        .context("Daemon binary not found. Ensure oxidize-daemon is in the same directory or installed to /usr/bin/")?;

    info!("Installing daemon from: {}", daemon_bin);

    let install_script = format!(
        r#"
        set -e
        mkdir -p /var/run/oxidize
        mkdir -p /etc/oxidize
        cp "{}" /usr/local/bin/oxidize-daemon
        chmod +x /usr/local/bin/oxidize-daemon
        
        # Create iptables rules script for NFQUEUE
        cat > /etc/oxidize/nfqueue-rules.sh << 'RULES'
#!/bin/bash
QUEUE_NUM=0
iptables -D OUTPUT -p udp -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null || true
iptables -I OUTPUT -p udp -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass
RULES
        chmod +x /etc/oxidize/nfqueue-rules.sh
        
        # Create systemd service (runs as root for NFQUEUE/iptables)
        cat > /etc/systemd/system/oxidize-daemon.service << 'EOF'
[Unit]
Description=Oxidize Network Relay Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/etc/oxidize/nfqueue-rules.sh
ExecStart=/usr/local/bin/oxidize-daemon
ExecStopPost=/sbin/iptables -D OUTPUT -p udp -j NFQUEUE --queue-num 0 2>/dev/null || true
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info
PrivateTmp=true
ReadWritePaths=/var/run/oxidize

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable oxidize-daemon
        systemctl start oxidize-daemon
        "#,
        daemon_bin
    );

    let status = Command::new("pkexec")
        .args(["bash", "-c", &install_script])
        .status()
        .context("Failed to run pkexec for daemon installation")?;

    if !status.success() {
        anyhow::bail!(
            "Daemon installation failed with exit code: {:?}",
            status.code()
        );
    }

    info!("Daemon installed and started successfully");
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn install_daemon() -> Result<()> {
    let daemon_bin = find_daemon_binary()
        .context("Daemon binary not found. Ensure oxidize-daemon is in the same directory or installed to /usr/local/bin/")?;

    info!("Installing daemon from: {}", daemon_bin);

    let install_script = format!(
        r#"
        mkdir -p /var/run/oxidize
        cp "{}" /usr/local/bin/oxidize-daemon
        chmod +x /usr/local/bin/oxidize-daemon
        
        # Create launchd plist (runs as root for packet capture)
        cat > /Library/LaunchDaemons/com.oxidize.daemon.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.oxidize.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/oxidize-daemon</string>
    </array>
    <key>UserName</key>
    <string>root</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/oxidize-daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/oxidize-daemon.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
</dict>
</plist>
EOF
        
        launchctl unload /Library/LaunchDaemons/com.oxidize.daemon.plist 2>/dev/null || true
        launchctl load /Library/LaunchDaemons/com.oxidize.daemon.plist
        "#,
        daemon_bin
    );

    let status = Command::new("osascript")
        .args([
            "-e",
            &format!(
                r#"do shell script "{}" with administrator privileges"#,
                install_script.replace('"', r#"\""#).replace('\n', " ")
            ),
        ])
        .status()
        .context("Failed to run installation with administrator privileges")?;

    if !status.success() {
        anyhow::bail!("Daemon installation failed");
    }

    info!("Daemon installed and started successfully");
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn install_daemon() -> Result<()> {
    let daemon_bin = find_daemon_binary()
        .context("Daemon binary not found. Ensure oxidize-daemon.exe is in the same directory")?;

    info!("Installing daemon from: {}", daemon_bin);

    // Copy to Program Files and create service (runs as LocalSystem for admin privileges)
    let install_script = format!(
        r#"
        $ErrorActionPreference = "Stop"
        
        # Stop and remove existing service
        Stop-Service -Name "OxidizeDaemon" -Force -ErrorAction SilentlyContinue
        sc.exe delete OxidizeDaemon 2>$null
        Start-Sleep -Seconds 1
        
        # Copy daemon to Program Files
        $targetDir = "$env:ProgramFiles\Oxidize"
        New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
        Copy-Item "{}" -Destination "$targetDir\oxidize-daemon.exe" -Force
        
        # Create Windows service (runs as LocalSystem for WinDivert access)
        sc.exe create OxidizeDaemon binPath= "$targetDir\oxidize-daemon.exe" DisplayName= "Oxidize Network Relay Daemon" start= auto obj= LocalSystem
        sc.exe failure OxidizeDaemon reset= 86400 actions= restart/5000/restart/10000/restart/30000
        sc.exe description OxidizeDaemon "Oxidize network relay daemon for traffic tunneling"
        
        # Add firewall rules (both inbound and outbound)
        netsh advfirewall firewall delete rule name="Oxidize Daemon" 2>$null
        netsh advfirewall firewall add rule name="Oxidize Daemon" dir=out action=allow program="$targetDir\oxidize-daemon.exe"
        netsh advfirewall firewall add rule name="Oxidize Daemon In" dir=in action=allow program="$targetDir\oxidize-daemon.exe"
        
        # Start service
        Start-Service -Name "OxidizeDaemon"
        "#,
        daemon_bin.replace('\\', "\\\\")
    );

    let status = Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-Command', '{}'",
                install_script.replace('\'', "''")
            ),
        ])
        .status()
        .context("Failed to run installation with administrator privileges")?;

    if !status.success() {
        anyhow::bail!("Daemon installation failed");
    }

    info!("Daemon installed and started successfully");
    Ok(())
}

/// Ensure daemon is running, installing if necessary
pub async fn ensure_daemon_running() -> Result<()> {
    if is_daemon_running().await {
        info!("Daemon is already running");
        return Ok(());
    }

    warn!("Daemon not running, attempting to install and start...");
    install_daemon()?;

    // Wait for daemon to start
    for i in 0..10 {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        if is_daemon_running().await {
            info!("Daemon started successfully");
            return Ok(());
        }
        if i == 9 {
            anyhow::bail!("Daemon installed but failed to start. Check system logs for details.");
        }
    }

    Ok(())
}

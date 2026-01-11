//! Graceful shutdown and zero-downtime deployment support
//!
//! This module provides:
//! - Graceful connection draining on shutdown signals
//! - SO_REUSEPORT for running multiple server instances
//! - Connection state tracking for clean handoffs

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, watch};
use tracing::{info, warn};

/// Shutdown coordinator for graceful termination
pub struct ShutdownCoordinator {
    /// Signal to stop accepting new connections
    shutdown_signal: watch::Sender<bool>,
    /// Receiver for shutdown signal
    shutdown_rx: watch::Receiver<bool>,
    /// Broadcast channel to notify all connections
    drain_tx: broadcast::Sender<()>,
    /// Number of active connections
    active_connections: Arc<AtomicUsize>,
    /// Whether we're in draining mode
    is_draining: Arc<AtomicBool>,
    /// Grace period for connection draining
    drain_timeout: Duration,
}

impl ShutdownCoordinator {
    pub fn new(drain_timeout: Duration) -> Self {
        let (shutdown_signal, shutdown_rx) = watch::channel(false);
        let (drain_tx, _) = broadcast::channel(1);

        Self {
            shutdown_signal,
            shutdown_rx,
            drain_tx,
            active_connections: Arc::new(AtomicUsize::new(0)),
            is_draining: Arc::new(AtomicBool::new(false)),
            drain_timeout,
        }
    }

    /// Get a handle for tracking connections
    pub fn connection_tracker(&self) -> ConnectionTracker {
        ConnectionTracker {
            active_connections: self.active_connections.clone(),
            drain_rx: self.drain_tx.subscribe(),
            is_draining: self.is_draining.clone(),
        }
    }

    /// Get a receiver to check if shutdown was signaled
    pub fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    /// Check if we should accept new connections
    pub fn should_accept(&self) -> bool {
        !self.is_draining.load(Ordering::SeqCst)
    }

    /// Get current active connection count
    pub fn active_count(&self) -> usize {
        self.active_connections.load(Ordering::SeqCst)
    }

    /// Initiate graceful shutdown
    /// Returns when all connections are drained or timeout expires
    pub async fn shutdown(&self) {
        info!("🔄 Initiating graceful shutdown...");

        // Stop accepting new connections
        self.is_draining.store(true, Ordering::SeqCst);
        let _ = self.shutdown_signal.send(true);

        // Notify all connections to finish up
        let _ = self.drain_tx.send(());

        let start = std::time::Instant::now();
        let check_interval = Duration::from_millis(100);

        // Wait for connections to drain
        loop {
            let active = self.active_connections.load(Ordering::SeqCst);

            if active == 0 {
                info!("✅ All connections drained gracefully");
                break;
            }

            if start.elapsed() >= self.drain_timeout {
                warn!(
                    "⚠️  Drain timeout reached with {} connections remaining",
                    active
                );
                break;
            }

            if start.elapsed().as_secs() % 5 == 0 && start.elapsed().as_millis() % 5000 < 100 {
                info!(
                    "   Draining... {} connections remaining ({:.0}s elapsed)",
                    active,
                    start.elapsed().as_secs_f32()
                );
            }

            tokio::time::sleep(check_interval).await;
        }

        info!(
            "🛑 Shutdown complete after {:.1}s",
            start.elapsed().as_secs_f32()
        );
    }
}

/// Handle for tracking individual connections
pub struct ConnectionTracker {
    active_connections: Arc<AtomicUsize>,
    drain_rx: broadcast::Receiver<()>,
    is_draining: Arc<AtomicBool>,
}

impl ConnectionTracker {
    /// Register a new connection
    pub fn register(&self) -> ConnectionGuard {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
        ConnectionGuard {
            active_connections: self.active_connections.clone(),
        }
    }

    /// Check if server is draining (should finish work quickly)
    pub fn is_draining(&self) -> bool {
        self.is_draining.load(Ordering::SeqCst)
    }

    /// Wait for drain signal
    pub async fn wait_for_drain(&mut self) {
        let _ = self.drain_rx.recv().await;
    }

    /// Clone for spawning tasks
    pub fn clone_tracker(&self) -> Self {
        Self {
            active_connections: self.active_connections.clone(),
            drain_rx: self.drain_rx.resubscribe(),
            is_draining: self.is_draining.clone(),
        }
    }
}

/// RAII guard that decrements connection count on drop
pub struct ConnectionGuard {
    active_connections: Arc<AtomicUsize>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Create a UDP socket with SO_REUSEPORT enabled
/// This allows multiple server processes to bind to the same port
/// for zero-downtime rolling restarts
pub fn create_reuseport_socket(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // Enable SO_REUSEPORT - allows multiple processes to bind to same port
    // Kernel load-balances incoming packets between them
    #[cfg(unix)]
    {
        socket.set_reuse_port(true)?;
    }

    // Also set SO_REUSEADDR for faster restarts
    socket.set_reuse_address(true)?;

    // Increase socket buffer sizes for high throughput
    socket.set_recv_buffer_size(16 * 1024 * 1024)?; // 16MB
    socket.set_send_buffer_size(16 * 1024 * 1024)?; // 16MB

    // Bind to address
    socket.bind(&addr.into())?;

    // Set non-blocking for async runtime
    socket.set_nonblocking(true)?;

    Ok(socket.into())
}

/// Setup signal handlers for graceful shutdown
pub async fn setup_signal_handlers(coordinator: Arc<ShutdownCoordinator>) {
    use tokio::signal::unix::{signal, SignalKind};

    let coordinator_term = coordinator.clone();
    let coordinator_int = coordinator.clone();
    let coordinator_quit = coordinator.clone();

    // SIGTERM - Standard termination signal (systemd, docker)
    tokio::spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM");
        sigterm.recv().await;
        info!("📥 Received SIGTERM");
        coordinator_term.shutdown().await;
        std::process::exit(0);
    });

    // SIGINT - Ctrl+C
    tokio::spawn(async move {
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to register SIGINT");
        sigint.recv().await;
        info!("📥 Received SIGINT (Ctrl+C)");
        coordinator_int.shutdown().await;
        std::process::exit(0);
    });

    // SIGQUIT - Graceful shutdown with more time
    tokio::spawn(async move {
        let mut sigquit = signal(SignalKind::quit()).expect("Failed to register SIGQUIT");
        sigquit.recv().await;
        info!("📥 Received SIGQUIT (graceful)");
        coordinator_quit.shutdown().await;
        std::process::exit(0);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_tracking() {
        let coordinator = ShutdownCoordinator::new(Duration::from_secs(5));
        let tracker = coordinator.connection_tracker();

        assert_eq!(coordinator.active_count(), 0);

        let guard1 = tracker.register();
        assert_eq!(coordinator.active_count(), 1);

        let guard2 = tracker.register();
        assert_eq!(coordinator.active_count(), 2);

        drop(guard1);
        assert_eq!(coordinator.active_count(), 1);

        drop(guard2);
        assert_eq!(coordinator.active_count(), 0);
    }

    #[tokio::test]
    async fn test_shutdown_draining() {
        let coordinator = Arc::new(ShutdownCoordinator::new(Duration::from_millis(100)));
        let tracker = coordinator.connection_tracker();

        // Register a connection
        let _guard = tracker.register();

        // Start shutdown in background
        let coord = coordinator.clone();
        tokio::spawn(async move {
            coord.shutdown().await;
        });

        // Wait a bit for draining to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert!(tracker.is_draining());
    }
}

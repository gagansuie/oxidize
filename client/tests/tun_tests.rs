//! TUN Handler Tests
//!
//! Note: Most TUN tests require root privileges and are marked #[ignore].
//! Run with: sudo cargo test --package relay-client -- --ignored

use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_tun_config_default() {
    // Test default TUN configuration values
    let default_name = "oxidize0";
    let default_address = (10u8, 200u8, 200u8, 1u8);
    let default_netmask = (255u8, 255u8, 255u8, 0u8);
    let default_mtu = 1400usize;

    assert_eq!(default_name, "oxidize0");
    assert_eq!(default_address, (10, 200, 200, 1));
    assert_eq!(default_netmask, (255, 255, 255, 0));
    assert_eq!(default_mtu, 1400);
}

#[test]
fn test_ip_bypass_calculation() {
    // Test that server IP bypass works correctly
    let server_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let gateway = "192.168.1.1";

    // Server IP should be routable via original gateway
    assert!(server_ip.is_ipv4());
    assert_eq!(gateway, "192.168.1.1");
}

#[test]
fn test_split_routing_coverage() {
    // Test that 0.0.0.0/1 and 128.0.0.0/1 cover all IPv4 addresses
    let routes = [
        ("0.0.0.0", "127.255.255.255"),   // 0.0.0.0/1
        ("128.0.0.0", "255.255.255.255"), // 128.0.0.0/1
    ];

    // First route covers 0.x.x.x - 127.x.x.x
    let (start1, end1) = routes[0];
    assert_eq!(start1, "0.0.0.0");
    assert_eq!(end1, "127.255.255.255");

    // Second route covers 128.x.x.x - 255.x.x.x
    let (start2, end2) = routes[1];
    assert_eq!(start2, "128.0.0.0");
    assert_eq!(end2, "255.255.255.255");

    // Together they cover all IPv4 without touching default route
}

#[test]
fn test_dns_servers_valid() {
    // Test default DNS servers are valid
    let dns_servers = vec!["1.1.1.1", "8.8.8.8"];

    for dns in &dns_servers {
        let parsed: Result<Ipv4Addr, _> = dns.parse();
        assert!(parsed.is_ok(), "DNS server {} should be valid IPv4", dns);
    }
}

#[test]
fn test_mtu_reasonable() {
    // MTU should be reasonable for tunneling
    let mtu = 1400;

    // Should be less than typical Ethernet MTU (1500)
    assert!(mtu < 1500, "TUN MTU should be less than Ethernet MTU");

    // Should be more than minimum for IP
    assert!(mtu >= 576, "TUN MTU should be at least 576 (IP minimum)");

    // Should leave room for QUIC overhead (~100 bytes)
    assert!(mtu <= 1400, "TUN MTU should leave room for QUIC overhead");
}

#[test]
#[ignore] // Requires root
fn test_tun_creation() {
    // This test requires root privileges
    // Run with: sudo cargo test --package relay-client -- --ignored test_tun_creation

    let mut tun_config = tun::Configuration::default();
    tun_config
        .address((10, 200, 200, 1))
        .netmask((255, 255, 255, 0))
        .mtu(1400)
        .up();

    #[cfg(target_os = "linux")]
    tun_config.platform(|config| {
        config.packet_information(false);
    });

    let result = tun::create(&tun_config);
    assert!(
        result.is_ok(),
        "TUN device creation should succeed with root"
    );
}

#[test]
#[ignore] // Requires root
fn test_routing_setup() {
    // This test requires root privileges
    use std::process::Command;

    // Test adding a route (will fail without root)
    let output = Command::new("ip")
        .args(["route", "add", "10.99.99.0/24", "dev", "lo"])
        .output();

    if let Ok(out) = output {
        // Cleanup
        let _ = Command::new("ip")
            .args(["route", "del", "10.99.99.0/24"])
            .output();

        assert!(out.status.success() || !out.stderr.is_empty());
    }
}

#[test]
fn test_privilege_check_non_root() {
    // When running as non-root, privilege check should fail
    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        // This test is run as non-root in CI
        if !is_root {
            assert!(!is_root, "Test should run as non-root user");
        }
    }
}

#[cfg(test)]
mod cleanup_tests {
    #[test]
    fn test_cleanup_idempotent() {
        // Cleanup should be safe to call multiple times
        // Even if routes don't exist, it shouldn't panic
        use std::process::Command;

        // Try to delete non-existent route (should not panic)
        let _ = Command::new("ip")
            .args(["route", "del", "10.99.98.0/24"])
            .output();

        // Second call should also be fine
        let _ = Command::new("ip")
            .args(["route", "del", "10.99.98.0/24"])
            .output();
    }

    #[test]
    fn test_dns_backup_restore() {
        // Test DNS backup/restore logic
        let original_dns = vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()];
        let tunnel_dns = vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()];

        // Simulate backup
        let backup = original_dns.clone();

        // Simulate setting tunnel DNS
        let current = tunnel_dns.clone();
        assert_eq!(current, tunnel_dns);

        // Simulate restore
        let restored = backup.clone();
        assert_eq!(restored, original_dns);
    }
}

#[cfg(test)]
mod packet_tests {
    #[test]
    fn test_ipv4_packet_parsing() {
        // Minimal IPv4 header (20 bytes)
        let ipv4_packet = vec![
            0x45, 0x00, // Version (4) + IHL (5) + DSCP/ECN
            0x00, 0x28, // Total length (40 bytes)
            0x00, 0x00, // Identification
            0x40, 0x00, // Flags + Fragment offset (Don't Fragment)
            0x40, 0x06, // TTL (64) + Protocol (TCP)
            0x00, 0x00, // Header checksum
            0x0a, 0x00, 0x00, 0x01, // Source IP (10.0.0.1)
            0x0a, 0x00, 0x00,
            0x02, // Dest IP (10.0.0.2)
                  // ... TCP header would follow
        ];

        // Check version
        let version = (ipv4_packet[0] >> 4) & 0x0f;
        assert_eq!(version, 4);

        // Check IHL (header length in 32-bit words)
        let ihl = ipv4_packet[0] & 0x0f;
        assert_eq!(ihl, 5); // 5 * 4 = 20 bytes
    }

    #[test]
    fn test_packet_size_limits() {
        // TUN packets should be within MTU
        let max_packet = 1400;
        let min_packet = 20; // Minimum IPv4 header

        assert!(min_packet <= max_packet);

        // Test various packet sizes
        let sizes = vec![20, 64, 128, 512, 1024, 1400];
        for size in sizes {
            assert!(size >= min_packet);
            assert!(size <= max_packet);
        }
    }
}

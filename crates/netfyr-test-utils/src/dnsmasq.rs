//! `DnsmasqGuard` — RAII wrapper for a dnsmasq DHCP server process.
//!
//! Used in integration tests to provide a real DHCP server inside an
//! unprivileged network namespace. `dnsmasq` must be installed on the host
//! (`apt-get install dnsmasq` / `dnf install dnsmasq`).

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

/// RAII guard that starts a dnsmasq process and kills it on drop.
pub struct DnsmasqGuard {
    child: Child,
    pid_file: PathBuf,
}

impl DnsmasqGuard {
    /// Start a dnsmasq DHCP server on `interface`.
    ///
    /// - `interface`: The network interface to listen on (e.g., `"veth-dhcp1"`).
    /// - `server_ip`: The IP address to listen on (must be assigned to `interface`).
    /// - `range_start`, `range_end`: DHCP address pool range.
    /// - `lease_time`: Lease time string (e.g., `"120s"`, `"1h"`).
    ///
    /// Waits 100 ms after spawning to allow dnsmasq to start listening.
    ///
    /// # Errors
    ///
    /// Returns an error if `dnsmasq` is not found or fails to start.
    pub fn start(
        interface: &str,
        server_ip: &str,
        range_start: &str,
        range_end: &str,
        lease_time: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Use a temp file for the PID file so it's cleaned up automatically.
        let pid_file = std::env::temp_dir().join(format!("dnsmasq-{}.pid", std::process::id()));

        let child = Command::new("dnsmasq")
            .args([
                "--no-daemon",
                "--bind-interfaces",
                &format!("--interface={interface}"),
                &format!("--listen-address={server_ip}"),
                &format!("--dhcp-range={range_start},{range_end},{lease_time}"),
                "--no-resolv",
                "--no-hosts",
                "--log-dhcp",
                &format!("--pid-file={}", pid_file.display()),
            ])
            // Suppress output unless test fails. Use `inherit` for debugging.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                format!(
                    "failed to spawn dnsmasq (is it installed?): {e}. \
                     Install with: apt-get install dnsmasq / dnf install dnsmasq"
                )
            })?;

        // Give dnsmasq time to bind and start listening.
        thread::sleep(Duration::from_millis(100));

        Ok(Self { child, pid_file })
    }
}

impl Drop for DnsmasqGuard {
    fn drop(&mut self) {
        // Try a graceful SIGTERM first.
        let _ = self.child.kill();
        let _ = self.child.wait();

        // Clean up the PID file.
        if self.pid_file.exists() {
            let _ = std::fs::remove_file(&self.pid_file);
        }
    }
}

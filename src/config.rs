use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

// The classic BPF fallback jump to the inbound port checks uses ports.len() + 6.
pub const MAX_INBOUND_PORTS: usize = u8::MAX as usize - 6;

/// CLI & environment configuration for `vless-audit`.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "vless-audit",
    version,
    about = "Passive AF_PACKET traffic, domain and inbound source auditor"
)]
pub struct AppConfig {
    /// Optional name shown in the audit dashboard.
    #[arg(long, env = "VLESS_AUDIT_INSTANCE_NAME")]
    pub instance_name: Option<String>,

    /// Network interface to capture on (e.g. eth0).
    #[arg(long, env = "VLESS_AUDIT_IFACE", default_value = "eth0")]
    pub iface: String,

    /// Explicit local IPv4 address of the interface; auto-detected if omitted.
    #[arg(long, env = "VLESS_AUDIT_LOCAL_IP")]
    pub local_ip: Option<Ipv4Addr>,

    /// Local TCP ports of direct VLESS inbounds to audit, comma-separated.
    #[arg(long = "inbound-port", env = "VLESS_AUDIT_INBOUND_PORT", value_delimiter = ',', value_parser = clap::value_parser!(u16).range(1..))]
    pub inbound_ports: Vec<u16>,

    /// Path to SQLite database file.
    #[arg(long, env = "VLESS_AUDIT_DB", default_value = "/var/lib/vless-audit/audit.db")]
    pub db_path: PathBuf,

    /// Optional local MMDB country database for source IP geolocation.
    #[arg(long, env = "VLESS_AUDIT_GEOIP_DB")]
    pub geoip_db: Option<PathBuf>,

    /// Local listen address for Web UI & API (keep on loopback behind Cloudflare Tunnel).
    #[arg(long, env = "VLESS_AUDIT_LISTEN", default_value = "127.0.0.1:18080")]
    pub listen: SocketAddr,

    /// Max prefix bytes buffered per flow while identifying TLS SNI / HTTP Host.
    #[arg(long, env = "VLESS_AUDIT_MAX_FLOW_PREFIX", default_value_t = 16 * 1024)]
    pub max_flow_prefix_bytes: usize,

    /// Max wait seconds for pending domain identification before falling back to unidentified.
    #[arg(long, env = "VLESS_AUDIT_PENDING_TIMEOUT_SECS", default_value_t = 3)]
    pub pending_timeout_secs: u64,

    /// Global byte budget across all concurrently pending flows.
    #[arg(long, env = "VLESS_AUDIT_MAX_GLOBAL_PENDING", default_value_t = 2 * 1024 * 1024)]
    pub max_global_pending_bytes: usize,

    /// Maximum concurrently tracked flows in memory.
    #[arg(long, env = "VLESS_AUDIT_MAX_ACTIVE_FLOWS", default_value_t = 20_000)]
    pub max_active_flows: usize,

    /// Idle timeout (seconds) for established flows without packets.
    #[arg(long, env = "VLESS_AUDIT_IDLE_TIMEOUT_SECS", default_value_t = 300)]
    pub idle_timeout_secs: u64,

    /// Interval (seconds) to flush aggregated deltas into SQLite.
    #[arg(long, env = "VLESS_AUDIT_FLUSH_INTERVAL_SECS", default_value_t = 5)]
    pub flush_interval_secs: u64,

    /// Socket SO_RCVBUF size in bytes (kernel doubles internally up to rmem_max).
    #[arg(long, env = "VLESS_AUDIT_RCVBUF_BYTES", default_value_t = 4 * 1024 * 1024)]
    pub rcvbuf_bytes: usize,

    /// Retention hours for full-domain drill-down rows in `recent_domains`.
    #[arg(long, env = "VLESS_AUDIT_RECENT_HOURS", default_value_t = 48)]
    pub recent_retention_hours: i64,

    /// Retention days for 5-minute aggregated rows in `traffic_buckets`.
    #[arg(long, env = "VLESS_AUDIT_BUCKET_DAYS", default_value_t = 90)]
    pub bucket_retention_days: i64,

    /// Optional: run in Web-only mode against existing SQLite DB (for local UI testing).
    #[arg(long, env = "VLESS_AUDIT_WEB_ONLY", default_value_t = false)]
    pub web_only: bool,
}

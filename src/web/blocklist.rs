use crate::collector::CollectorStatus;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

const REQUEST: &str = "/var/lib/vless-audit/blocklist-request";
const REPORT: &str = "/var/lib/vless-audit-blocklist/status.json";

#[derive(Debug, Deserialize)]
struct FirewallReport {
    interface: String,
    ports: Vec<u16>,
    processed: bool,
    active: bool,
    updated_at: Option<i64>,
    ipv4_ranges: u64,
    ipv6_ranges: u64,
    warning: Option<String>,
}

#[derive(Serialize, Default)]
pub struct BlocklistStatus {
    pub installed: bool,
    pub available: bool,
    pub enabled: bool,
    pub active: bool,
    pub pending: bool,
    pub updated_at: Option<i64>,
    pub ipv4_ranges: u64,
    pub ipv6_ranges: u64,
    pub warning: Option<String>,
}

pub fn status(collector: &CollectorStatus) -> BlocklistStatus {
    let report: FirewallReport = match File::open(REPORT)
        .ok()
        .and_then(|file| serde_json::from_reader(file.take(8192)).ok())
    {
        Some(report) => report,
        None => return BlocklistStatus::default(),
    };
    let mut request = String::new();
    if let Ok(file) = File::open(REQUEST) {
        let _ = file.take(8).read_to_string(&mut request);
    }
    let enabled = request == "on\n";
    let installed = !collector.web_only;
    BlocklistStatus {
        installed,
        available: installed
            && !collector.inbound_ports.is_empty()
            && report.interface == collector.iface
            && report.ports == collector.inbound_ports,
        enabled,
        active: report.active,
        pending: installed && enabled != report.processed,
        updated_at: report.updated_at,
        ipv4_ranges: report.ipv4_ranges,
        ipv6_ranges: report.ipv6_ranges,
        warning: report.warning,
    }
}

pub fn set_enabled(enabled: bool) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let target = Path::new(REQUEST);
    let temp = target.with_extension(format!(
        "{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    let result = file
        .write_all(if enabled { b"on\n" } else { b"off\n" })
        .and_then(|_| file.sync_all());
    drop(file);
    let result = result.and_then(|_| std::fs::rename(&temp, target));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

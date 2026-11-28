use crate::collector::{CollectorStatus, unix_now};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

const REQUEST: &str = "/var/lib/vless-audit/blocklist-request";
const REPORT: &str = "/var/lib/vless-audit-blocklist/status.json";
const DROP_HITS: &str = "/var/lib/vless-audit-blocklist/drop-hits.json";

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
    tracking_since: Option<i64>,
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
    #[serde(skip)]
    tracking_since: Option<i64>,
}

#[derive(Deserialize, Serialize)]
pub struct DropHits {
    tracking_since: i64,
    collected_at: i64,
    at_capacity: bool,
    rows: Vec<DropHit>,
}

#[derive(Deserialize, Serialize)]
struct DropHit {
    ip: IpAddr,
    last_seen: i64,
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
        tracking_since: report.tracking_since,
    }
}

fn snapshot_is_fresh(snapshot: &DropHits, tracking_since: Option<i64>, now: i64) -> bool {
    Some(snapshot.tracking_since) == tracking_since
        && (now - 90..=now).contains(&snapshot.collected_at)
}

fn retain_recent_hits(rows: &mut Vec<DropHit>, now: i64) {
    rows.retain(|hit| hit.last_seen >= now - 86400);
}

pub fn drop_hits(collector: &CollectorStatus) -> Option<DropHits> {
    let status = status(collector);
    if !status.installed || !status.active {
        return None;
    }
    let file = File::open(DROP_HITS).ok()?;
    let mut snapshot: DropHits =
        serde_json::from_reader(BufReader::new(file.take(1024 * 1024))).ok()?;
    let now = unix_now();
    if !snapshot_is_fresh(&snapshot, status.tracking_since, now) {
        return None;
    }
    retain_recent_hits(&mut snapshot.rows, now);
    Some(snapshot)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const NOW: i64 = 1_700_000_000;

    fn snapshot(tracking_since: i64, collected_at: i64, rows: Vec<DropHit>) -> DropHits {
        DropHits {
            tracking_since,
            collected_at,
            at_capacity: false,
            rows,
        }
    }

    fn hit(ip: &str, last_seen: i64) -> DropHit {
        DropHit {
            ip: ip.parse().expect("test address"),
            last_seen,
        }
    }

    #[test]
    fn snapshot_freshness_requires_matching_tracking_and_recent_collection() {
        let fresh = snapshot(7, NOW, vec![]);
        assert!(snapshot_is_fresh(&fresh, Some(7), NOW));
        assert!(snapshot_is_fresh(&fresh, Some(7), NOW + 90));
        assert!(!snapshot_is_fresh(&fresh, Some(7), NOW + 91));
        assert!(!snapshot_is_fresh(&fresh, None, NOW));
        assert!(!snapshot_is_fresh(&fresh, Some(8), NOW));
        assert!(!snapshot_is_fresh(
            &snapshot(7, NOW + 1, vec![]),
            Some(7),
            NOW
        ));
    }

    #[test]
    fn drop_hit_rows_keep_the_24_hour_boundary() {
        let mut rows = vec![
            hit("192.0.2.1", NOW - 86_400),
            hit("192.0.2.2", NOW - 86_401),
            hit("2001:db8::1", NOW),
        ];
        retain_recent_hits(&mut rows, NOW);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(rows[0].last_seen, NOW - 86_400);
        assert_eq!(rows[1].ip, IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn drop_hits_json_matches_the_python_writer_contract() {
        let json = br#"{"tracking_since":5,"collected_at":6,"at_capacity":true,"rows":[{"ip":"192.0.2.1","last_seen":7},{"ip":"2001:db8::1","last_seen":8}]}"#;
        let parsed: DropHits = serde_json::from_slice(json).expect("valid snapshot");
        assert_eq!(parsed.tracking_since, 5);
        assert_eq!(parsed.collected_at, 6);
        assert!(parsed.at_capacity);
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[1].ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.rows[1].last_seen, 8);
    }
}

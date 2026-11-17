pub mod cbpf;
pub mod domain;
#[cfg(target_os = "linux")]
pub mod linux_capture;
pub mod protocol;

use crate::collector::domain::{UNIDENTIFIED_DOMAIN, extract_root_domain};
use crate::collector::protocol::{
    ParseDecision, PrefixReassembler, ReasmStatus, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN,
    extract_domain_from_prefix, parse_ethernet_ipv4_tcp,
};
use crate::config::AppConfig;
use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const BUCKET_SECONDS: i64 = 300;
const CLOSING_GRACE_SECS: u64 = 5;

#[inline]
pub fn align_bucket(unix_ts: i64) -> i64 {
    unix_ts - unix_ts.rem_euclid(BUCKET_SECONDS)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub local_port: u16,
    pub remote_ip: u32,
    pub remote_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, Default)]
pub struct BucketAcc {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub conn_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecentKey {
    pub bucket_ts: i64,
    pub full_domain: String,
}

#[derive(Debug, Clone)]
pub struct RecentAcc {
    pub root_domain: String,
    pub ech_ext: bool,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub conn_count: u64,
    pub last_seen: i64,
}

#[derive(Debug, Default)]
pub struct FlushBatch {
    pub buckets: HashMap<(i64, String), BucketAcc>,
    pub recent: HashMap<RecentKey, RecentAcc>,
}

impl FlushBatch {
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty() && self.recent.is_empty()
    }

    pub fn merge_from(&mut self, other: FlushBatch) {
        for (k, v) in other.buckets {
            let entry = self.buckets.entry(k).or_default();
            entry.tx_bytes += v.tx_bytes;
            entry.rx_bytes += v.rx_bytes;
            entry.conn_count += v.conn_count;
        }
        for (k, v) in other.recent {
            self.recent
                .entry(k)
                .and_modify(|e| {
                    e.tx_bytes += v.tx_bytes;
                    e.rx_bytes += v.rx_bytes;
                    e.conn_count += v.conn_count;
                    e.ech_ext |= v.ech_ext;
                    if v.last_seen > e.last_seen {
                        e.last_seen = v.last_seen;
                    }
                })
                .or_insert(v);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CollectorStatus {
    pub running: bool,
    pub web_only: bool,
    pub iface: String,
    pub local_ip: String,
    pub started_at: i64,
    pub uptime_sec: u64,
    pub socket_packets_total: u64,
    pub socket_drops_total: u64,
    pub parsed_packets_total: u64,
    pub syn_flows_total: u64,
    pub resolved_flows_total: u64,
    pub unidentified_flows_total: u64,
    pub active_flows: usize,
    pub pending_flows: usize,
    pub pending_prefix_bytes: usize,
    pub preexisting_gap_packets: u64,
    pub preexisting_gap_bytes: u64,
    pub flow_limit_drops: u64,
    pub pending_budget_drops: u64,
    pub last_flush_at: Option<i64>,
    pub coverage_note: String,
}

impl CollectorStatus {
    pub fn new(cfg: &AppConfig, local_ip: Option<Ipv4Addr>, started_at: i64) -> Self {
        Self {
            running: !cfg.web_only,
            web_only: cfg.web_only,
            iface: cfg.iface.clone(),
            local_ip: local_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "未检测".to_string()),
            started_at,
            uptime_sec: 0,
            socket_packets_total: 0,
            socket_drops_total: 0,
            parsed_packets_total: 0,
            syn_flows_total: 0,
            resolved_flows_total: 0,
            unidentified_flows_total: 0,
            active_flows: 0,
            pending_flows: 0,
            pending_prefix_bytes: 0,
            preexisting_gap_packets: 0,
            preexisting_gap_bytes: 0,
            flow_limit_drops: 0,
            pending_budget_drops: 0,
            last_flush_at: None,
            coverage_note: "仅统计 IPv4 TCP 80/443 本机主动出站连接负载估算（不含 QUIC/UDP、非 80/443 端口及 IPv6）；ECH 扩展可能为 GREASE，外层域名仅供可见参考。".to_string(),
        }
    }
}

#[derive(Debug)]
enum FlowIdentity {
    Pending {
        reasm: PrefixReassembler,
        pending_buckets: Vec<(i64, u64, u64)>,
    },
    Resolved {
        full_domain: String,
        root_domain: String,
        ech_ext: bool,
    },
    Unidentified,
}

#[derive(Debug)]
struct FlowEntry {
    init_seq: u32,
    created_at: Instant,
    created_bucket_ts: i64,
    last_seen: Instant,
    closing_at: Option<Instant>,
    identity: FlowIdentity,
}

pub struct FlowTracker {
    local_ip: Ipv4Addr,
    max_flow_prefix_bytes: usize,
    pending_timeout: Duration,
    max_global_pending_bytes: usize,
    max_active_flows: usize,
    idle_timeout: Duration,

    flows: HashMap<FlowKey, FlowEntry>,
    pending_flows_count: usize,
    global_pending_bytes: usize,

    flush_batch: FlushBatch,

    // Cumulative metrics
    pub parsed_packets_total: u64,
    pub syn_flows_total: u64,
    pub resolved_flows_total: u64,
    pub unidentified_flows_total: u64,
    pub preexisting_gap_packets: u64,
    pub preexisting_gap_bytes: u64,
    pub flow_limit_drops: u64,
    pub pending_budget_drops: u64,
}

impl FlowTracker {
    pub fn new(local_ip: Ipv4Addr, cfg: &AppConfig) -> Self {
        Self {
            local_ip,
            max_flow_prefix_bytes: cfg.max_flow_prefix_bytes,
            pending_timeout: Duration::from_secs(cfg.pending_timeout_secs),
            max_global_pending_bytes: cfg.max_global_pending_bytes,
            max_active_flows: cfg.max_active_flows,
            idle_timeout: Duration::from_secs(cfg.idle_timeout_secs),
            flows: HashMap::with_capacity(1024),
            pending_flows_count: 0,
            global_pending_bytes: 0,
            flush_batch: FlushBatch::default(),
            parsed_packets_total: 0,
            syn_flows_total: 0,
            resolved_flows_total: 0,
            unidentified_flows_total: 0,
            preexisting_gap_packets: 0,
            preexisting_gap_bytes: 0,
            flow_limit_drops: 0,
            pending_budget_drops: 0,
        }
    }

    /// Processes a single captured Ethernet frame.
    pub fn handle_packet(
        &mut self,
        pkt: &[u8],
        direction: Direction,
        now: Instant,
        unix_ts: i64,
    ) {
        let Some(tcp) = parse_ethernet_ipv4_tcp(pkt) else {
            return;
        };

        // Defense-in-depth directional & port verification in userspace
        let key = match direction {
            Direction::Outbound => {
                if tcp.src_ip != self.local_ip
                    || tcp.dst_ip == self.local_ip
                    || (tcp.dst_port != 443 && tcp.dst_port != 80)
                {
                    return;
                }
                FlowKey {
                    local_port: tcp.src_port,
                    remote_ip: u32::from(tcp.dst_ip),
                    remote_port: tcp.dst_port,
                }
            }
            Direction::Inbound => {
                if tcp.dst_ip != self.local_ip
                    || tcp.src_ip == self.local_ip
                    || (tcp.src_port != 443 && tcp.src_port != 80)
                {
                    return;
                }
                FlowKey {
                    local_port: tcp.dst_port,
                    remote_ip: u32::from(tcp.src_ip),
                    remote_port: tcp.src_port,
                }
            }
        };

        self.parsed_packets_total += 1;
        let bucket_ts = align_bucket(unix_ts);
        let is_syn_only = (tcp.flags & TCP_SYN) != 0 && (tcp.flags & TCP_ACK) == 0;
        let is_fin_or_rst = (tcp.flags & (TCP_FIN | TCP_RST)) != 0;

        if direction == Direction::Outbound && is_syn_only {
            self.handle_outbound_syn(key, tcp.seq, tcp.payload_len, now, bucket_ts);
            return;
        }

        let Some(flow) = self.flows.get_mut(&key) else {
            // Connection opened before service started (or after flow eviction): track in gap counter.
            self.preexisting_gap_packets += 1;
            self.preexisting_gap_bytes += tcp.payload_len;
            return;
        };

        flow.last_seen = now;
        if is_fin_or_rst && flow.closing_at.is_none() {
            flow.closing_at = Some(now);
        }

        let (tx_add, rx_add) = match direction {
            Direction::Outbound => (tcp.payload_len, 0),
            Direction::Inbound => (0, tcp.payload_len),
        };

        // Check whether this packet updates pending reassembly or bills directly
        let mut finalize_decision: Option<ParseDecision> = None;

        match &mut flow.identity {
            FlowIdentity::Pending {
                reasm,
                pending_buckets,
            } => {
                if tx_add > 0 || rx_add > 0 {
                    add_pending_bucket(pending_buckets, bucket_ts, tx_add, rx_add);
                }

                if direction == Direction::Outbound && !tcp.captured_payload.is_empty() {
                    let prev_global = self.global_pending_bytes;
                    match reasm.push(tcp.seq, tcp.captured_payload) {
                        Ok(delta_bytes) => {
                            let new_global = (prev_global as isize + delta_bytes).max(0) as usize;
                            self.global_pending_bytes = new_global;
                            if new_global > self.max_global_pending_bytes {
                                self.pending_budget_drops += 1;
                                finalize_decision = Some(ParseDecision::Unrecognized);
                            } else {
                                let decision = extract_domain_from_prefix(reasm.contiguous());
                                match decision {
                                    ParseDecision::Resolved { .. } | ParseDecision::Unrecognized => {
                                        finalize_decision = Some(decision);
                                    }
                                    ParseDecision::NeedMoreData => {}
                                }
                            }
                        }
                        Err(ReasmStatus::Overflow) => {
                            finalize_decision = Some(ParseDecision::Unrecognized);
                        }
                    }
                }

                if finalize_decision.is_none() && is_fin_or_rst {
                    finalize_decision = Some(ParseDecision::Unrecognized);
                }
            }
            FlowIdentity::Resolved {
                full_domain,
                root_domain,
                ech_ext,
            } => {
                if tx_add > 0 || rx_add > 0 {
                    Self::record_delta(
                        &mut self.flush_batch,
                        bucket_ts,
                        root_domain,
                        Some((full_domain.as_str(), *ech_ext, unix_ts)),
                        tx_add,
                        rx_add,
                        0,
                    );
                }
            }
            FlowIdentity::Unidentified => {
                if tx_add > 0 || rx_add > 0 {
                    Self::record_delta(
                        &mut self.flush_batch,
                        bucket_ts,
                        UNIDENTIFIED_DOMAIN,
                        None,
                        tx_add,
                        rx_add,
                        0,
                    );
                }
            }
        }

        if let Some(decision) = finalize_decision {
            self.finalize_pending_flow(key, decision, unix_ts);
        }
    }

    fn handle_outbound_syn(
        &mut self,
        key: FlowKey,
        syn_seq: u32,
        payload_len: u64,
        now: Instant,
        bucket_ts: i64,
    ) {
        if let Some(existing) = self.flows.get_mut(&key) {
            // Retransmitted SYN for an active flow with same ISN -> continue existing flow
            if existing.init_seq == syn_seq && existing.closing_at.is_none() {
                existing.last_seen = now;
                return;
            }
            // Otherwise a 5-tuple was reused: finalize & replace old entry immediately
            self.remove_flow(key);
        }

        if self.flows.len() >= self.max_active_flows {
            self.flow_limit_drops += 1;
            return;
        }

        self.syn_flows_total += 1;

        let over_pending_budget = self.global_pending_bytes >= self.max_global_pending_bytes;
        let identity = if over_pending_budget {
            self.pending_budget_drops += 1;
            self.unidentified_flows_total += 1;
            Self::record_delta(
                &mut self.flush_batch,
                bucket_ts,
                UNIDENTIFIED_DOMAIN,
                None,
                payload_len,
                0,
                1,
            );
            FlowIdentity::Unidentified
        } else {
            self.pending_flows_count += 1;
            let mut pending_buckets = Vec::new();
            if payload_len > 0 {
                pending_buckets.push((bucket_ts, payload_len, 0));
            }
            FlowIdentity::Pending {
                reasm: PrefixReassembler::new(syn_seq, self.max_flow_prefix_bytes),
                pending_buckets,
            }
        };

        self.flows.insert(
            key,
            FlowEntry {
                init_seq: syn_seq,
                created_at: now,
                created_bucket_ts: bucket_ts,
                last_seen: now,
                closing_at: None,
                identity,
            },
        );
    }

    fn finalize_pending_flow(&mut self, key: FlowKey, decision: ParseDecision, unix_ts: i64) {
        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };

        let old_identity = std::mem::replace(&mut flow.identity, FlowIdentity::Unidentified);
        let FlowIdentity::Pending {
            reasm,
            pending_buckets,
        } = old_identity
        else {
            flow.identity = old_identity;
            return;
        };

        self.pending_flows_count = self.pending_flows_count.saturating_sub(1);
        self.global_pending_bytes = self
            .global_pending_bytes
            .saturating_sub(reasm.buffered_bytes());

        let created_bucket = flow.created_bucket_ts;

        match decision {
            ParseDecision::Resolved { domain, ech_ext } => {
                let root_domain = extract_root_domain(&domain);
                self.resolved_flows_total += 1;
                Self::record_delta(
                    &mut self.flush_batch,
                    created_bucket,
                    &root_domain,
                    Some((&domain, ech_ext, unix_ts)),
                    0,
                    0,
                    1,
                );
                for (bts, tx, rx) in pending_buckets {
                    Self::record_delta(
                        &mut self.flush_batch,
                        bts,
                        &root_domain,
                        Some((&domain, ech_ext, unix_ts)),
                        tx,
                        rx,
                        0,
                    );
                }
                flow.identity = FlowIdentity::Resolved {
                    full_domain: domain,
                    root_domain,
                    ech_ext,
                };
            }
            ParseDecision::Unrecognized | ParseDecision::NeedMoreData => {
                self.unidentified_flows_total += 1;
                Self::record_delta(
                    &mut self.flush_batch,
                    created_bucket,
                    UNIDENTIFIED_DOMAIN,
                    None,
                    0,
                    0,
                    1,
                );
                for (bts, tx, rx) in pending_buckets {
                    Self::record_delta(
                        &mut self.flush_batch,
                        bts,
                        UNIDENTIFIED_DOMAIN,
                        None,
                        tx,
                        rx,
                        0,
                    );
                }
                flow.identity = FlowIdentity::Unidentified;
            }
        }
    }

    fn remove_flow(&mut self, key: FlowKey) {
        if let Some(entry) = self.flows.remove(&key) {
            if let FlowIdentity::Pending {
                reasm,
                pending_buckets,
            } = entry.identity
            {
                self.pending_flows_count = self.pending_flows_count.saturating_sub(1);
                self.global_pending_bytes = self
                    .global_pending_bytes
                    .saturating_sub(reasm.buffered_bytes());
                self.unidentified_flows_total += 1;
                Self::record_delta(
                    &mut self.flush_batch,
                    entry.created_bucket_ts,
                    UNIDENTIFIED_DOMAIN,
                    None,
                    0,
                    0,
                    1,
                );
                for (bts, tx, rx) in pending_buckets {
                    Self::record_delta(
                        &mut self.flush_batch,
                        bts,
                        UNIDENTIFIED_DOMAIN,
                        None,
                        tx,
                        rx,
                        0,
                    );
                }
            }
        }
    }

    /// Expires pending domain timers (3s) and closed/idle flows.
    pub fn expire(&mut self, now: Instant, unix_ts: i64) {
        let mut timed_out_pending = Vec::new();
        let mut to_remove = Vec::new();
        let closing_grace = Duration::from_secs(CLOSING_GRACE_SECS);

        for (&key, flow) in &self.flows {
            if matches!(flow.identity, FlowIdentity::Pending { .. })
                && now.duration_since(flow.created_at) >= self.pending_timeout
            {
                timed_out_pending.push(key);
            }
            if let Some(closed_at) = flow.closing_at {
                if now.duration_since(closed_at) >= closing_grace {
                    to_remove.push(key);
                    continue;
                }
            }
            if now.duration_since(flow.last_seen) >= self.idle_timeout {
                to_remove.push(key);
            }
        }

        for key in timed_out_pending {
            self.finalize_pending_flow(key, ParseDecision::Unrecognized, unix_ts);
        }
        for key in to_remove {
            self.remove_flow(key);
        }
    }

    pub fn take_flush_batch(&mut self) -> FlushBatch {
        std::mem::take(&mut self.flush_batch)
    }

    pub fn active_flows(&self) -> usize {
        self.flows.len()
    }

    pub fn pending_flows(&self) -> usize {
        self.pending_flows_count
    }

    pub fn pending_prefix_bytes(&self) -> usize {
        self.global_pending_bytes
    }

    fn record_delta(
        batch: &mut FlushBatch,
        bucket_ts: i64,
        root_domain: &str,
        full_info: Option<(&str, bool, i64)>,
        tx_bytes: u64,
        rx_bytes: u64,
        conn_count: u64,
    ) {
        let entry = batch
            .buckets
            .entry((bucket_ts, root_domain.to_string()))
            .or_default();
        entry.tx_bytes += tx_bytes;
        entry.rx_bytes += rx_bytes;
        entry.conn_count += conn_count;

        if let Some((full_domain, ech_ext, last_seen)) = full_info {
            let key = RecentKey {
                bucket_ts,
                full_domain: full_domain.to_string(),
            };
            batch
                .recent
                .entry(key)
                .and_modify(|e| {
                    e.tx_bytes += tx_bytes;
                    e.rx_bytes += rx_bytes;
                    e.conn_count += conn_count;
                    e.ech_ext |= ech_ext;
                    if last_seen > e.last_seen {
                        e.last_seen = last_seen;
                    }
                })
                .or_insert_with(|| RecentAcc {
                    root_domain: root_domain.to_string(),
                    ech_ext,
                    tx_bytes,
                    rx_bytes,
                    conn_count,
                    last_seen,
                });
        }
    }
}

fn add_pending_bucket(vec: &mut Vec<(i64, u64, u64)>, bucket_ts: i64, tx: u64, rx: u64) {
    if let Some(item) = vec.iter_mut().find(|(ts, _, _)| *ts == bucket_ts) {
        item.1 += tx;
        item.2 += rx;
    } else {
        vec.push((bucket_ts, tx, rx));
    }
}

#[inline]
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
pub fn start_capture_thread(
    cfg: AppConfig,
    local_ip: Ipv4Addr,
    tx_flush: std::sync::mpsc::SyncSender<FlushBatch>,
    status: Arc<RwLock<CollectorStatus>>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let fd = linux_capture::open_capture_socket(&cfg.iface, local_ip, cfg.rcvbuf_bytes)?;
    Ok(std::thread::Builder::new()
        .name("af-packet-capture".to_string())
        .spawn(move || {
            linux_capture::run_capture_loop(fd, cfg, local_ip, tx_flush, status, shutdown);
        })?)
}

#[cfg(not(target_os = "linux"))]
pub fn start_capture_thread(
    _cfg: AppConfig,
    _local_ip: Ipv4Addr,
    _tx_flush: std::sync::mpsc::SyncSender<FlushBatch>,
    _status: Arc<RwLock<CollectorStatus>>,
    _shutdown: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "AF_PACKET capture is only supported on Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::protocol::{TCP_ACK, TCP_FIN, TCP_SYN};

    fn make_tcp_pkt(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        flags: u8,
        tot_len_override: Option<u16>,
        payload: &[u8],
    ) -> Vec<u8> {
        let tot_len = tot_len_override.unwrap_or((40 + payload.len()) as u16);
        let mut pkt = vec![0u8; 14 + 40 + payload.len()];
        pkt[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        pkt[14] = 0x45;
        pkt[16..18].copy_from_slice(&tot_len.to_be_bytes());
        pkt[23] = 6;
        pkt[26..30].copy_from_slice(&src_ip.octets());
        pkt[30..34].copy_from_slice(&dst_ip.octets());
        pkt[34..36].copy_from_slice(&src_port.to_be_bytes());
        pkt[36..38].copy_from_slice(&dst_port.to_be_bytes());
        pkt[38..42].copy_from_slice(&seq.to_be_bytes());
        pkt[46] = 0x50;
        pkt[47] = flags;
        if !payload.is_empty() {
            pkt[54..].copy_from_slice(payload);
        }
        pkt
    }

    fn test_cfg() -> AppConfig {
        AppConfig {
            iface: "eth0".into(),
            local_ip: Some(Ipv4Addr::new(10, 1, 1, 4)),
            db_path: ":memory:".into(),
            listen: "127.0.0.1:18080".parse().unwrap(),
            max_flow_prefix_bytes: 16 * 1024,
            pending_timeout_secs: 3,
            max_global_pending_bytes: 2 * 1024 * 1024,
            max_active_flows: 1000,
            idle_timeout_secs: 300,
            flush_interval_secs: 5,
            rcvbuf_bytes: 1024 * 1024,
            recent_retention_hours: 48,
            bucket_retention_days: 90,
            web_only: false,
        }
    }

    #[test]
    fn flow_tracker_bills_split_http_and_isolates_port_reuse() {
        let local = Ipv4Addr::new(10, 1, 1, 4);
        let remote = Ipv4Addr::new(93, 184, 216, 34);
        let cfg = test_cfg();
        let mut tracker = FlowTracker::new(local, &cfg);
        let t0 = Instant::now();
        let unix0 = 1_795_000_200; // aligns to 1_795_000_200 % 300 == 200 -> 1_795_000_000

        // 1. Outbound SYN
        let syn = make_tcp_pkt(local, remote, 50001, 80, 1000, TCP_SYN, None, &[]);
        tracker.handle_packet(&syn, Direction::Outbound, t0, unix0);
        // Duplicate SYN retransmission -> does not reset
        tracker.handle_packet(&syn, Direction::Outbound, t0, unix0);
        assert_eq!(tracker.syn_flows_total, 1);

        // 2. First HTTP fragment (before Host finishes)
        let part1 = b"GET /a HTTP/1.1\r\n";
        let p1 = make_tcp_pkt(local, remote, 50001, 80, 1001, TCP_ACK, None, part1);
        tracker.handle_packet(&p1, Direction::Outbound, t0, unix0);
        assert_eq!(tracker.pending_flows(), 1);

        // 3. Second HTTP fragment completes Host
        let part2 = b"Host: Sub.Example.COM\r\n\r\n";
        let p2 = make_tcp_pkt(
            local,
            remote,
            50001,
            80,
            1001 + part1.len() as u32,
            TCP_ACK,
            None,
            part2,
        );
        tracker.handle_packet(&p2, Direction::Outbound, t0, unix0);
        assert_eq!(tracker.pending_flows(), 0);
        assert_eq!(tracker.resolved_flows_total, 1);

        // 4. Inbound truncated 160B packet reporting full 2040B IP packet (2000B TCP payload)
        let mut rx = make_tcp_pkt(remote, local, 80, 50001, 5000, TCP_ACK, Some(2040), &[0u8; 106]);
        rx.truncate(160);
        tracker.handle_packet(&rx, Direction::Inbound, t0, unix0);

        // 5. FIN closes flow; then reuse exact same port for a NEW SYN -> must NOT inherit example.com
        let fin = make_tcp_pkt(local, remote, 50001, 80, 1100, TCP_FIN | TCP_ACK, None, &[]);
        tracker.handle_packet(&fin, Direction::Outbound, t0, unix0);

        let syn2 = make_tcp_pkt(local, remote, 50001, 80, 9000, TCP_SYN, None, &[]);
        tracker.handle_packet(&syn2, Direction::Outbound, t0 + Duration::from_secs(1), unix0 + 1);
        assert_eq!(tracker.pending_flows(), 1);

        // Expire pending timeout (3s) -> falls back to 未识别
        tracker.expire(t0 + Duration::from_secs(5), unix0 + 5);
        assert_eq!(tracker.pending_flows(), 0);

        let batch = tracker.take_flush_batch();
        let bts = align_bucket(unix0);
        let ex = batch.buckets.get(&(bts, "example.com".to_string())).unwrap();
        assert_eq!(ex.tx_bytes, (part1.len() + part2.len()) as u64);
        assert_eq!(ex.rx_bytes, 2000);
        assert_eq!(ex.conn_count, 1);

        let unid = batch
            .buckets
            .get(&(bts, UNIDENTIFIED_DOMAIN.to_string()))
            .unwrap();
        assert_eq!(unid.conn_count, 1);
    }

    #[test]
    fn preexisting_connection_counts_in_gap_only() {
        let local = Ipv4Addr::new(10, 1, 1, 4);
        let remote = Ipv4Addr::new(1, 1, 1, 1);
        let cfg = test_cfg();
        let mut tracker = FlowTracker::new(local, &cfg);

        let rx = make_tcp_pkt(remote, local, 443, 55555, 1, TCP_ACK, Some(540), &[0u8; 60]);
        tracker.handle_packet(&rx, Direction::Inbound, Instant::now(), 1_795_000_200);
        assert_eq!(tracker.preexisting_gap_packets, 1);
        assert_eq!(tracker.preexisting_gap_bytes, 500);
        assert!(tracker.take_flush_batch().is_empty());
    }
}

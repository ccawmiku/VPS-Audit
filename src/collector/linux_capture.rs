use crate::collector::cbpf::{attach_filter, build_ipv4_tcp_80_443_filter};
use crate::collector::{CollectorStatus, Direction, FlowTracker, FlushBatch, unix_now};
use crate::config::AppConfig;
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[repr(C)]
#[derive(Default)]
struct TpacketStats {
    tp_packets: u32,
    tp_drops: u32,
}

/// Detects the primary IPv4 address assigned to `iface` via `getifaddrs`.
pub fn detect_iface_ipv4(iface: &str) -> std::io::Result<Ipv4Addr> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    let ret = unsafe { libc::getifaddrs(&mut ifap) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut found: Option<Ipv4Addr> = None;
    let mut cur = ifap;
    while !cur.is_null() {
        unsafe {
            let entry = &*cur;
            if !entry.ifa_name.is_null() && !entry.ifa_addr.is_null() {
                let name = std::ffi::CStr::from_ptr(entry.ifa_name).to_string_lossy();
                if name == iface && (*entry.ifa_addr).sa_family as i32 == libc::AF_INET {
                    let sin = &*(entry.ifa_addr as *const libc::sockaddr_in);
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    if !ip.is_loopback() {
                        found = Some(ip);
                        break;
                    }
                }
            }
            cur = entry.ifa_next;
        }
    }

    unsafe { libc::freeifaddrs(ifap) };

    found.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("no non-loopback IPv4 address found on interface {iface}"),
        )
    })
}

pub fn open_capture_socket(
    iface: &str,
    local_ip: Ipv4Addr,
    rcvbuf_bytes: usize,
) -> std::io::Result<RawFd> {
    let c_iface = CString::new(iface)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid iface name"))?;
    let ifindex = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
    if ifindex == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("interface {iface} not found: {}", std::io::Error::last_os_error()),
        ));
    }

    let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Set receive buffer size (best-effort if capped by rmem_max)
    let rcvbuf = rcvbuf_bytes.min(i32::MAX as usize) as libc::c_int;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // Attach cBPF before binding so unfiltered frames never enter the socket queue
    let filter = build_ipv4_tcp_80_443_filter(local_ip);
    if let Err(e) = attach_filter(fd, &filter) {
        unsafe { libc::close(fd) };
        return Err(e);
    }

    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    sll.sll_ifindex = ifindex as libc::c_int;

    let bind_ret = unsafe {
        libc::bind(
            fd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if bind_ret != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // Read once to clear any initial counter noise
    let _ = read_packet_statistics(fd);

    Ok(fd)
}

fn read_packet_statistics(fd: RawFd) -> Option<(u64, u64)> {
    let mut stats = TpacketStats::default();
    let mut len = std::mem::size_of::<TpacketStats>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_STATISTICS,
            &mut stats as *mut TpacketStats as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 {
        Some((stats.tp_packets as u64, stats.tp_drops as u64))
    } else {
        None
    }
}

pub fn run_capture_loop(
    fd: RawFd,
    cfg: AppConfig,
    local_ip: Ipv4Addr,
    tx_flush: SyncSender<FlushBatch>,
    status: Arc<RwLock<CollectorStatus>>,
    shutdown: Arc<AtomicBool>,
) {
    let mut tracker = FlowTracker::new(local_ip, &cfg);
    let mut buf = vec![0u8; 20_480];
    let started_instant = Instant::now();
    let mut last_tick = Instant::now();
    let mut last_flush = Instant::now();
    let flush_interval = Duration::from_secs(cfg.flush_interval_secs.max(1));
    let mut sock_packets_total: u64 = 0;
    let mut sock_drops_total: u64 = 0;
    let mut pending_carry = FlushBatch::default();

    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    while !shutdown.load(Ordering::Relaxed) {
        let pret = unsafe { libc::poll(&mut pfd, 1, 500) };
        if pret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            tracing::error!(error = %err, "AF_PACKET poll error");
            break;
        }

        if pret > 0 && (pfd.revents & libc::POLLIN) != 0 {
            // Drain a small burst per poll wakeup before checking timers
            for _ in 0..256 {
                let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
                let mut addr_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
                let n = unsafe {
                    libc::recvfrom(
                        fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        libc::MSG_DONTWAIT,
                        &mut sll as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                        &mut addr_len,
                    )
                };
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::Interrupted
                    {
                        break;
                    }
                    tracing::error!(error = %err, "AF_PACKET recvfrom error");
                    break;
                }
                if n == 0 {
                    break;
                }

                let direction = if sll.sll_pkttype == libc::PACKET_OUTGOING as u8 {
                    Direction::Outbound
                } else {
                    Direction::Inbound
                };
                tracker.handle_packet(&buf[..n as usize], direction, Instant::now(), unix_now());
            }
        }

        let now = Instant::now();
        if now.duration_since(last_tick) >= Duration::from_secs(1) {
            last_tick = now;
            let uts = unix_now();
            tracker.expire(now, uts);
            if let Some((pkts, drops)) = read_packet_statistics(fd) {
                sock_packets_total += pkts;
                sock_drops_total += drops;
            }

            if let Ok(mut guard) = status.write() {
                guard.uptime_sec = now.duration_since(started_instant).as_secs();
                guard.socket_packets_total = sock_packets_total;
                guard.socket_drops_total = sock_drops_total;
                guard.parsed_packets_total = tracker.parsed_packets_total;
                guard.syn_flows_total = tracker.syn_flows_total;
                guard.resolved_flows_total = tracker.resolved_flows_total;
                guard.unidentified_flows_total = tracker.unidentified_flows_total;
                guard.active_flows = tracker.active_flows();
                guard.pending_flows = tracker.pending_flows();
                guard.pending_prefix_bytes = tracker.pending_prefix_bytes();
                guard.preexisting_gap_packets = tracker.preexisting_gap_packets;
                guard.preexisting_gap_bytes = tracker.preexisting_gap_bytes;
                guard.flow_limit_drops = tracker.flow_limit_drops;
                guard.pending_budget_drops = tracker.pending_budget_drops;
            }
        }

        if now.duration_since(last_flush) >= flush_interval {
            last_flush = now;
            let batch = tracker.take_flush_batch();
            pending_carry.merge_from(batch);
            if !pending_carry.is_empty() {
                let to_send = std::mem::take(&mut pending_carry);
                match tx_flush.try_send(to_send) {
                    Ok(()) => {
                        if let Ok(mut guard) = status.write() {
                            guard.last_flush_at = Some(unix_now());
                        }
                    }
                    Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                        pending_carry.merge_from(returned);
                        tracing::warn!("SQLite flush channel full; carrying batch in memory");
                    }
                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                        break;
                    }
                }
            }
        }
    }

    // Final flush on shutdown: expire pending flows immediately so buffered bytes are not lost
    let far_future = Instant::now() + Duration::from_secs(cfg.pending_timeout_secs + 10);
    tracker.expire(far_future, unix_now());
    pending_carry.merge_from(tracker.take_flush_batch());
    if !pending_carry.is_empty() {
        let _ = tx_flush.send(pending_carry);
    }

    unsafe { libc::close(fd) };
    tracing::info!("AF_PACKET capture thread exited cleanly");
}

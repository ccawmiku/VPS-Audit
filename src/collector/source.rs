use super::protocol::{ParsedTcpPacket, TCP_ACK, TCP_RST, TCP_SYN};
use super::{Direction, FlushBatch, align_bucket};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const HANDSHAKE_WINDOW: Duration = Duration::from_secs(30);
const MAX_HANDSHAKES: usize = 8_192;

#[derive(Debug, Clone, Copy)]
struct Handshake {
    client_seq: u32,
    server_ack: u32,
    seen_at: Instant,
    counted: bool,
}

pub(super) struct SourceTracker {
    ports: Vec<u16>,
    handshakes: HashMap<(u16, Ipv4Addr, u16), Handshake>,
    pub(super) limit_drops: u64,
}

impl SourceTracker {
    pub(super) fn new(ports: Vec<u16>) -> Self {
        Self {
            ports,
            handshakes: HashMap::new(),
            limit_drops: 0,
        }
    }

    pub(super) fn observe(
        &mut self,
        tcp: &ParsedTcpPacket<'_>,
        direction: Direction,
        local_ip: Ipv4Addr,
        now: Instant,
        unix_ts: i64,
        batch: &mut FlushBatch,
    ) {
        let (port, peer, peer_port) = match direction {
            Direction::Outbound if tcp.src_ip == local_ip => {
                (tcp.src_port, tcp.dst_ip, tcp.dst_port)
            }
            Direction::Inbound if tcp.dst_ip == local_ip => {
                (tcp.dst_port, tcp.src_ip, tcp.src_port)
            }
            _ => return,
        };
        if peer == local_ip || self.ports.binary_search(&port).is_err() {
            return;
        }
        let source_key = (align_bucket(unix_ts), port, peer);
        if tcp.payload_len > 0 {
            let row = batch.sources.entry(source_key).or_default();
            match direction {
                Direction::Outbound => row.download_bytes += tcp.payload_len,
                Direction::Inbound => row.upload_bytes += tcp.payload_len,
            }
            row.last_seen = row.last_seen.max(unix_ts);
        }

        let flags = tcp.flags & (TCP_SYN | TCP_ACK | TCP_RST);
        match direction {
            Direction::Outbound if flags == (TCP_SYN | TCP_ACK) => {
                let key = (port, peer, peer_port);
                // The server already acknowledged the client's SYN, including TCP Fast Open data.
                let server_ack = tcp.seq.wrapping_add(1).wrapping_add(tcp.payload_len as u32);
                if let Some(previous) = self.handshakes.get(&key) {
                    if previous.client_seq == tcp.ack
                        && previous.server_ack == server_ack
                        && now.duration_since(previous.seen_at) < HANDSHAKE_WINDOW
                    {
                        return;
                    }
                } else if self.handshakes.len() >= MAX_HANDSHAKES {
                    self.limit_drops += 1;
                    return;
                }
                self.handshakes.insert(
                    key,
                    Handshake {
                        client_seq: tcp.ack,
                        server_ack,
                        seen_at: now,
                        counted: false,
                    },
                );
            }
            Direction::Inbound if flags == TCP_ACK => {
                let key = (port, peer, peer_port);
                let Some(handshake) = self.handshakes.get_mut(&key) else {
                    return;
                };
                if handshake.counted
                    || now.duration_since(handshake.seen_at) >= HANDSHAKE_WINDOW
                    || tcp.seq != handshake.client_seq
                    || tcp.ack != handshake.server_ack
                {
                    return;
                }
                handshake.counted = true;
                let row = batch.sources.entry(source_key).or_default();
                row.conn_count += 1;
                row.last_seen = row.last_seen.max(unix_ts);
            }
            _ => {}
        }
    }

    pub(super) fn expire(&mut self, now: Instant) {
        self.handshakes
            .retain(|_, handshake| now.duration_since(handshake.seen_at) < HANDSHAKE_WINDOW);
    }
}

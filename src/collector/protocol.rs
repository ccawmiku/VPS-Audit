use crate::collector::domain::normalize_hostname;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy)]
pub struct ParsedTcpPacket<'a> {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload_len: u64,
    pub captured_payload: &'a [u8],
}

/// Parses an Ethernet + IPv4 + TCP packet.
/// Uses IPv4 `tot_len` (not captured slice len) to compute `payload_len`,
/// which preserves accuracy when GRO/LRO aggregates >1500 B packets and when RX is truncated to 160 B.
pub fn parse_ethernet_ipv4_tcp(pkt: &[u8]) -> Option<ParsedTcpPacket<'_>> {
    if pkt.len() < 14 + 20 + 20 {
        return None;
    }
    let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
    if ethertype != 0x0800 {
        return None;
    }

    let ip = &pkt[14..];
    let version = ip[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl + 20 {
        return None;
    }

    let tot_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let frag_off = u16::from_be_bytes([ip[6], ip[7]]);
    if (frag_off & 0x3fff) != 0 {
        return None;
    }
    if ip[9] != 6 {
        return None;
    }

    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);

    let tcp = &ip[ihl..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let doff = ((tcp[12] >> 4) as usize) * 4;
    let flags = tcp[13];

    if doff < 20 || tcp.len() < doff {
        return None;
    }
    if tot_len < ihl + doff {
        return None;
    }

    let payload_len = (tot_len - ihl - doff) as u64;
    let payload_start = 14 + ihl + doff;
    let ip_end = 14 + tot_len;
    let avail_end = pkt.len().min(ip_end);
    let captured_payload = if payload_start < avail_end {
        &pkt[payload_start..avail_end]
    } else {
        &[]
    };

    Some(ParsedTcpPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        payload_len,
        captured_payload,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseDecision {
    Resolved { domain: String, ech_ext: bool },
    NeedMoreData,
    Unrecognized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasmStatus {
    Overflow,
}

/// Bounded TCP stream prefix reassembler for outbound SNI / HTTP Host extraction.
#[derive(Debug)]
pub struct PrefixReassembler {
    base_seq: u32,
    max_bytes: usize,
    contiguous: Vec<u8>,
    ooo: BTreeMap<usize, Vec<u8>>,
    ooo_bytes: usize,
}

impl PrefixReassembler {
    pub fn new(init_syn_seq: u32, max_bytes: usize) -> Self {
        Self {
            base_seq: init_syn_seq.wrapping_add(1),
            max_bytes,
            contiguous: Vec::new(),
            ooo: BTreeMap::new(),
            ooo_bytes: 0,
        }
    }

    pub fn buffered_bytes(&self) -> usize {
        self.contiguous.len() + self.ooo_bytes
    }

    pub fn contiguous(&self) -> &[u8] {
        &self.contiguous
    }

    /// Inserts a TCP payload slice at `seq` and returns delta in total buffered bytes (`new - old`).
    pub fn push(&mut self, seq: u32, data: &[u8]) -> Result<isize, ReasmStatus> {
        if data.is_empty() {
            return Ok(0);
        }

        let old_total = self.buffered_bytes() as isize;
        let rel = seq.wrapping_sub(self.base_seq) as i32;

        let (start, slice) = if rel < 0 {
            let skip = rel.unsigned_abs() as usize;
            if skip >= data.len() {
                return Ok(0);
            }
            (0usize, &data[skip..])
        } else {
            (rel as usize, data)
        };

        if start >= self.max_bytes {
            return Err(ReasmStatus::Overflow);
        }

        let end = (start + slice.len()).min(self.max_bytes);
        let bounded = &slice[..end - start];

        if start <= self.contiguous.len() {
            let overlap = self.contiguous.len() - start;
            if bounded.len() > overlap {
                self.contiguous.extend_from_slice(&bounded[overlap..]);
                self.drain_ooo();
            }
        } else {
            // Limit out-of-order segments per flow to avoid degenerate memory churn.
            if self.ooo.len() >= 16 {
                return Err(ReasmStatus::Overflow);
            }
            match self.ooo.get_mut(&start) {
                Some(existing) if existing.len() >= bounded.len() => {}
                Some(existing) => {
                    let diff = bounded.len() - existing.len();
                    *existing = bounded.to_vec();
                    self.ooo_bytes += diff;
                }
                None => {
                    self.ooo_bytes += bounded.len();
                    self.ooo.insert(start, bounded.to_vec());
                }
            }
        }

        Ok(self.buffered_bytes() as isize - old_total)
    }

    fn drain_ooo(&mut self) {
        while let Some((&seg_start, _)) = self.ooo.iter().next() {
            if seg_start > self.contiguous.len() {
                break;
            }
            let seg = self.ooo.remove(&seg_start).unwrap();
            self.ooo_bytes = self.ooo_bytes.saturating_sub(seg.len());
            let overlap = self.contiguous.len() - seg_start;
            if seg.len() > overlap {
                self.contiguous.extend_from_slice(&seg[overlap..]);
            }
        }
    }
}

/// Extracts TLS SNI or HTTP Host from a contiguous client-to-server TCP payload prefix.
pub fn extract_domain_from_prefix(buf: &[u8]) -> ParseDecision {
    if buf.is_empty() {
        return ParseDecision::NeedMoreData;
    }

    if buf[0] == 0x16 {
        return parse_tls_client_hello(buf);
    }

    parse_http_host(buf)
}

fn parse_tls_client_hello(buf: &[u8]) -> ParseDecision {
    let mut pos = 0usize;
    let mut handshake = Vec::new();
    let mut expected_hs_len: Option<usize> = None;

    // Reassemble handshake bytes across one or more consecutive TLS 0x16 records.
    while pos < buf.len() {
        if buf.len() - pos < 5 {
            return ParseDecision::NeedMoreData;
        }
        let content_type = buf[pos];
        let major_ver = buf[pos + 1];
        let rec_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        if content_type != 0x16 || major_ver != 0x03 || rec_len == 0 || rec_len > 18_432 {
            return ParseDecision::Unrecognized;
        }

        let rec_start = pos + 5;
        let rec_end = rec_start + rec_len;
        handshake.extend_from_slice(&buf[rec_start..rec_end.min(buf.len())]);
        pos = rec_end;

        if expected_hs_len.is_none() && handshake.len() >= 4 {
            if handshake[0] != 0x01 {
                return ParseDecision::Unrecognized;
            }
            let hs_len = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | (handshake[3] as usize);
            expected_hs_len = Some(4 + hs_len);
        }

        if expected_hs_len.is_some_and(|need| handshake.len() >= need) {
            break;
        }
        if rec_end > buf.len() {
            return ParseDecision::NeedMoreData;
        }
    }

    let Some(total_hs_len) = expected_hs_len else {
        return ParseDecision::NeedMoreData;
    };
    if handshake.len() < total_hs_len {
        return ParseDecision::NeedMoreData;
    }

    let body = &handshake[4..total_hs_len];
    parse_client_hello_body(body)
}

fn parse_client_hello_body(body: &[u8]) -> ParseDecision {
    // legacy_version(2) + random(32)
    let mut off = 34usize;
    if body.len() < off + 1 {
        return ParseDecision::Unrecognized;
    }

    // session_id
    let sid_len = body[off] as usize;
    off += 1 + sid_len;
    if body.len() < off + 2 {
        return ParseDecision::Unrecognized;
    }

    // cipher_suites
    let cs_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2 + cs_len;
    if body.len() < off + 1 {
        return ParseDecision::Unrecognized;
    }

    // compression_methods
    let comp_len = body[off] as usize;
    off += 1 + comp_len;
    if body.len() == off {
        // Valid ClientHello with no extensions -> no SNI
        return ParseDecision::Unrecognized;
    }
    if body.len() < off + 2 {
        return ParseDecision::Unrecognized;
    }

    let exts_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + exts_len {
        return ParseDecision::Unrecognized;
    }

    let mut exts = &body[off..off + exts_len];
    let mut sni: Option<String> = None;
    let mut ech_ext = false;

    while exts.len() >= 4 {
        let ext_type = u16::from_be_bytes([exts[0], exts[1]]);
        let ext_len = u16::from_be_bytes([exts[2], exts[3]]) as usize;
        exts = &exts[4..];
        if exts.len() < ext_len {
            break;
        }
        let ext_data = &exts[..ext_len];
        exts = &exts[ext_len..];

        if ext_type == 0x0000 && sni.is_none() {
            sni = parse_sni_extension(ext_data);
        } else if ext_type == 0xfe0d {
            ech_ext = true;
        }
    }

    match sni {
        Some(domain) => ParseDecision::Resolved { domain, ech_ext },
        None => ParseDecision::Unrecognized,
    }
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }
    let mut cur = &data[2..2 + list_len];
    while cur.len() >= 3 {
        let name_type = cur[0];
        let name_len = u16::from_be_bytes([cur[1], cur[2]]) as usize;
        cur = &cur[3..];
        if cur.len() < name_len {
            return None;
        }
        let raw_bytes = &cur[..name_len];
        cur = &cur[name_len..];
        if name_type == 0x00 {
            if let Ok(raw_str) = std::str::from_utf8(raw_bytes) {
                if let Some(norm) = normalize_hostname(raw_str) {
                    return Some(norm);
                }
            }
        }
    }
    None
}

const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

fn parse_http_host(buf: &[u8]) -> ParseDecision {
    let matches_any = HTTP_METHODS.iter().any(|m| {
        if buf.len() >= m.len() {
            buf.starts_with(m)
        } else {
            m.starts_with(buf)
        }
    });

    if !matches_any {
        return ParseDecision::Unrecognized;
    }

    if buf.len() < 8
        && HTTP_METHODS
            .iter()
            .any(|m| buf.len() < m.len() && m.starts_with(buf))
    {
        return ParseDecision::NeedMoreData;
    }

    // Stop within the headers so a binary HTTP body cannot invalidate an otherwise readable Host.
    for raw_line in buf.split_inclusive(|&b| b == b'\n').skip(1) {
        let Some(line) = raw_line.strip_suffix(b"\n") else {
            return ParseDecision::NeedMoreData;
        };
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            return ParseDecision::Unrecognized;
        }
        if let Some(colon) = line.iter().position(|&b| b == b':')
            && line[..colon].eq_ignore_ascii_case(b"host")
        {
            return match std::str::from_utf8(&line[colon + 1..])
                .ok()
                .and_then(normalize_hostname)
            {
                Some(domain) => ParseDecision::Resolved {
                    domain,
                    ech_ext: false,
                },
                None => ParseDecision::Unrecognized,
            };
        }
    }

    ParseDecision::NeedMoreData
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tls_client_hello_payload(sni: &str, include_ech: bool) -> Vec<u8> {
        let mut exts = Vec::new();
        // SNI extension (0x0000)
        let host = sni.as_bytes();
        let entry_len = 1 + 2 + host.len();
        let list_len = entry_len;
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&((2 + list_len) as u16).to_be_bytes());
        exts.extend_from_slice(&(list_len as u16).to_be_bytes());
        exts.push(0x00);
        exts.extend_from_slice(&(host.len() as u16).to_be_bytes());
        exts.extend_from_slice(host);

        if include_ech {
            exts.extend_from_slice(&0xfe0du16.to_be_bytes());
            exts.extend_from_slice(&4u16.to_be_bytes());
            exts.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy
        body.extend_from_slice(&[0xaa; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // compression len
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let l = body.len() as u32;
        hs.push(((l >> 16) & 0xff) as u8);
        hs.push(((l >> 8) & 0xff) as u8);
        hs.push((l & 0xff) as u8);
        hs.extend_from_slice(&body);
        hs
    }

    fn wrap_tls_record(payload: &[u8]) -> Vec<u8> {
        let mut rec = Vec::with_capacity(5 + payload.len());
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        rec.extend_from_slice(payload);
        rec
    }

    #[test]
    fn parses_tls_sni_single_split_and_multi_record() {
        let hs = build_tls_client_hello_payload("Example.COM", false);
        let single_rec = wrap_tls_record(&hs);
        assert_eq!(
            extract_domain_from_prefix(&single_rec),
            ParseDecision::Resolved {
                domain: "example.com".into(),
                ech_ext: false
            }
        );

        // Partial TLS record -> NeedMoreData
        assert_eq!(
            extract_domain_from_prefix(&single_rec[..20]),
            ParseDecision::NeedMoreData
        );

        let mut partial_record = single_rec.clone();
        let declared_record_len = (hs.len() + 20) as u16;
        partial_record[3..5].copy_from_slice(&declared_record_len.to_be_bytes());
        assert_eq!(
            extract_domain_from_prefix(&partial_record),
            extract_domain_from_prefix(&single_rec)
        );

        // Split ClientHello across two TLS records
        let mid = hs.len() / 2;
        let mut multi_rec = wrap_tls_record(&hs[..mid]);
        multi_rec.extend_from_slice(&wrap_tls_record(&hs[mid..]));
        assert_eq!(
            extract_domain_from_prefix(&multi_rec),
            ParseDecision::Resolved {
                domain: "example.com".into(),
                ech_ext: false
            }
        );

        // With ECH extension
        let ech_rec = wrap_tls_record(&build_tls_client_hello_payload("cloudflare-ech.com", true));
        assert_eq!(
            extract_domain_from_prefix(&ech_rec),
            ParseDecision::Resolved {
                domain: "cloudflare-ech.com".into(),
                ech_ext: true
            }
        );
    }

    #[test]
    fn reassembles_overlapping_and_ooo_tcp_segments() {
        let hs = build_tls_client_hello_payload("www.youtube.com", false);
        let rec = wrap_tls_record(&hs);

        let mut r = PrefixReassembler::new(1000, 16 * 1024);
        // Out-of-order second piece arrives first
        r.push(1001 + 25, &rec[25..]).unwrap();
        assert_eq!(r.contiguous().len(), 0);
        // First piece arrives with 5-byte overlap
        r.push(1001, &rec[..30]).unwrap();
        assert_eq!(r.contiguous(), rec.as_slice());
        assert_eq!(
            extract_domain_from_prefix(r.contiguous()),
            ParseDecision::Resolved {
                domain: "www.youtube.com".into(),
                ech_ext: false
            }
        );
    }

    #[test]
    fn parses_http_host_including_split() {
        let req = b"GET /index.html HTTP/1.1\r\nUser-Agent: curl\r\nHost: Example.Org:80\r\n\r\n";
        assert_eq!(
            extract_domain_from_prefix(&req[..30]),
            ParseDecision::NeedMoreData
        );
        assert_eq!(
            extract_domain_from_prefix(req),
            ParseDecision::Resolved {
                domain: "example.org".into(),
                ech_ext: false
            }
        );
        let mut with_binary_body = req.to_vec();
        with_binary_body.extend_from_slice(b"\xff\xfe\x00");
        assert_eq!(
            extract_domain_from_prefix(&with_binary_body),
            extract_domain_from_prefix(req)
        );
        assert_eq!(
            extract_domain_from_prefix(b"\x17\x03\x03\x00\x10hello"),
            ParseDecision::Unrecognized
        );
    }

    #[test]
    fn gro_packet_truncated_to_160_still_counts_full_payload() {
        let mut pkt = vec![0u8; 160];
        pkt[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        pkt[14] = 0x45; // IPv4, IHL=20
        // IPv4 tot_len = 4000
        pkt[16..18].copy_from_slice(&4000u16.to_be_bytes());
        pkt[23] = 6; // TCP
        pkt[26..30].copy_from_slice(&[93, 184, 216, 34]);
        pkt[30..34].copy_from_slice(&[10, 1, 1, 4]);
        // TCP src=443, dst=50000, doff=20 (0x50)
        pkt[34..36].copy_from_slice(&443u16.to_be_bytes());
        pkt[36..38].copy_from_slice(&50000u16.to_be_bytes());
        pkt[46] = 0x50;
        pkt[47] = TCP_ACK;

        let parsed = parse_ethernet_ipv4_tcp(&pkt).unwrap();
        assert_eq!(parsed.payload_len, 4000 - 20 - 20);
        assert_eq!(parsed.captured_payload.len(), 160 - 54);
    }
}

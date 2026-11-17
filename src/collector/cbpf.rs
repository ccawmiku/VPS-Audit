use std::net::Ipv4Addr;

pub const OUTBOUND_SNAPLEN: u32 = 16_640;
pub const INBOUND_SNAPLEN: u32 = 160;

// Classic BPF opcodes (Linux <linux/bpf_common.h> / <linux/filter.h>)
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;

const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MSH: u16 = 0xa0;

const BPF_K: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;
const BPF_TXA: u16 = 0x80;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[inline]
const fn bpf_stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[inline]
const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Builds a classic BPF filter matching Ethernet + IPv4 + non-fragmented TCP on ports 80/443
/// for `local_ip`, returning `OUTBOUND_SNAPLEN` for outbound packets and `INBOUND_SNAPLEN` for inbound.
pub fn build_ipv4_tcp_80_443_filter(local_ip: Ipv4Addr) -> Vec<SockFilter> {
    let ip_u32 = u32::from(local_ip);

    // Instruction layout (indices 0..=21):
    //  0: ldh  [12]              ; EtherType
    //  1: jeq  #0x0800, +0, L_DROP(21)
    //  2: ldb  [23]              ; IPv4 protocol
    //  3: jeq  #6, +0, L_DROP(21)
    //  4: ldh  [20]              ; IPv4 flags + frag_off
    //  5: jset #0x3fff, L_DROP(21), +0
    //  6: ldx  4*([14]&0xf)      ; X = IPv4 IHL bytes
    //  7: txa                    ; A = X
    //  8: jge  #20, +0, L_DROP(21)
    //  9: ld   [26]              ; IPv4 src_ip
    // 10: jeq  #local_ip, +0, L_INBOUND(16)
    // 11: ld   [30]              ; (outbound) IPv4 dst_ip
    // 12: jeq  #local_ip, L_DROP(21), +0
    // 13: ldh  [x+16]            ; TCP dst_port
    // 14: jeq  #443, L_OUT(20), +0
    // 15: jeq  #80, L_OUT(20), L_DROP(21)
    // 16: ld   [30]              ; (inbound) IPv4 dst_ip
    // 17: jeq  #local_ip, +0, L_DROP(21)
    // 18: ldh  [x+14]            ; TCP src_port
    // 19: jeq  #443, L_IN(22), L_IN_80(23)
    // 20: ret  #OUTBOUND_SNAPLEN
    // 21: ret  #0
    // 22: ret  #INBOUND_SNAPLEN
    // 23: jeq  #80, L_IN(22), L_DROP(21)
    // Wait: let's keep returns contiguous at the end and make jumps crystal clear:
    // 19: jeq  #443, L_IN(22), +0
    // 20: jeq  #80, L_IN(22), L_DROP(23)
    // 21: ret  #OUTBOUND_SNAPLEN
    // 22: ret  #INBOUND_SNAPLEN
    // 23: ret  #0

    vec![
        // 0..1: EtherType == IPv4 (0x0800)
        bpf_stmt(BPF_LD | BPF_H | BPF_ABS, 12),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 0, 21), // jf -> 23 (1 + 1 + 21 = 23)
        // 2..3: IP proto == TCP (6)
        bpf_stmt(BPF_LD | BPF_B | BPF_ABS, 23),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 6, 0, 19), // jf -> 23 (3 + 1 + 19 = 23)
        // 4..5: Reject subsequent and first IP fragments (MF flag or nonzero offset)
        bpf_stmt(BPF_LD | BPF_H | BPF_ABS, 20),
        bpf_jump(BPF_JMP | BPF_JSET | BPF_K, 0x3fff, 17, 0), // jt -> 23 (5 + 1 + 17 = 23)
        // 6..8: X = IHL >= 20
        bpf_stmt(BPF_LDX | BPF_MSH | BPF_B, 14),
        bpf_stmt(BPF_MISC | BPF_TXA, 0),
        bpf_jump(BPF_JMP | BPF_JGE | BPF_K, 20, 0, 14), // jf -> 23 (8 + 1 + 14 = 23)
        // 9..10: src_ip == local_ip ?
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 26),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, ip_u32, 0, 5), // jf -> 16 (10 + 1 + 5 = 16)
        // 11..12: (outbound) dst_ip != local_ip
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 30),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, ip_u32, 10, 0), // jt -> 23 (12 + 1 + 10 = 23)
        // 13..15: (outbound) tcp.dst_port == 443 || 80
        bpf_stmt(BPF_LD | BPF_H | BPF_IND, 16),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 443, 6, 0), // jt -> 21 (14 + 1 + 6 = 21)
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 80, 5, 7),  // jt -> 21, jf -> 23
        // 16..17: (inbound) dst_ip == local_ip
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 30),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, ip_u32, 0, 5), // jf -> 23 (17 + 1 + 5 = 23)
        // 18..20: (inbound) tcp.src_port == 443 || 80
        bpf_stmt(BPF_LD | BPF_H | BPF_IND, 14),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 443, 2, 0), // jt -> 22 (19 + 1 + 2 = 22)
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 80, 1, 2),  // jt -> 22, jf -> 23
        // 21: return OUTBOUND_SNAPLEN
        bpf_stmt(BPF_RET | BPF_K, OUTBOUND_SNAPLEN),
        // 22: return INBOUND_SNAPLEN
        bpf_stmt(BPF_RET | BPF_K, INBOUND_SNAPLEN),
        // 23: drop
        bpf_stmt(BPF_RET | BPF_K, 0),
    ]
}

#[cfg(target_os = "linux")]
pub fn attach_filter(fd: libc::c_int, prog: &[SockFilter]) -> std::io::Result<()> {
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    let fprog = SockFprog {
        len: u16::try_from(prog.len())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "BPF too long"))?,
        filter: prog.as_ptr(),
    };

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const SockFprog as *const libc::c_void,
            std::mem::size_of::<SockFprog>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal faithful classic BPF evaluator for unit-testing our generated filter.
    fn eval_cbpf(prog: &[SockFilter], pkt: &[u8]) -> u32 {
        let mut a: u32 = 0;
        let mut x: u32 = 0;
        let mut pc: usize = 0;

        while pc < prog.len() {
            let insn = prog[pc];
            let class = insn.code & 0x07;
            match class {
                BPF_LD => {
                    let size = insn.code & 0x18;
                    let mode = insn.code & 0xe0;
                    let off = match mode {
                        BPF_ABS => insn.k as usize,
                        BPF_IND => (x as usize).saturating_add(insn.k as usize),
                        _ => panic!("unsupported LD mode {mode:#x}"),
                    };
                    a = match size {
                        BPF_B => match pkt.get(off) {
                            Some(&b) => b as u32,
                            None => return 0,
                        },
                        BPF_H => match pkt.get(off..off + 2) {
                            Some(s) => u16::from_be_bytes([s[0], s[1]]) as u32,
                            None => return 0,
                        },
                        BPF_W => match pkt.get(off..off + 4) {
                            Some(s) => u32::from_be_bytes([s[0], s[1], s[2], s[3]]),
                            None => return 0,
                        },
                        _ => panic!("unsupported LD size {size:#x}"),
                    };
                    pc += 1;
                }
                BPF_LDX => {
                    assert_eq!(insn.code, BPF_LDX | BPF_MSH | BPF_B);
                    let off = insn.k as usize;
                    let b = match pkt.get(off) {
                        Some(&v) => v,
                        None => return 0,
                    };
                    x = ((b & 0x0f) as u32) * 4;
                    pc += 1;
                }
                BPF_MISC => {
                    assert_eq!(insn.code, BPF_MISC | BPF_TXA);
                    a = x;
                    pc += 1;
                }
                BPF_JMP => {
                    let op = insn.code & 0xf0;
                    let cond = match op {
                        BPF_JEQ => a == insn.k,
                        BPF_JGE => a >= insn.k,
                        BPF_JSET => (a & insn.k) != 0,
                        _ => panic!("unsupported JMP op {op:#x}"),
                    };
                    let delta = if cond { insn.jt } else { insn.jf } as usize;
                    pc += 1 + delta;
                }
                BPF_RET => {
                    return insn.k;
                }
                _ => panic!("unsupported class {class:#x}"),
            }
        }
        0
    }

    fn make_eth_ipv4_tcp(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        ihl_words: u8,
        frag_off: u16,
        proto: u8,
        ethertype: u16,
    ) -> Vec<u8> {
        let ihl = (ihl_words as usize) * 4;
        let mut pkt = vec![0u8; 14 + ihl + 20];
        pkt[12..14].copy_from_slice(&ethertype.to_be_bytes());
        pkt[14] = (4 << 4) | (ihl_words & 0x0f);
        pkt[20..22].copy_from_slice(&frag_off.to_be_bytes());
        pkt[23] = proto;
        pkt[26..30].copy_from_slice(&src_ip.octets());
        pkt[30..34].copy_from_slice(&dst_ip.octets());
        let l4 = 14 + ihl;
        pkt[l4..l4 + 2].copy_from_slice(&src_port.to_be_bytes());
        pkt[l4 + 2..l4 + 4].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    #[test]
    fn cbpf_filters_outbound_inbound_and_rejects_vless_tunnel() {
        let local = Ipv4Addr::new(10, 1, 1, 4);
        let remote = Ipv4Addr::new(93, 184, 216, 34);
        let client = Ipv4Addr::new(203, 0, 113, 9);
        let prog = build_ipv4_tcp_80_443_filter(local);

        // Outbound HTTPS & HTTP -> OUTBOUND_SNAPLEN
        let out_443 = make_eth_ipv4_tcp(local, remote, 54321, 443, 5, 0x4000, 6, 0x0800);
        assert_eq!(eval_cbpf(&prog, &out_443), OUTBOUND_SNAPLEN);

        let out_80 = make_eth_ipv4_tcp(local, remote, 54322, 80, 6, 0, 6, 0x0800);
        assert_eq!(eval_cbpf(&prog, &out_80), OUTBOUND_SNAPLEN);

        // Inbound HTTPS & HTTP -> INBOUND_SNAPLEN
        let in_443 = make_eth_ipv4_tcp(remote, local, 443, 54321, 5, 0x4000, 6, 0x0800);
        assert_eq!(eval_cbpf(&prog, &in_443), INBOUND_SNAPLEN);

        let in_80 = make_eth_ipv4_tcp(remote, local, 80, 54322, 5, 0, 6, 0x0800);
        assert_eq!(eval_cbpf(&prog, &in_80), INBOUND_SNAPLEN);

        // VLESS inbound client -> VPS:443 -> DROP
        let vless_in = make_eth_ipv4_tcp(client, local, 60000, 443, 5, 0, 6, 0x0800);
        assert_eq!(eval_cbpf(&prog, &vless_in), 0);

        // VLESS outbound reply VPS:443 -> client -> DROP
        let vless_out = make_eth_ipv4_tcp(local, client, 443, 60000, 5, 0, 6, 0x0800);
        assert_eq!(eval_cbpf(&prog, &vless_out), 0);

        // Non-80/443 outbound -> DROP
        let ssh_out = make_eth_ipv4_tcp(local, remote, 54323, 22, 5, 0, 6, 0x0800);
        assert_eq!(eval_cbpf(&prog, &ssh_out), 0);

        // UDP 443 (QUIC) -> DROP
        let quic = make_eth_ipv4_tcp(local, remote, 54324, 443, 5, 0, 17, 0x0800);
        assert_eq!(eval_cbpf(&prog, &quic), 0);

        // IPv6 EtherType -> DROP
        let ipv6 = make_eth_ipv4_tcp(local, remote, 54324, 443, 5, 0, 6, 0x86dd);
        assert_eq!(eval_cbpf(&prog, &ipv6), 0);

        // Subsequent IP fragment -> DROP
        let frag = make_eth_ipv4_tcp(local, remote, 54324, 443, 5, 0x0040, 6, 0x0800);
        assert_eq!(eval_cbpf(&prog, &frag), 0);

        let first_fragment = make_eth_ipv4_tcp(local, remote, 54324, 443, 5, 0x2000, 6, 0x0800);
        assert_eq!(eval_cbpf(&prog, &first_fragment), 0);

        // Malformed IHL < 5 -> DROP
        let bad_ihl = make_eth_ipv4_tcp(local, remote, 54324, 443, 4, 0, 6, 0x0800);
        assert_eq!(eval_cbpf(&prog, &bad_ihl), 0);
    }
}

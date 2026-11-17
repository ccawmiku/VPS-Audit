# vless-audit

面向单台 Linux VPS 的零侵入、轻量级 `AF_PACKET` 旁路流量与域名审计工具。

## 特性
- **单套接字全功能采集**：基于 `AF_PACKET/SOCK_RAW` + cBPF 过滤 IPv4 TCP 80/443，双向负载字节计数与域名识别（TLS SNI / HTTP Host，支持多 TCP 分段与跨 TLS Record 重组）。
- **零改动 VLESS**：通过本机出站方向（主动 SYN + `PACKET_OUTGOING`）严格隔离入站隧道流与本机出站网页连接。
- **低资源单静态二进制**：Rust + `rusqlite (bundled)` + `axum` + `rust-embed`，SQLite WAL 模式，5 分钟时间窗聚合 + PSL 主域名归并。
- **零公网暴露**：仅监听 loopback（默认 `127.0.0.1:18080`），配合 Cloudflare Tunnel (`HTTP/2`) + Cloudflare Access (`Protect with Access`) 安全访问。

## 本地交叉编译（WSL Debian 13）
```bash
bash deploy/build_linux.sh
```
核心编译命令：
```bash
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build --release --target x86_64-unknown-linux-gnu
```

## VPS 部署步骤
1. 将编译好的 `vless-audit` 二进制和 `deploy/vless-audit.service`、`deploy/install.sh` 传至 VPS：
   ```bash
   chmod +x install.sh
   sudo ./install.sh ./vless-audit ./vless-audit.service
   ```
   如需自定义网卡、监听端口和界面名称，先写入 `/etc/vless-audit.env`。例如

   ```ini
   VLESS_AUDIT_IFACE=enp1s0
   VLESS_AUDIT_LISTEN=127.0.0.1:18081
   VLESS_AUDIT_INSTANCE_NAME="第二台 VPS"
   ```

   自定义端口时，在安装命令的第三个参数传入同一地址，如 `127.0.0.1:18081`。

2. 验证服务以非 root 用户 `vless-audit`（仅 `CAP_NET_RAW`）运行且仅监听 `127.0.0.1:18080`：
   ```bash
   ss -tlnp | grep 18080
   curl -s http://127.0.0.1:18080/healthz
   curl -s http://127.0.0.1:18080/api/status
   ```
3. 安装并配置 `cloudflared`（固定 `--protocol http2` 传输）：
   - Tunnel Public Hostname 指向 `http://127.0.0.1:18080`；
   - 在 Cloudflare Zero Trust 创建独立 Access 应用并关联仅允许指定邮箱的 Reusable Policy；
   - 开启 **Protect with Access**（由 `cloudflared` 校验该应用 JWT）。

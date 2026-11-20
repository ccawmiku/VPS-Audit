# vless-audit

面向单台 Linux VPS 的轻量级 `AF_PACKET` 旁路流量、域名与来源 IP 审计工具。

## 特性
- **单套接字全功能采集**：基于 `AF_PACKET/SOCK_RAW` + cBPF 过滤 IPv4 TCP 80/443，双向负载字节计数与域名识别（TLS SNI / HTTP Host，支持多 TCP 分段与跨 TLS Record 重组）。
- **零改动 VLESS**：通过本机出站方向（主动 SYN + `PACKET_OUTGOING`）严格隔离入站隧道流与本机出站网页连接。
- **低资源单静态二进制**：Rust + `rusqlite (bundled)` + `axum` + `rust-embed`，SQLite WAL 模式，5 分钟时间窗聚合 + PSL 主域名归并。
- **可选来源 IP 统计**：指定直连 VLESS 的 TCP 端口，按 IPv4 对端聚合上传、下载、TCP 完整握手次数和最近活动。采集器复用原有抓包套接字与本地 SQLite。
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
   VLESS_AUDIT_INBOUND_PORT=443
   ```

   自定义端口时，在安装命令的第三个参数传入同一地址，如 `127.0.0.1:18081`。

   `VLESS_AUDIT_INBOUND_PORT` 默认未配置。设置为 Xray 直连入站在采集网卡上可见的 TCP 端口，多个端口用英文逗号分隔（如 `443,2443`），设置后重启 `vless-audit`。来源 IP 按 5 分钟聚合写入本地 SQLite，沿用 `VLESS_AUDIT_BUCKET_DAYS`（默认 90 天）的保留时长。

   可设置 `VLESS_AUDIT_GEOIP_DB=/var/lib/vless-audit/dbip-country.mmdb` 启用来源地区分布。下载并解压 [DB-IP Country Lite MMDB](https://db-ip.com/db/download/ip-to-country-lite)，将文件放到该路径并重启服务。查询在本地完成，显示 IP 地址所属的国家或地区估算。

   来源地区的色块按所选时段内各地区的隧道总流量着色，以当期最高流量为最深色。流量总览的类型占比按出站主域名归类，并包含其他域名和未识别流量。最近访问明细可以用完整域名显示更细的服务标签。

   世界地图采用内嵌的 Natural Earth 简化轮廓，按来源地区页需要加载。底图由 [Natural Earth 1:110m 国家轮廓和 1:50m 微小地区点位](https://github.com/nvkelso/natural-earth-vector/tree/v5.1.1/geojson) 生成。流量总览的主域名排行可用「看趋势」在上方图表查看该域名的分时段流量。

   来源 IP 页面按隧道总流量排序。上行为客户端发给 VPS 的 TCP 负载，下行为 VPS 发给客户端的 TCP 负载，均包含重传。升级前的连接记录会保留，字节数自启用新版开始累计。完成 TCP 握手的扫描也可能进入统计。经过 Cloudflare Tunnel、其他反代或 NAT 时，页面显示采集网卡实际可见的对端。

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

### 可选入站 IP 屏蔽

Debian 13 可以随 Audit 安装可选的防火墙组件。它需要系统自带 Python 3 和 nftables，安装脚本旁需保留 `vless-audit-blocklist` 及其 `.service`、`.path`、`.timer` 文件。

```bash
sudo ./deploy/install.sh ./dist/vless-audit ./deploy/vless-audit.service 127.0.0.1:18080 --with-blocklist
```

初次安装默认为关闭。在「来源 IP」页开启后，系统服务下载 [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) 的 IPv4、IPv6 名单，只匹配 `VLESS_AUDIT_IFACE` 上发往 `VLESS_AUDIT_INBOUND_PORT` 的入站 TCP。接口和端口须与 Audit 的实际采集配置一致。其他防火墙规则照常执行。开启时每天刷新名单，下载或解析失败保留最近一次有效名单。关闭后移除 Audit 的专用防火墙表。

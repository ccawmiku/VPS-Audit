const $ = (id) => document.getElementById(id);

const formats = {
  date: new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'
  }),
  short: new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
  }),
  clock: new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
  }),
  integer: new Intl.NumberFormat('zh-CN')
};
const views = {
  overview: ['流量总览', '查看本机主动发起的 IPv4 TCP 80 / 443 流量与域名分布。', 'viewOverview'],
  sources: ['来源 IP', '按客户端 IPv4 查看直连隧道的流量和连接次数。', 'viewSources'],
  status: ['采集诊断', '检查网卡、抓包和 SQLite 落库状态。', 'viewStatus']
};
const state = {
  view: 'overview', preset: '24h', from: 0, to: 0, drill: null,
  domainTab: 'domains', overview: null, recent: null, expandedRoot: null,
  searchIp: ''
};
const presets = [...document.querySelectorAll('[data-preset]')];
const navItems = [...document.querySelectorAll('[data-view]')];
let requestId = 0;
let requestController;
let chart;
let trendDomain = null;
let domainTimeline = [];
let blocklistStatus;
let blocklistSaving = false;
let blocklistPoll;
let dropHitsRequest;
let dropHitsCollectedAt;

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);
}

function icon(name) {
  return `<svg class="icon" aria-hidden="true"><use href="#icon-${name}"></use></svg>`;
}

function setText(id, value) {
  $(id).textContent = value;
}

function time(sec, kind = 'date') {
  return sec ? formats[kind].format(new Date(sec * 1000)) : '—';
}

function number(n) {
  return formats.integer.format(n);
}

function bytes(value, digits = 2) {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit++;
  }
  return `${size.toFixed(unit === 0 ? 0 : digits)} ${units[unit]}`;
}

function dateInput(sec) {
  return new Date((sec + 8 * 3600) * 1000).toISOString().slice(0, 16);
}

function updateRange() {
  if (state.preset === 'custom' || state.drill) return;
  const now = Math.floor(Date.now() / 1000);
  const durations = { '1h': 3600, '24h': 86400, '7d': 7 * 86400 };
  state.to = now;
  state.from = state.preset === 'today'
    ? Math.floor((now + 8 * 3600) / 86400) * 86400 - 8 * 3600
    : now - durations[state.preset];
}

function currentRange() {
  return state.drill ?? { from: state.from, to: state.to };
}

function updateRangeUi() {
  const { from, to } = currentRange();
  setText('rangeCaption', state.preset === 'custom' ? `${time(from, 'short')} – ${time(to, 'short')}` : '北京时间 (UTC+8)');
  $('drillBadge').hidden = !state.drill || state.view === 'status';
  if (state.drill) {
    $('drillBadge').innerHTML = `${icon('x')}${esc(time(from, 'short'))} – ${esc(time(to, 'short'))} · 退出下钻`;
  }
  for (const button of presets) {
    button.setAttribute('aria-pressed', String(button.dataset.preset === state.preset));
  }
}

async function fetchJson(path, signal) {
  const response = await fetch(path, { signal });
  if (!response.ok) throw new Error(`请求失败 (${response.status})`);
  return response.json();
}

async function refresh() {
  const id = ++requestId;
  requestController?.abort();
  requestController = new AbortController();
  const { signal } = requestController;
  updateRange();
  updateRangeUi();
  const { from, to } = currentRange();
  const range = `from=${from}&to=${to}`;
  $('refreshBtn').setAttribute('aria-busy', 'true');

  try {
    const statusQuery = fetchJson('/api/status', signal);
    const overviewQuery = state.view === 'overview' ? fetchJson(`/api/overview?${range}`, signal) : null;
    const recentQuery = state.view === 'overview' && state.domainTab === 'recent'
      ? fetchJson('/api/recent?limit=150', signal) : null;
    const sourceQuery = state.view === 'sources'
      ? fetchJson(`/api/sources?${range}${state.searchIp ? '&ip=' + encodeURIComponent(state.searchIp) : ''}`, signal) : null;
    const timelineQuery = state.view === 'overview' && trendDomain
      ? fetchJson(`/api/domain/${encodeURIComponent(trendDomain)}/timeline?${range}`, signal) : null;
    const [status, overview, recent, sources, timeline] = await Promise.all([
      statusQuery, overviewQuery, recentQuery, sourceQuery, timelineQuery
    ]);
    if (id !== requestId) return;
    $('requestError').hidden = true;
    renderStatus(status);
    if (overview) {
      state.overview = overview;
      domainTimeline = timeline ?? [];
      renderOverview(overview);
    }
    if (recent) {
      state.recent = recent;
      renderRecent();
    }
    if (sources) {
      renderSources(sources, status);
    }
  } catch (error) {
    if (id !== requestId) return;
    setText('requestError', `暂时无法读取审计数据。${error.message}，请重试。`);
    $('requestError').hidden = false;
    setHealth('读取失败', 'error');
  } finally {
    if (id === requestId) $('refreshBtn').removeAttribute('aria-busy');
  }
}

function showView() {
  const slug = location.hash.slice(1);
  state.view = Object.hasOwn(views, slug) ? slug : 'overview';
  const [title, description] = views[state.view];
  setText('pageTitle', title);
  setText('breadcrumb', title);
  setText('pageDescription', description);
  $('dateControl').open = false;
  $('rangeBar').hidden = state.view === 'status';
  for (const [name, [, , id]] of Object.entries(views)) {
    $(id).hidden = name !== state.view;
  }
  for (const item of navItems) {
    if (item.dataset.view === state.view) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  }
  closeTooltip();
  if (state.view === 'overview' && state.overview) renderCurrentChart();
  refresh();
}

function renderOverview(overview) {
  const s = overview.summary;
  setText('sumRx', bytes(s.total_rx_bytes));
  setText('sumTx', bytes(s.total_tx_bytes));
  setText('sumTotalSub', `双向合计 ${bytes(s.total_rx_bytes + s.total_tx_bytes)}`);
  setText('sumConns', `出站连接 ${number(s.total_conns)}`);
  setText('sumDomains', number(s.active_root_domains));
  setText('sumUnid', `${s.unidentified_ratio_pct.toFixed(1)}%`);
  setText('sumUnidSub', `上下行合计 ${bytes(s.unidentified_tx_bytes + s.unidentified_rx_bytes)}`);
  renderCurrentChart();
  renderTrafficMix(overview.traffic_types ?? [], s.total_rx_bytes + s.total_tx_bytes);
  if (state.domainTab === 'domains') renderDomains();
}

function renderCurrentChart() {
  setText('trendTitle', trendDomain ? `流量趋势 · ${trendDomain}` : '流量趋势');
  $('resetTrendDomain').hidden = !trendDomain;
  renderChart(trendDomain ? { ...state.overview, timeline: domainTimeline } : state.overview);
}

const trafficKinds = {
  ai: ['AI', '#7159b0'], video: ['影音与直播', '#149477'],
  social: ['社交与通信', '#3478b6'], development: ['开发工具', '#c36a3b'],
  cloud: ['云服务与 CDN', '#537395'], platform: ['通用平台', '#5b8170'],
  games: ['游戏', '#c78325'], files: ['文件与网盘', '#a34d81'],
  other: ['其他域名', '#a0a977'], unidentified: ['未识别', '#a2afbc']
};

function renderTrafficMix(types, total) {
  $('trafficMixContent').hidden = total === 0;
  $('trafficMixEmpty').hidden = total > 0;
  if (total === 0) return;
  let offset = 0;
  const stops = [];
  $('trafficMixLegend').innerHTML = types.map(({ kind, total_bytes: count }) => {
    const [label, color] = trafficKinds[kind] ?? trafficKinds.other;
    const share = count / total * 100;
    const end = Math.min(100, offset + share);
    stops.push(`${color} ${offset}% ${end}%`);
    offset = end;
    return `<li><i class="dot" style="background:${color}" aria-hidden="true"></i><span>${label}</span>
      <strong>${bytes(count)}</strong><small>${share >= 0.1 ? share.toFixed(1) : '＜0.1'}%</small></li>`;
  }).join('');
  $('trafficMixRing').style.background = `conic-gradient(${stops.join(', ')})`;
  setText('trafficMixTotal', bytes(total));
}

function renderChart({ timeline, summary }) {
  const svg = $('timelineSvg');
  const width = svg.clientWidth;
  const height = svg.clientHeight;
  if (!width || !height) return;
  closeTooltip();
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

  const left = 59;
  const right = width - 11;
  const top = 13;
  const bottom = height - 26;
  const step = summary.step_secs;
  const first = Math.floor(summary.from_ts / step) * step;
  const fullCount = Math.floor((summary.to_ts - first) / step) + 1;
  const stride = Math.max(1, Math.ceil(fullCount / Math.min(300, Math.max(20, right - left))));
  const bin = stride * step;
  const count = Math.ceil(fullCount / stride);
  const slotWidth = (right - left) / count;
  const points = Array.from({ length: count }, (_, index) => ({
    ts: first + index * bin, rx: 0, tx: 0, unknown: 0, conns: 0
  }));
  for (const item of timeline) {
    const point = points[Math.floor((item.ts - first) / bin)];
    if (!point) continue;
    point.rx += item.rx_bytes;
    point.tx += item.tx_bytes;
    point.unknown += item.unidentified_bytes;
    point.conns += item.conn_count;
  }

  chart = timeline.length ? { points, height, left, right, top, bottom, slotWidth, summary, bin, selected: -1 } : null;
  $('chartEmpty').hidden = Boolean(chart);
  svg.classList.toggle('has-data', Boolean(chart));
  svg.tabIndex = chart ? 0 : -1;
  setText('stepLabel', `每 ${number(bin / 60)} 分钟汇总 TCP 负载`);
  const max = Math.max(1, ...points.map((point) => Math.max(point.rx, point.tx)));
  const x = (i) => left + slotWidth * (i + 0.5);
  const y = (value) => bottom - (bottom - top) * value / max;
  const grids = [1, 0.75, 0.5, 0.25, 0].map((band) => `
    <line class="chart-grid" x1="${left}" x2="${right}" y1="${y(max * band)}" y2="${y(max * band)}"/>
    ${chart ? `<text class="chart-label" x="${left - 7}" y="${y(max * band) + 3}" text-anchor="end">${bytes(max * band, 1)}</text>` : ''}`).join('');
  const duration = summary.to_ts - summary.from_ts;
  const axisCount = Math.min(count, width < 460 ? 3 : 5);
  const labels = Array.from({ length: axisCount }, (_, i) => {
    const index = axisCount === 1 ? 0 : Math.round(i * (count - 1) / (axisCount - 1));
    const anchor = axisCount === 1 ? 'middle' : i === 0 ? 'start' : i === axisCount - 1 ? 'end' : 'middle';
    return `<text class="chart-label" x="${x(index)}" y="${height - 7}" text-anchor="${anchor}">${esc(time(points[index].ts, duration < 12 * 3600 ? 'clock' : 'short'))}</text>`;
  }).join('');
  const series = (key, fill) => {
    if (count === 1) {
      return `<path d="M${left},${y(points[0][key])} H${right}" class="chart-stroke ${key}"/>`;
    }
    const line = points.map((point, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(point[key]).toFixed(1)}`).join(' ');
    return `${fill ? `<path d="${line} L${x(count - 1)},${bottom} H${x(0)} Z" fill="url(#chartFill)"/>` : ''}
      <path d="${line}" class="chart-stroke ${key}"/>`;
  };
  svg.innerHTML = `<defs><linearGradient id="chartFill" x2="0" y2="1"><stop stop-color="#75d5b4" stop-opacity=".44"/><stop offset="1" stop-color="#75d5b4" stop-opacity=".06"/></linearGradient></defs>
    ${grids}${labels}${chart ? `${series('rx', true)}${series('tx', false)}<line class="chart-guide" id="chartGuide" y1="${top}" y2="${bottom}" visibility="hidden"/>` : ''}`;
}

function closeTooltip() {
  $('tooltip').hidden = true;
  $('chartGuide')?.setAttribute('visibility', 'hidden');
}

function showChartPoint(index, clientX, clientY) {
  const point = chart.points[index];
  chart.selected = index;
  const x = chart.left + chart.slotWidth * (index + 0.5);
  const guide = $('chartGuide');
  guide.setAttribute('x1', x);
  guide.setAttribute('x2', x);
  guide.setAttribute('visibility', 'visible');
  const tip = $('tooltip');
  tip.innerHTML = `<strong>${esc(time(point.ts, 'short'))}</strong>
    <span>下行 ${bytes(point.rx)} · 上行 ${bytes(point.tx)}</span>
    <span>未识别 ${bytes(point.unknown)} · ${number(point.conns)} 条连接</span>`;
  tip.hidden = false;
  tip.style.left = `${Math.max(4, Math.min(clientX + 12, innerWidth - tip.offsetWidth - 6))}px`;
  tip.style.top = `${Math.max(4, Math.min(clientY + 10, innerHeight - tip.offsetHeight - 6))}px`;
}

function chartIndex(event) {
  if (!chart) return -1;
  const rect = $('timelineSvg').getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;
  if (x < chart.left || x >= chart.right || y < chart.top || y > chart.bottom) return -1;
  return Math.floor((x - chart.left) / chart.slotWidth);
}

function drillChart(index) {
  const point = chart.points[index];
  state.drill = {
    from: Math.max(chart.summary.from_ts, point.ts),
    to: Math.min(chart.summary.to_ts, point.ts + chart.bin - 1)
  };
  closeTooltip();
  refresh();
}

function emptyRow(cols, message) {
  return `<tr><td class="empty" colspan="${cols}">${icon('inbox')}${esc(message)}</td></tr>`;
}

function tag(label) {
  return label ? `<span class="tag">${esc(label)}</span>` : '';
}

function echTag(flag) {
  return flag ? '<span class="tag ech" title="可见 TLS 0xfe0d 扩展，可能为 ECH 或 GREASE">ECH / GREASE</span>' : '';
}

function matchesFilter(...values) {
  const filter = $('domainFilter').value.trim().toLowerCase();
  return !filter || values.some((value) => value?.toLowerCase().includes(filter));
}

function renderDomains() {
  if (!state.overview) return;
  const focusRoot = document.activeElement?.dataset.root;
  const { summary, domains } = state.overview;
  const rows = domains.filter((item) => matchesFilter(item.root_domain, item.service_label));
  const tbody = $('domainsBody');
  tbody.innerHTML = rows.map((item) => {
    const { root_domain: root, share_pct: share } = item;
    const expanded = root === state.expandedRoot;
    return `<tr class="rank-row">
      <td><button type="button" class="row-toggle" data-root="${esc(root)}" aria-expanded="${expanded}">${icon('chevron-right')}<span class="mono">${esc(root)}</span></button>${tag(item.service_label)}
        <button type="button" class="domain-trend" data-trend-root="${esc(root)}" aria-label="查看 ${esc(root)} 的流量趋势" aria-pressed="${root === trendDomain}">看趋势</button></td>
      <td class="num">${bytes(item.rx_bytes)}</td><td class="num">${bytes(item.tx_bytes)}</td>
      <td class="num"><strong>${bytes(item.total_bytes)}</strong></td>
      <td><span class="share"><progress max="100" value="${share.toFixed(2)}" aria-label="流量占比"></progress>${share.toFixed(1)}%</span></td>
      <td class="num">${number(item.conn_count)}</td>
    </tr>${expanded ? '<tr class="detail-row"><td colspan="6">正在加载子域名明细…</td></tr>' : ''}`;
  }).join('') || emptyRow(6, domains.length ? '没有匹配筛选条件的域名' : '此时段暂无域名记录');

  for (const button of tbody.querySelectorAll('[data-root]')) {
    if (button.dataset.root === focusRoot) button.focus({ preventScroll: true });
  }
  const detail = tbody.querySelector('.detail-row > td');
  if (detail) loadDetails(detail, state.expandedRoot, summary.from_ts, summary.to_ts);
}

async function loadDetails(cell, root, from, to) {
  try {
    const details = await fetchJson(`/api/domain/${encodeURIComponent(root)}/details?from=${from}&to=${to}`);
    if (!cell.isConnected) return;
    if (!details.length) {
      cell.textContent = '此时段暂无子域名明细';
      return;
    }
    cell.innerHTML = `<table>
      <thead><tr><th scope="col">完整域名</th><th scope="col" class="num">下行</th><th scope="col" class="num">上行</th><th scope="col" class="num">连接数</th><th scope="col" class="num">最后活跃</th></tr></thead>
      <tbody>${details.map((item) => `<tr>
        <td class="mono">${esc(item.full_domain)}${echTag(item.ech_ext)}</td>
        <td class="num">${bytes(item.rx_bytes)}</td><td class="num">${bytes(item.tx_bytes)}</td>
        <td class="num">${number(item.conn_count)}</td><td class="num">${esc(time(item.last_seen, 'short'))}</td>
      </tr>`).join('')}</tbody></table>`;
  } catch {
    if (cell.isConnected) cell.textContent = '子域名明细加载失败，请刷新重试';
  }
}

function renderRecent() {
  if (!state.recent) return;
  $('recentBody').innerHTML = state.recent
    .filter((item) => matchesFilter(item.full_domain, item.root_domain, item.service_label))
    .map((item) => `<tr>
      <td>${esc(time(item.last_seen))}</td><td class="mono">${esc(item.full_domain)}${echTag(item.ech_ext)}</td>
      <td class="mono">${esc(item.root_domain)}${tag(item.service_label)}</td>
      <td class="num">${bytes(item.rx_bytes)}</td><td class="num">${bytes(item.tx_bytes)}</td><td class="num">${number(item.conn_count)}</td>
    </tr>`).join('') || emptyRow(6, '暂无匹配的访问明细');
}

const regionNames = new Intl.DisplayNames(['zh-CN'], { type: 'region' });

function regionName(code) {
  return code ? regionNames.of(code) : '未知地区';
}

let mapGeometry;
let mapLoading = false;
let mapRegions = [];
let mapShapePaths = [];
let mapPointPaths = [];
let focusedRegion = null;

function regionHeat(count, max) {
  return 0.66 * Math.sqrt(count / Math.max(1, max));
}

async function renderSourceMap(regions) {
  mapRegions = regions ?? [];
  if (!mapRegions.length) {
    $('sourceMap').hidden = true;
    return;
  }
  if (!mapGeometry && !mapLoading) {
    mapLoading = true;
    try {
      mapGeometry = await fetchJson('/world-map.json');
      mapShapePaths = mapGeometry.countries.map(([code, rings]) => {
        const path = new Path2D();
        for (const coords of rings) {
          path.moveTo(coords[0], coords[1]);
          for (let i = 2; i < coords.length; i += 2) path.lineTo(coords[i], coords[i + 1]);
          path.closePath();
        }
        return [code, path];
      });
      mapPointPaths = mapGeometry.points.map(([code, x, y]) => {
        const path = new Path2D();
        path.arc(x, y, 4, 0, 2 * Math.PI);
        return [code, path];
      });
    } catch {
      mapGeometry = undefined;
    } finally {
      mapLoading = false;
    }
  }
  if (!mapGeometry || !mapRegions.length) return;
  $('sourceMap').hidden = false;
  drawSourceMap();
}

function drawSourceMap() {
  const canvas = $('sourceMapCanvas');
  const ctx = canvas.getContext('2d');
  if (!mapGeometry || !canvas.clientWidth || !ctx) return;
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  const width = Math.round(canvas.clientWidth * ratio);
  const height = Math.round(canvas.clientHeight * ratio);
  if (canvas.width !== width) canvas.width = width;
  if (canvas.height !== height) canvas.height = height;
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, width, height);
  ctx.setTransform(width / mapGeometry.size[0], 0, 0, height / mapGeometry.size[1], 0, 0);
  const regions = new Map(mapRegions.filter(r => r.country_code).map(r => [r.country_code, r.total_bytes]));
  const max = mapRegions[0]?.total_bytes ?? 0;
  for (const [code, path] of [...mapShapePaths, ...mapPointPaths.filter(([id]) => regions.has(id))]) {
    const heat = regionHeat(regions.get(code) ?? 0, max);
    ctx.fillStyle = heat
      ? `rgb(${Math.round(244 - 174 * heat)}, ${Math.round(250 - 62 * heat)}, ${Math.round(247 - 98 * heat)})`
      : '#e1e9e6';
    ctx.fill(path, 'evenodd');
    ctx.lineWidth = 1;
    ctx.strokeStyle = '#a8bbb1';
    ctx.stroke(path);
  }
}

function describeSourceMap(event) {
  if (!mapGeometry) return;
  const canvas = $('sourceMapCanvas');
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const rect = canvas.getBoundingClientRect();
  const x = (event.clientX - rect.left) * mapGeometry.size[0] / rect.width;
  const y = (event.clientY - rect.top) * mapGeometry.size[1] / rect.height;
  const data = new Map(mapRegions.filter(r => r.country_code).map(r => [r.country_code, r]));
  ctx.save();
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  const hit = [...mapPointPaths, ...mapShapePaths]
    .find(([code, path]) => data.has(code) && ctx.isPointInPath(path, x, y, 'evenodd'));
  ctx.restore();
  const code = hit?.[0] ?? null;
  if (code === focusedRegion) return;
  focusedRegion = code;
  const region = data.get(code);
  setText('sourceMapDetail', region
    ? `${regionName(code)} · ${number(region.unique_ips)} 个 IP · ${bytes(region.total_bytes)}`
    : '指向或点按地区查看流量');
}

function renderSourceGeography(data) {
  const regions = data.regions;
  $('sourceGeography').hidden = !regions;
  renderSourceMap(regions);
  if (!regions) return;
  focusedRegion = null;
  setText('sourceMapDetail', '指向或点按地区查看流量');
  $('sourceGeoEmpty').hidden = regions.length > 0;
  setText('sourceGeoCaption', regions.length > 8
    ? '显示流量前 8 个地区，颜色越深总流量越大'
    : '颜色越深，当前时段的总流量越大');
  const totalBytes = data.upload_bytes + data.download_bytes;
  const maxBytes = Math.max(1, regions[0]?.total_bytes ?? 0);
  $('sourceGeoList').innerHTML = regions.slice(0, 8).map(region => {
    const label = regionName(region.country_code);
    const share = totalBytes ? 100 * region.total_bytes / totalBytes : 0;
    const heat = 100 * regionHeat(region.total_bytes, maxBytes);
    return `<li style="--heat:${heat.toFixed(1)}%"><div><strong>${esc(label)}</strong><strong>${bytes(region.total_bytes)}</strong></div>
      <small>${number(region.unique_ips)} 个 IP · ${share.toFixed(1)}%</small></li>`;
  }).join('');
}

function renderSources(data, status) {
  renderBlocklist(status.blocklist);
  const ports = status.inbound_ports ?? (status.inbound_port ? [status.inbound_port] : []);
  const notice = $('sourcesNotice');
  notice.hidden = ports.length > 0 && !status.web_only;
  notice.textContent = status.web_only
    ? '当前以仅网页模式运行，显示本地数据库中已有的记录。'
    : '来源 IP 采集尚未启用。设置 VLESS_AUDIT_INBOUND_PORT 为本机 VLESS 直连 TCP 端口后，重启采集服务。';
  setText('sourceUnique', number(data.unique_ips));
  setText('sourceConns', number(data.total_conns));
  setText('sourceLatest', time(data.latest_seen));
  setText('sourceTraffic', bytes(data.download_bytes + data.upload_bytes));
  setText('sourceTrafficSplit', `下行 ${bytes(data.download_bytes)} · 上行 ${bytes(data.upload_bytes)}`);
  const sortNote = state.searchIp ? `查询 ${state.searchIp}`
    : data.unique_ips > data.rows.length ? `流量前 ${number(data.rows.length)} 个地址，可按完整 IPv4 查询其余地址。`
    : '按隧道总流量排序。';
  setText('sourcesCaption', ports.length ? `当前采集端口 ${ports.join(' / ')} · ${sortNote}` : sortNote);
  renderSourceGeography(data);
  $('sourcesBody').innerHTML = data.rows.map((item) => `<tr>
    <td><strong class="mono">${esc(item.ip)}</strong>${data.regions ? `<small class="source-location">${esc(regionName(item.country_code))}</small>` : ''}</td><td class="mono source-port">${esc(item.ports.split(',').join(' / '))}</td>
    <td class="num traffic-direction">${bytes(item.download_bytes)}</td><td class="num traffic-direction">${bytes(item.upload_bytes)}</td>
    <td class="num"><strong>${bytes(item.download_bytes + item.upload_bytes)}</strong><small class="compact-traffic">↓ ${bytes(item.download_bytes)} · ↑ ${bytes(item.upload_bytes)}</small></td>
    <td class="num">${number(item.conn_count)}</td><td class="num">${esc(time(item.last_seen))}</td>
  </tr>`).join('') || emptyRow(7, state.searchIp ? '此时段没有该来源 IP 的记录' : '此时段暂无来源 IP 记录');
}

function renderBlocklist(info) {
  blocklistStatus = info;
  clearTimeout(blocklistPoll);
  const button = $('blocklistToggle');
  const enabled = Boolean(info?.enabled);
  button.setAttribute('aria-checked', String(enabled));
  button.textContent = enabled ? '开启' : '关闭';
  button.disabled = blocklistSaving || !info?.installed || (!info.available && !enabled) || info.pending;
  const warnings = {
    no_feed: '暂未获取到有效名单',
    stale_feed: '更新失败，继续使用上次有效名单',
    firewall_error: '防火墙应用失败，请检查服务日志',
    invalid_scope: '采集接口或端口配置有误',
    no_ports: '请先配置直连 VLESS 端口'
  };
  let message = '防火墙组件未安装';
  if (info?.installed) {
    const phase = info.pending ? '等待应用' : info.active ? '已生效' : '已关闭';
    message = `Spamhaus DROP · ${phase}`;
    if (info.updated_at != null) message += ` · 名单更新于 ${time(info.updated_at)}`;
    if (info.warning) message += ` · ${warnings[info.warning] ?? '防火墙状态异常'}`;
    else if (!info.available) message += ' · 请核对采集接口和直连端口';
    if (info.pending) blocklistPoll = setTimeout(() => {
      if (state.view === 'sources') refresh();
    }, 2200);
  }
  setText('blocklistStatus', message);
  $('dropHits').hidden = !info?.installed || !info.active;
  if ($('dropHits').hidden) $('dropHits').open = false;
  loadDropHits();
}

async function loadDropHits(showLoading = false) {
  dropHitsRequest?.abort();
  if ($('dropHits').hidden || !$('dropHits').open) return;
  dropHitsRequest = new AbortController();
  const { signal } = dropHitsRequest;
  const table = $('dropHitsTable');
  if (showLoading) {
    table.hidden = true;
    setText('dropHitsStatus', '正在读取拦截记录');
  }
  try {
    const data = await fetchJson('/api/blocklist/hits', signal);
    if (signal.aborted) return;
    const count = data.rows.length;
    const capacity = data.at_capacity ? ' · 记录已达容量上限' : '';
    setText('dropHitsStatus', count ? `最近 24 小时拦截 ${number(count)} 个来源 IP${capacity}` : '最近 24 小时暂无拦截记录');
    if (dropHitsCollectedAt !== data.collected_at || $('dropHitsBody').rows.length !== count) {
      $('dropHitsBody').innerHTML = data.rows.map(({ ip, last_seen }) =>
        `<tr><td class="mono">${esc(ip)}</td><td>${esc(time(last_seen))}</td></tr>`).join('');
      dropHitsCollectedAt = data.collected_at;
    }
    table.hidden = count === 0;
  } catch (error) {
    if (signal.aborted) return;
    table.hidden = true;
    setText('dropHitsStatus', '暂时无法读取拦截记录，稍后自动刷新');
  }
}

function setHealth(label, tone) {
  $('liveBadge').dataset.tone = tone;
  setText('liveBadge', label);
}

function definitionList(items) {
  return items.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('');
}

function renderStatus(status) {
  const instance = status.instance_name || '本机';
  document.title = status.instance_name ? `VLESS 旁路流量审计 · ${instance}` : 'VLESS 旁路流量审计';
  setText('instanceName', instance);
  $('instanceName').title = instance;
  setText('sidebarDb', `${bytes(status.db_size_bytes)} · 含 WAL`);
  $('cfUserBadge').hidden = !status.cf_access_user;
  setText('cfUserBadge', status.cf_access_user ?? '');

  const label = status.web_only ? '仅网页模式' : !status.running ? '采集未运行'
    : status.socket_drops_total ? '采集中 · 有丢包' : '采集中';
  const tone = status.web_only || status.socket_drops_total ? 'warn' : status.running ? 'ok' : 'error';
  setHealth(label, tone);
  setText('collectorCaption', label);
  setText('coverageNote', status.coverage_note);
  const iface = `${status.iface || '—'} · ${status.local_ip || '—'}`;
  const flushed = time(status.last_flush_at);
  $('overviewStatus').innerHTML = definitionList([
    ['网卡 / 本机地址', iface], ['最近落库', flushed], ['套接字丢包', number(status.socket_drops_total)]
  ]);
  $('statusGrid').innerHTML = definitionList([
    ['网卡 / 本机地址', iface],
    ['套接字收包 / 丢包', `${number(status.socket_packets_total)} / ${number(status.socket_drops_total)}`],
    ['出站连接 / 已识别 / 未识别', `${number(status.syn_flows_total)} / ${number(status.resolved_flows_total)} / ${number(status.unidentified_flows_total)}`],
    ['活跃 / 待识别连接', `${number(status.active_flows)} / ${number(status.pending_flows)} · ${bytes(status.pending_prefix_bytes)}`],
    ['启动时缺口', `${number(status.preexisting_gap_packets)} 包 · ${bytes(status.preexisting_gap_bytes)}`],
    ['流表 / 前缀预算丢弃', `${number(status.flow_limit_drops)} / ${number(status.pending_budget_drops)}`],
    ['来源 IP 采集端口', status.inbound_ports?.length ? `IPv4 TCP ${status.inbound_ports.join(' / ')}` : '未配置'],
    ['入站握手跟踪超限', number(status.source_limit_drops)],
    ['运行时长', `${number(status.uptime_sec)} 秒`],
    ['最近落库', flushed],
    ['SQLite 占用（含 WAL）', bytes(status.db_size_bytes)]
  ]);
}

function selectDomainTab(tab) {
  state.domainTab = tab;
  const isRank = tab === 'domains';
  $('domainsPane').hidden = !isRank;
  $('recentPane').hidden = isRank;
  $('tabDomainsBtn').setAttribute('aria-pressed', isRank);
  $('tabRecentBtn').setAttribute('aria-pressed', !isRank);
  setText('domainDescription', isRank ? '按出站流量排序，选择域名查看子域名明细。' : '最近 150 条完整域名记录，使用独立保留期。');
  if (isRank) renderDomains();
  else {
    renderRecent();
    refresh();
  }
}

for (const button of presets) button.addEventListener('click', () => {
  state.preset = button.dataset.preset;
  state.drill = null;
  $('dateControl').open = false;
  refresh();
});

$('dateControl').addEventListener('toggle', () => {
  if (!$('dateControl').open) return;
  const { from, to } = currentRange();
  $('fromInput').value = dateInput(from);
  $('toInput').value = dateInput(to);
  $('dateError').hidden = true;
});

$('dateForm').addEventListener('submit', (event) => {
  event.preventDefault();
  const from = Math.floor(Date.parse($('fromInput').value + '+08:00') / 1000);
  const to = Math.floor(Date.parse($('toInput').value + '+08:00') / 1000);
  if (!Number.isFinite(from) || !Number.isFinite(to) || from > to) {
    setText('dateError', '开始时间须早于或等于结束时间');
    $('dateError').hidden = false;
    return;
  }
  Object.assign(state, { preset: 'custom', from, to, drill: null });
  $('dateControl').open = false;
  refresh();
});

$('sourceForm').addEventListener('submit', (event) => {
  event.preventDefault();
  const ip = $('sourceFilter').value.trim();
  if (ip && (!/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(ip)
    || ip.split('.').some((octet) => Number(octet) > 255))) {
    setText('sourceError', '请输入完整 IPv4 地址，例如 203.0.113.8');
    $('sourceError').hidden = false;
    return;
  }
  state.searchIp = ip;
  $('sourceError').hidden = true;
  refresh();
});

$('blocklistToggle').addEventListener('click', async () => {
  if (!blocklistStatus || blocklistSaving) return;
  blocklistSaving = true;
  $('blocklistToggle').disabled = true;
  setText('blocklistStatus', '正在提交防火墙设置');
  try {
    const response = await fetch('/api/blocklist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Audit-Action': 'blocklist' },
      body: JSON.stringify({ enabled: !blocklistStatus.enabled })
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
  } catch (error) {
    setText('blocklistStatus', `设置失败 · ${error.message}`);
    $('blocklistToggle').disabled = false;
    return;
  } finally {
    blocklistSaving = false;
  }
  await refresh();
});

$('dropHits').addEventListener('toggle', () => loadDropHits(true));

$('sourceFilter').addEventListener('input', () => {
  $('sourceError').hidden = true;
  if (!$('sourceFilter').value && state.searchIp) {
    state.searchIp = '';
    refresh();
  }
});

$('domainsBody').addEventListener('click', (event) => {
  const trend = event.target.closest('[data-trend-root]');
  if (trend) {
    trendDomain = trend.dataset.trendRoot;
    domainTimeline = [];
    refresh();
    $('trendTitle').scrollIntoView({ block: 'center' });
    return;
  }
  const button = event.target.closest('[data-root]');
  if (!button) return;
  state.expandedRoot = state.expandedRoot === button.dataset.root ? null : button.dataset.root;
  renderDomains();
});

$('resetTrendDomain').addEventListener('click', () => {
  trendDomain = null;
  renderCurrentChart();
  refresh();
});
$('sourceMapCanvas').addEventListener('pointermove', describeSourceMap);
$('sourceMapCanvas').addEventListener('pointerdown', describeSourceMap);
$('sourceMapCanvas').addEventListener('pointerleave', () => {
  focusedRegion = null;
  setText('sourceMapDetail', '指向或点按地区查看流量');
});
new ResizeObserver(drawSourceMap).observe($('sourceMapCanvas'));

$('drillBadge').addEventListener('click', () => {
  state.drill = null;
  refresh();
});
$('refreshBtn').addEventListener('click', refresh);
$('domainFilter').addEventListener('input', () => state.domainTab === 'domains' ? renderDomains() : renderRecent());
$('tabDomainsBtn').addEventListener('click', () => selectDomainTab('domains'));
$('tabRecentBtn').addEventListener('click', () => selectDomainTab('recent'));

const timelineSvg = $('timelineSvg');
timelineSvg.addEventListener('pointermove', (event) => {
  const index = chartIndex(event);
  if (index < 0) closeTooltip();
  else showChartPoint(index, event.clientX, event.clientY);
});
timelineSvg.addEventListener('pointerleave', closeTooltip);
timelineSvg.addEventListener('blur', closeTooltip);
timelineSvg.addEventListener('click', (event) => {
  const index = chartIndex(event);
  if (index >= 0) drillChart(index);
});
timelineSvg.addEventListener('keydown', (event) => {
  if (!chart) return;
  if (event.key === 'Enter' && chart.selected >= 0) drillChart(chart.selected);
  if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
  event.preventDefault();
  const delta = event.key === 'ArrowRight' ? 1 : -1;
  const index = Math.min(chart.points.length - 1, Math.max(0, chart.selected + delta));
  const rect = timelineSvg.getBoundingClientRect();
  showChartPoint(index, rect.left + chart.left + chart.slotWidth * (index + 0.5), rect.top + chart.top);
});

new ResizeObserver(() => {
  if (state.view === 'overview' && state.overview) renderCurrentChart();
}).observe($('chartBox'));

addEventListener('hashchange', showView);
document.addEventListener('click', (event) => {
  if ($('dateControl').open && !$('dateControl').contains(event.target)) $('dateControl').open = false;
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && $('dateControl').open) {
    $('dateControl').open = false;
    $('dateControl').querySelector('summary').focus();
  }
});
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) refresh();
});

showView();
setInterval(() => {
  if (!document.hidden) refresh();
}, 30000);

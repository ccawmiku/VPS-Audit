use crate::collector::domain::{TrafficKind, UNIDENTIFIED_DOMAIN, service_label, traffic_kind};
use crate::collector::{CollectorStatus, FlushBatch, align_bucket, unix_now};
use crate::geo::{CountryDb, country_code};
use rusqlite::{Connection, OpenFlags, params};
use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, RwLock, mpsc::Receiver};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

#[derive(Debug, Clone, Serialize)]
pub struct OverviewSummary {
    pub from_ts: i64,
    pub to_ts: i64,
    pub step_secs: i64,
    pub total_tx_bytes: u64,
    pub total_rx_bytes: u64,
    pub total_conns: u64,
    pub unidentified_tx_bytes: u64,
    pub unidentified_rx_bytes: u64,
    pub unidentified_ratio_pct: f64,
    pub active_root_domains: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelinePoint {
    pub ts: i64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub unidentified_bytes: u64,
    pub conn_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainRankRow {
    pub root_domain: String,
    pub service_label: Option<&'static str>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub total_bytes: u64,
    pub conn_count: u64,
    pub share_pct: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverviewResponse {
    pub summary: OverviewSummary,
    pub timeline: Vec<TimelinePoint>,
    pub domains: Vec<DomainRankRow>,
    pub traffic_types: Vec<TrafficShare>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrafficShare {
    pub kind: TrafficKind,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubdomainDetailRow {
    pub full_domain: String,
    pub ech_ext: bool,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub total_bytes: u64,
    pub conn_count: u64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecentDomainRow {
    pub full_domain: String,
    pub root_domain: String,
    pub service_label: Option<&'static str>,
    pub ech_ext: bool,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub conn_count: u64,
    pub last_seen: i64,
}

#[derive(Debug, Default, Serialize)]
pub struct SourcesResponse {
    pub unique_ips: u64,
    pub total_conns: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub latest_seen: Option<i64>,
    pub regions: Option<Vec<SourceRegion>>,
    pub rows: Vec<SourceRankRow>,
}

#[derive(Debug, Serialize)]
pub struct SourceRegion {
    pub country_code: Option<String>,
    pub unique_ips: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct SourceRankRow {
    pub ip: String,
    pub country_code: Option<String>,
    pub ports: String,
    pub conn_count: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub last_seen: i64,
}

pub fn init_schema(db_path: &Path) -> rusqlite::Result<()> {
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let mut conn = open_rw(db_path)?;
    configure_connection(&conn)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS traffic_buckets (
            bucket_ts   INTEGER NOT NULL,
            root_domain TEXT    NOT NULL,
            tx_bytes    INTEGER NOT NULL DEFAULT 0,
            rx_bytes    INTEGER NOT NULL DEFAULT 0,
            conn_count  INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket_ts, root_domain)
        );
        CREATE INDEX IF NOT EXISTS idx_buckets_domain_ts
            ON traffic_buckets(root_domain, bucket_ts);

        CREATE TABLE IF NOT EXISTS recent_domains (
            bucket_ts   INTEGER NOT NULL,
            full_domain TEXT    NOT NULL,
            root_domain TEXT    NOT NULL,
            ech_ext     INTEGER NOT NULL DEFAULT 0,
            tx_bytes    INTEGER NOT NULL DEFAULT 0,
            rx_bytes    INTEGER NOT NULL DEFAULT 0,
            conn_count  INTEGER NOT NULL DEFAULT 0,
            last_seen   INTEGER NOT NULL,
            PRIMARY KEY (bucket_ts, full_domain)
        );
        CREATE INDEX IF NOT EXISTS idx_recent_root_ts
            ON recent_domains(root_domain, bucket_ts);
        CREATE INDEX IF NOT EXISTS idx_recent_last_seen
            ON recent_domains(last_seen DESC);

        CREATE TABLE IF NOT EXISTS source_buckets (
            bucket_ts    INTEGER NOT NULL,
            inbound_port INTEGER NOT NULL,
            source_ip    INTEGER NOT NULL,
            conn_count   INTEGER NOT NULL,
            last_seen    INTEGER NOT NULL,
            upload_bytes INTEGER NOT NULL DEFAULT 0,
            download_bytes INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket_ts, inbound_port, source_ip)
        ) WITHOUT ROWID;
        "#,
    )?;
    for column in ["upload_bytes", "download_bytes"] {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('source_buckets') WHERE name = ?1)",
            [column],
            |row| row.get(0),
        )?;
        if !exists {
            tx.execute_batch(&format!(
                "ALTER TABLE source_buckets ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0"
            ))?;
        }
    }
    tx.commit()
}

fn open_rw(db_path: &Path) -> rusqlite::Result<Connection> {
    Connection::open(db_path)
}

fn open_ro(db_path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_millis(5000))?;
    Ok(conn)
}

fn configure_connection(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(Duration::from_millis(5000))?;
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = MEMORY;
        "#,
    )?;
    Ok(())
}

pub fn start_writer_thread(
    db_path: std::path::PathBuf,
    rx: Receiver<FlushBatch>,
    recent_retention_hours: i64,
    bucket_retention_days: i64,
    status: Arc<RwLock<CollectorStatus>>,
    worker_failure: Arc<Notify>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let mut conn = open_rw(&db_path).map_err(std::io::Error::other)?;
    configure_connection(&conn).map_err(std::io::Error::other)?;
    std::thread::Builder::new()
        .name("sqlite-writer".to_string())
        .spawn(move || {
            let mut last_cleanup = Instant::now();
            let cleanup_interval = Duration::from_secs(3600);

            while let Ok(batch) = rx.recv() {
                if !batch.is_empty() {
                    if let Err(e) = write_batch(&mut conn, &batch) {
                        tracing::error!(error = %e, "failed to flush SQLite batch; restarting service");
                        worker_failure.notify_one();
                        return;
                    }
                    if let Ok(mut guard) = status.write() {
                        guard.last_flush_at = Some(unix_now());
                    }
                }
                if last_cleanup.elapsed() >= cleanup_interval {
                    last_cleanup = Instant::now();
                    if let Err(e) =
                        cleanup_old_rows(&conn, unix_now(), recent_retention_hours, bucket_retention_days)
                    {
                        tracing::warn!(error = %e, "SQLite retention cleanup failed");
                    }
                }
            }

            // Final WAL checkpoint on clean shutdown
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
            tracing::info!("SQLite writer thread exited cleanly");
        })
}

pub fn write_batch(conn: &mut Connection, batch: &FlushBatch) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    {
        let mut stmt_bucket = tx.prepare_cached(
            r#"
            INSERT INTO traffic_buckets (bucket_ts, root_domain, tx_bytes, rx_bytes, conn_count)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(bucket_ts, root_domain) DO UPDATE SET
                tx_bytes   = tx_bytes   + excluded.tx_bytes,
                rx_bytes   = rx_bytes   + excluded.rx_bytes,
                conn_count = conn_count + excluded.conn_count
            "#,
        )?;
        for ((bucket_ts, root_domain), acc) in &batch.buckets {
            stmt_bucket.execute(params![
                bucket_ts,
                root_domain,
                acc.tx_bytes as i64,
                acc.rx_bytes as i64,
                acc.conn_count as i64,
            ])?;
        }
    }

    {
        let mut stmt_recent = tx.prepare_cached(
            r#"
            INSERT INTO recent_domains (
                bucket_ts, full_domain, root_domain, ech_ext, tx_bytes, rx_bytes, conn_count, last_seen
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(bucket_ts, full_domain) DO UPDATE SET
                ech_ext    = MAX(ech_ext, excluded.ech_ext),
                tx_bytes   = tx_bytes   + excluded.tx_bytes,
                rx_bytes   = rx_bytes   + excluded.rx_bytes,
                conn_count = conn_count + excluded.conn_count,
                last_seen  = MAX(last_seen, excluded.last_seen)
            "#,
        )?;
        for (key, acc) in &batch.recent {
            stmt_recent.execute(params![
                key.bucket_ts,
                key.full_domain,
                acc.root_domain,
                if acc.ech_ext { 1i64 } else { 0i64 },
                acc.tx_bytes as i64,
                acc.rx_bytes as i64,
                acc.conn_count as i64,
                acc.last_seen,
            ])?;
        }
    }

    if !batch.sources.is_empty() {
        let mut stmt_source = tx.prepare_cached(
            r#"
            INSERT INTO source_buckets (
                bucket_ts, inbound_port, source_ip, conn_count, last_seen, upload_bytes, download_bytes
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(bucket_ts, inbound_port, source_ip) DO UPDATE SET
                conn_count = conn_count + excluded.conn_count,
                last_seen  = MAX(last_seen, excluded.last_seen),
                upload_bytes = upload_bytes + excluded.upload_bytes,
                download_bytes = download_bytes + excluded.download_bytes
            "#,
        )?;
        for ((bucket, port, ip), acc) in &batch.sources {
            stmt_source.execute(params![
                bucket,
                port,
                u32::from(*ip),
                acc.conn_count as i64,
                acc.last_seen,
                acc.upload_bytes as i64,
                acc.download_bytes as i64
            ])?;
        }
    }

    tx.commit()
}

pub fn cleanup_old_rows(
    conn: &Connection,
    now_ts: i64,
    recent_hours: i64,
    bucket_days: i64,
) -> rusqlite::Result<()> {
    let recent_cutoff = now_ts - recent_hours.max(1) * 3600;
    let bucket_cutoff = now_ts - bucket_days.max(1) * 86_400;
    conn.execute(
        "DELETE FROM recent_domains WHERE bucket_ts < ?1",
        params![recent_cutoff],
    )?;
    conn.execute(
        "DELETE FROM traffic_buckets WHERE bucket_ts < ?1",
        params![bucket_cutoff],
    )?;
    conn.execute(
        "DELETE FROM source_buckets WHERE bucket_ts < ?1",
        params![bucket_cutoff],
    )?;
    Ok(())
}

pub fn query_overview(
    db_path: &Path,
    from_ts: i64,
    to_ts: i64,
    step_secs: i64,
) -> rusqlite::Result<OverviewResponse> {
    let mut conn = open_ro(db_path)?;
    let snapshot = conn.transaction()?;
    let step = step_secs.max(300);
    let from_bucket = align_bucket(from_ts);
    let to_bucket = align_bucket(to_ts);

    // Use the same snapshot and whole buckets for the ranking and timeline.
    let mut stmt_dom = snapshot.prepare(
        r#"
        SELECT
            root_domain,
            COALESCE(SUM(tx_bytes), 0) AS tx,
            COALESCE(SUM(rx_bytes), 0) AS rx,
            COALESCE(SUM(conn_count), 0) AS conns
        FROM traffic_buckets
        WHERE bucket_ts >= ?1 AND bucket_ts <= ?2
        GROUP BY root_domain
        ORDER BY (tx + rx) DESC, conns DESC
        "#,
    )?;

    let mut raw_domains = Vec::new();
    let mut total_tx: u64 = 0;
    let mut total_rx: u64 = 0;
    let mut total_conns: u64 = 0;
    let mut unid_tx: u64 = 0;
    let mut unid_rx: u64 = 0;

    let rows = stmt_dom.query_map(params![from_bucket, to_bucket], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?.max(0) as u64,
            row.get::<_, i64>(2)?.max(0) as u64,
            row.get::<_, i64>(3)?.max(0) as u64,
        ))
    })?;

    let mut types = HashMap::new();
    for item in rows {
        let (root, tx, rx, conns) = item?;
        total_tx += tx;
        total_rx += rx;
        total_conns += conns;
        if tx + rx > 0 {
            *types.entry(traffic_kind(&root)).or_insert(0) += tx + rx;
        }
        if root == UNIDENTIFIED_DOMAIN {
            unid_tx += tx;
            unid_rx += rx;
        }
        raw_domains.push((root, tx, rx, conns));
    }

    let grand_total = (total_tx + total_rx).max(1) as f64;
    let active_root_domains =
        raw_domains.len() - usize::from(raw_domains.iter().any(|row| row.0 == UNIDENTIFIED_DOMAIN));
    let mut traffic_types: Vec<_> = types
        .into_iter()
        .map(|(kind, total_bytes)| TrafficShare { kind, total_bytes })
        .collect();
    traffic_types.sort_unstable_by(|a, b| {
        b.total_bytes
            .cmp(&a.total_bytes)
            .then_with(|| a.kind.cmp(&b.kind))
    });

    let domains: Vec<DomainRankRow> = raw_domains
        .into_iter()
        .take(200)
        .map(|(root, tx, rx, conns)| {
            let total = tx + rx;
            let share_pct = if total_tx + total_rx == 0 {
                0.0
            } else {
                (total as f64 / grand_total) * 100.0
            };
            let label = service_label(&root);
            DomainRankRow {
                root_domain: root,
                service_label: label,
                tx_bytes: tx,
                rx_bytes: rx,
                total_bytes: total,
                conn_count: conns,
                share_pct,
            }
        })
        .collect();

    // 2. Time-series rollup
    let mut stmt_tl = snapshot.prepare(
        r#"
        SELECT
            (bucket_ts / ?3) * ?3 AS slot_ts,
            COALESCE(SUM(tx_bytes), 0) AS tx,
            COALESCE(SUM(rx_bytes), 0) AS rx,
            COALESCE(SUM(CASE WHEN root_domain = ?4 THEN tx_bytes + rx_bytes ELSE 0 END), 0) AS unid,
            COALESCE(SUM(conn_count), 0) AS conns
        FROM traffic_buckets
        WHERE bucket_ts >= ?1 AND bucket_ts <= ?2
        GROUP BY slot_ts
        ORDER BY slot_ts ASC
        "#,
    )?;

    let tl_rows = stmt_tl.query_map(
        params![from_bucket, to_bucket, step, UNIDENTIFIED_DOMAIN],
        |row| {
            Ok(TimelinePoint {
                ts: row.get(0)?,
                tx_bytes: row.get::<_, i64>(1)?.max(0) as u64,
                rx_bytes: row.get::<_, i64>(2)?.max(0) as u64,
                unidentified_bytes: row.get::<_, i64>(3)?.max(0) as u64,
                conn_count: row.get::<_, i64>(4)?.max(0) as u64,
            })
        },
    )?;

    let mut timeline = Vec::new();
    for item in tl_rows {
        timeline.push(item?);
    }

    let unidentified_ratio_pct = if total_tx + total_rx == 0 {
        0.0
    } else {
        ((unid_tx + unid_rx) as f64 / (total_tx + total_rx) as f64) * 100.0
    };

    Ok(OverviewResponse {
        summary: OverviewSummary {
            from_ts,
            to_ts,
            step_secs: step,
            total_tx_bytes: total_tx,
            total_rx_bytes: total_rx,
            total_conns,
            unidentified_tx_bytes: unid_tx,
            unidentified_rx_bytes: unid_rx,
            unidentified_ratio_pct,
            active_root_domains,
        },
        timeline,
        domains,
        traffic_types,
    })
}

pub fn query_domain_details(
    db_path: &Path,
    root_domain: &str,
    from_ts: i64,
    to_ts: i64,
) -> rusqlite::Result<Vec<SubdomainDetailRow>> {
    let conn = open_ro(db_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT
            full_domain,
            MAX(ech_ext) AS ech,
            COALESCE(SUM(tx_bytes), 0) AS tx,
            COALESCE(SUM(rx_bytes), 0) AS rx,
            COALESCE(SUM(conn_count), 0) AS conns,
            MAX(last_seen) AS last_seen
        FROM recent_domains
        WHERE root_domain = ?1 AND bucket_ts >= ?2 AND bucket_ts <= ?3
        GROUP BY full_domain
        ORDER BY (tx + rx) DESC, last_seen DESC
        LIMIT 100
        "#,
    )?;

    let rows = stmt.query_map(
        params![root_domain, align_bucket(from_ts), align_bucket(to_ts)],
        |row| {
            let tx = row.get::<_, i64>(2)?.max(0) as u64;
            let rx = row.get::<_, i64>(3)?.max(0) as u64;
            Ok(SubdomainDetailRow {
                full_domain: row.get(0)?,
                ech_ext: row.get::<_, i64>(1)? > 0,
                tx_bytes: tx,
                rx_bytes: rx,
                total_bytes: tx + rx,
                conn_count: row.get::<_, i64>(4)?.max(0) as u64,
                last_seen: row.get(5)?,
            })
        },
    )?;

    let mut out = Vec::new();
    for item in rows {
        out.push(item?);
    }
    Ok(out)
}

pub fn query_recent(db_path: &Path, limit: usize) -> rusqlite::Result<Vec<RecentDomainRow>> {
    let conn = open_ro(db_path)?;
    let lim = (limit.clamp(1, 500)) as i64;
    let mut stmt = conn.prepare(
        r#"
        SELECT
            full_domain,
            root_domain,
            ech_ext,
            tx_bytes,
            rx_bytes,
            conn_count,
            last_seen
        FROM recent_domains
        ORDER BY last_seen DESC
        LIMIT ?1
        "#,
    )?;

    let rows = stmt.query_map(params![lim], |row| {
        let full: String = row.get(0)?;
        let root: String = row.get(1)?;
        let label = service_label(&full).or_else(|| service_label(&root));
        Ok(RecentDomainRow {
            full_domain: full,
            root_domain: root,
            service_label: label,
            ech_ext: row.get::<_, i64>(2)? > 0,
            tx_bytes: row.get::<_, i64>(3)?.max(0) as u64,
            rx_bytes: row.get::<_, i64>(4)?.max(0) as u64,
            conn_count: row.get::<_, i64>(5)?.max(0) as u64,
            last_seen: row.get(6)?,
        })
    })?;

    let mut out = Vec::new();
    for item in rows {
        out.push(item?);
    }
    Ok(out)
}

pub fn query_sources(
    db_path: &Path,
    from_ts: i64,
    to_ts: i64,
    ip: Option<Ipv4Addr>,
    country_db: Option<&CountryDb>,
) -> rusqlite::Result<SourcesResponse> {
    const RANK_LIMIT: usize = 200;
    let conn = open_ro(db_path)?;
    let mut stmt = conn.prepare(
        r#"
        WITH ranked AS (
            SELECT source_ip, GROUP_CONCAT(DISTINCT inbound_port) AS ports,
                   SUM(conn_count) AS conns, MAX(last_seen) AS last_seen,
                   SUM(upload_bytes) AS upload, SUM(download_bytes) AS download
            FROM source_buckets
            WHERE bucket_ts BETWEEN ?1 AND ?2 AND (?3 IS NULL OR source_ip = ?3)
            GROUP BY source_ip
        )
        SELECT source_ip, ports, conns, last_seen, upload, download,
               COUNT(*) OVER (), SUM(conns) OVER (), MAX(last_seen) OVER (),
               SUM(upload) OVER (), SUM(download) OVER ()
        FROM ranked
        ORDER BY (upload + download) DESC, conns DESC, last_seen DESC, source_ip
        LIMIT ?4
        "#,
    )?;
    let mut rows = stmt.query(params![
        align_bucket(from_ts),
        align_bucket(to_ts),
        ip.map(u32::from),
        if country_db.is_some() {
            -1
        } else {
            RANK_LIMIT as i64
        }
    ])?;
    let mut result = SourcesResponse::default();
    let mut regions = HashMap::<Option<String>, (u64, u64)>::new();
    while let Some(row) = rows.next()? {
        if result.rows.is_empty() {
            result.unique_ips = row.get::<_, i64>(6)? as u64;
            result.total_conns = row.get::<_, i64>(7)? as u64;
            result.latest_seen = row.get(8)?;
            result.upload_bytes = row.get::<_, i64>(9)? as u64;
            result.download_bytes = row.get::<_, i64>(10)? as u64;
        }
        let ip = Ipv4Addr::from(row.get::<_, u32>(0)?);
        let upload_bytes = row.get::<_, i64>(4)? as u64;
        let download_bytes = row.get::<_, i64>(5)? as u64;
        let location = country_db.and_then(|db| country_code(db, ip));
        if country_db.is_some() {
            let (ips, bytes) = regions.entry(location.clone()).or_default();
            *ips += 1;
            *bytes += upload_bytes + download_bytes;
        }
        if result.rows.len() < RANK_LIMIT {
            result.rows.push(SourceRankRow {
                ip: ip.to_string(),
                country_code: location,
                ports: row.get(1)?,
                conn_count: row.get::<_, i64>(2)? as u64,
                last_seen: row.get(3)?,
                upload_bytes,
                download_bytes,
            });
        }
    }
    result.regions = country_db.map(|_| {
        let mut regions: Vec<_> = regions
            .into_iter()
            .map(|(country_code, (unique_ips, total_bytes))| SourceRegion {
                country_code,
                unique_ips,
                total_bytes,
            })
            .collect();
        regions.sort_unstable_by(|a, b| {
            b.total_bytes
                .cmp(&a.total_bytes)
                .then_with(|| b.unique_ips.cmp(&a.unique_ips))
                .then_with(|| a.country_code.cmp(&b.country_code))
        });
        regions
    });
    Ok(result)
}

pub fn db_size_bytes(db_path: &Path) -> u64 {
    let main = std::fs::metadata(db_path).map(|m| m.len()).unwrap_or(0);
    let wal_path = format!("{}-wal", db_path.display());
    let wal = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
    main + wal
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::{BucketAcc, RecentAcc, RecentKey};

    #[test]
    fn sqlite_writes_queries_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!(
            "vless_audit_test_{}_{}",
            std::process::id(),
            unix_now()
        ));
        let db_path = dir.join("audit.db");
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = Connection::open(&db_path).unwrap();
        legacy.execute_batch(
            "CREATE TABLE source_buckets (
                bucket_ts INTEGER NOT NULL, inbound_port INTEGER NOT NULL, source_ip INTEGER NOT NULL,
                conn_count INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                PRIMARY KEY (bucket_ts, inbound_port, source_ip)
            ) WITHOUT ROWID;
            INSERT INTO source_buckets VALUES (1794999600, 443, 3405803818, 3, 1794999660);",
        ).unwrap();
        drop(legacy);
        init_schema(&db_path).unwrap();
        init_schema(&db_path).unwrap();
        let migrated = query_sources(&db_path, 1_794_999_600, 1_794_999_600, None, None).unwrap();
        assert_eq!(migrated.total_conns, 3);
        assert_eq!((migrated.upload_bytes, migrated.download_bytes), (0, 0));

        let mut conn = open_rw(&db_path).unwrap();
        configure_connection(&conn).unwrap();

        let bts = 1_795_000_200;
        let mut batch = FlushBatch::default();
        batch.buckets.insert(
            (bts, "youtube.com".into()),
            BucketAcc {
                tx_bytes: 1_000,
                rx_bytes: 50_000,
                conn_count: 2,
            },
        );
        batch.buckets.insert(
            (bts, UNIDENTIFIED_DOMAIN.into()),
            BucketAcc {
                tx_bytes: 500,
                rx_bytes: 2_500,
                conn_count: 1,
            },
        );
        batch.recent.insert(
            RecentKey {
                bucket_ts: bts,
                full_domain: "www.youtube.com".into(),
            },
            RecentAcc {
                root_domain: "youtube.com".into(),
                ech_ext: true,
                tx_bytes: 1_000,
                rx_bytes: 50_000,
                conn_count: 2,
                last_seen: bts + 30,
            },
        );

        let source_ip: Ipv4Addr = "203.0.113.42".parse().unwrap();
        let mut source_batch = FlushBatch::default();
        source_batch.sources.insert(
            (bts, 443, source_ip),
            crate::collector::SourceAcc {
                conn_count: 2,
                last_seen: bts + 5,
                upload_bytes: 100,
                download_bytes: 300,
            },
        );
        write_batch(&mut conn, &source_batch).unwrap();
        let source = batch.sources.entry((bts, 443, source_ip)).or_default();
        source.conn_count = 1;
        source.last_seen = bts + 10;
        source.upload_bytes = 20;
        source.download_bytes = 10;
        let second_ip: Ipv4Addr = "198.51.100.20".parse().unwrap();
        let second_source = batch.sources.entry((bts, 443, second_ip)).or_default();
        second_source.conn_count = 1;
        second_source.last_seen = bts + 12;
        write_batch(&mut conn, &batch).unwrap();

        let sources = query_sources(&db_path, bts, bts + 12, None, None).unwrap();
        assert_eq!(sources.unique_ips, 2);
        assert_eq!(sources.total_conns, 4);
        assert_eq!(sources.latest_seen, Some(bts + 12));
        assert_eq!((sources.upload_bytes, sources.download_bytes), (120, 310));
        assert_eq!(sources.rows[0].ip, "203.0.113.42");
        assert_eq!(sources.rows[0].ports, "443");
        assert_eq!(sources.rows[0].last_seen, bts + 10);
        assert_eq!(
            (sources.rows[0].upload_bytes, sources.rows[0].download_bytes),
            (120, 310)
        );
        let matched = query_sources(&db_path, bts, bts + 12, Some(second_ip), None).unwrap();
        assert_eq!(matched.unique_ips, 1);
        assert_eq!(matched.total_conns, 1);

        let ov = query_overview(&db_path, bts - 300, bts + 300, 300).unwrap();
        assert_eq!(ov.summary.total_tx_bytes, 1_500);
        assert_eq!(ov.summary.total_rx_bytes, 52_500);
        assert_eq!(ov.summary.unidentified_tx_bytes, 500);
        assert_eq!(ov.domains[0].root_domain, "youtube.com");
        assert_eq!(ov.domains[0].service_label, Some("YouTube"));
        assert_eq!(
            ov.traffic_types
                .iter()
                .map(|row| row.total_bytes)
                .sum::<u64>(),
            54_000
        );
        assert_eq!(ov.traffic_types[0].kind, TrafficKind::Video);
        assert_eq!(ov.traffic_types[1].kind, TrafficKind::Unidentified);

        let details = query_domain_details(&db_path, "youtube.com", bts - 300, bts + 300).unwrap();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].full_domain, "www.youtube.com");
        assert!(details[0].ech_ext);

        let inside_bucket = query_overview(&db_path, bts + 1, bts + 2, 300).unwrap();
        assert_eq!(inside_bucket.summary.total_rx_bytes, 52_500);
        assert_eq!(inside_bucket.summary.active_root_domains, 1);
        assert_eq!(inside_bucket.timeline[0].rx_bytes, 52_500);
        assert_eq!(
            query_domain_details(&db_path, "youtube.com", bts + 1, bts + 2)
                .unwrap()
                .len(),
            1
        );

        let recent = query_recent(&db_path, 10).unwrap();
        assert_eq!(recent.len(), 1);

        cleanup_old_rows(&conn, bts + 100 * 3600, 48, 90).unwrap();
        let recent_after = query_recent(&db_path, 10).unwrap();
        assert!(recent_after.is_empty());
        cleanup_old_rows(&conn, bts + 91 * 86_400, 48, 90).unwrap();
        assert!(
            query_sources(&db_path, bts, bts + 300, None, None)
                .unwrap()
                .rows
                .is_empty()
        );

        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

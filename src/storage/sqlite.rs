use crate::collector::domain::{UNIDENTIFIED_DOMAIN, service_label};
use crate::collector::{FlushBatch, unix_now};
use rusqlite::{Connection, OpenFlags, params};
use serde::Serialize;
use std::path::Path;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

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

pub fn init_schema(db_path: &Path) -> rusqlite::Result<()> {
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let conn = open_rw(db_path)?;
    configure_connection(&conn)?;
    conn.execute_batch(
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
        "#,
    )?;
    Ok(())
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
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("sqlite-writer".to_string())
        .spawn(move || {
            let mut conn = match open_rw(&db_path).and_then(|c| {
                configure_connection(&c)?;
                Ok(c)
            }) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "failed to open SQLite writer connection");
                    return;
                }
            };

            let mut last_cleanup = Instant::now();
            let cleanup_interval = Duration::from_secs(3600);

            while let Ok(batch) = rx.recv() {
                if !batch.is_empty() {
                    if let Err(e) = write_batch(&mut conn, &batch) {
                        tracing::error!(error = %e, "failed to flush SQLite batch");
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
    Ok(())
}

pub fn query_overview(
    db_path: &Path,
    from_ts: i64,
    to_ts: i64,
    step_secs: i64,
) -> rusqlite::Result<OverviewResponse> {
    let conn = open_ro(db_path)?;
    let step = step_secs.max(300);

    // 1. Domain ranking across [from_ts, to_ts]
    let mut stmt_dom = conn.prepare(
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

    let rows = stmt_dom.query_map(params![from_ts, to_ts], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?.max(0) as u64,
            row.get::<_, i64>(2)?.max(0) as u64,
            row.get::<_, i64>(3)?.max(0) as u64,
        ))
    })?;

    for item in rows {
        let (root, tx, rx, conns) = item?;
        total_tx += tx;
        total_rx += rx;
        total_conns += conns;
        if root == UNIDENTIFIED_DOMAIN {
            unid_tx += tx;
            unid_rx += rx;
        }
        raw_domains.push((root, tx, rx, conns));
    }

    let grand_total = (total_tx + total_rx).max(1) as f64;
    let active_root_domains = raw_domains.len();

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
    let mut stmt_tl = conn.prepare(
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
        params![from_ts, to_ts, step, UNIDENTIFIED_DOMAIN],
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

    let rows = stmt.query_map(params![root_domain, from_ts, to_ts], |row| {
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
    })?;

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
        let root: String = row.get(1)?;
        let label = service_label(&root);
        Ok(RecentDomainRow {
            full_domain: row.get(0)?,
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
        init_schema(&db_path).unwrap();

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

        write_batch(&mut conn, &batch).unwrap();

        let ov = query_overview(&db_path, bts - 300, bts + 300, 300).unwrap();
        assert_eq!(ov.summary.total_tx_bytes, 1_500);
        assert_eq!(ov.summary.total_rx_bytes, 52_500);
        assert_eq!(ov.summary.unidentified_tx_bytes, 500);
        assert_eq!(ov.domains[0].root_domain, "youtube.com");
        assert_eq!(ov.domains[0].service_label, Some("YouTube"));

        let details = query_domain_details(&db_path, "youtube.com", bts - 300, bts + 300).unwrap();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].full_domain, "www.youtube.com");
        assert!(details[0].ech_ext);

        let recent = query_recent(&db_path, 10).unwrap();
        assert_eq!(recent.len(), 1);

        cleanup_old_rows(&conn, bts + 100 * 3600, 48, 90).unwrap();
        let recent_after = query_recent(&db_path, 10).unwrap();
        assert!(recent_after.is_empty());

        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

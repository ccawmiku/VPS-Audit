mod collector;
mod config;
mod storage;
mod web;

use clap::Parser;
use collector::{CollectorStatus, FlushBatch, start_capture_thread, unix_now};
use config::AppConfig;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, mpsc};
use storage::sqlite::{init_schema, start_writer_thread};
use web::server::{AppState, build_router};

fn resolve_local_ip(cfg: &AppConfig) -> Option<Ipv4Addr> {
    if cfg.web_only {
        return cfg.local_ip;
    }
    if let Some(ip) = cfg.local_ip {
        return Some(ip);
    }
    #[cfg(target_os = "linux")]
    {
        match collector::linux_capture::detect_iface_ipv4(&cfg.iface) {
            Ok(ip) => Some(ip),
            Err(e) => {
                tracing::error!(iface = %cfg.iface, error = %e, "failed to detect interface IPv4");
                None
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vless_audit=info".into()),
        )
        .init();

    let cfg = AppConfig::parse();
    if let Err(e) = init_schema(&cfg.db_path) {
        tracing::error!(db = %cfg.db_path.display(), error = %e, "failed to initialize SQLite schema");
        std::process::exit(1);
    }

    let local_ip = resolve_local_ip(&cfg);
    if !cfg.web_only && local_ip.is_none() {
        tracing::error!("cannot start capture without local IPv4 address (pass --local-ip or check --iface)");
        std::process::exit(1);
    }

    let status = Arc::new(RwLock::new(CollectorStatus::new(
        &cfg,
        local_ip,
        unix_now(),
    )));
    let shutdown = Arc::new(AtomicBool::new(false));
    let (tx_flush, rx_flush) = mpsc::sync_channel::<FlushBatch>(64);

    let writer_handle = start_writer_thread(
        cfg.db_path.clone(),
        rx_flush,
        cfg.recent_retention_hours,
        cfg.bucket_retention_days,
    )
    .unwrap_or_else(|e| {
        tracing::error!(error = %e, "failed to start SQLite writer thread");
        std::process::exit(1);
    });

    let capture_handle = if cfg.web_only {
        tracing::info!(db = %cfg.db_path.display(), "starting in --web-only mode");
        None
    } else {
        let ip = local_ip.expect("checked above");
        match start_capture_thread(
            cfg.clone(),
            ip,
            tx_flush.clone(),
            status.clone(),
            shutdown.clone(),
        ) {
            Ok(h) => {
                tracing::info!(iface = %cfg.iface, local_ip = %ip, "AF_PACKET capture started");
                Some(h)
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to open AF_PACKET capture socket (need CAP_NET_RAW / root)");
                std::process::exit(1);
            }
        }
    };

    drop(tx_flush);

    let app = build_router(AppState {
        db_path: cfg.db_path.clone(),
        status: status.clone(),
    });

    let listener = match tokio::net::TcpListener::bind(cfg.listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(listen = %cfg.listen, error = %e, "failed to bind web listener");
            shutdown.store(true, Ordering::Relaxed);
            if let Some(h) = capture_handle {
                let _ = h.join();
            }
            let _ = writer_handle.join();
            std::process::exit(1);
        }
    };

    tracing::info!(listen = %cfg.listen, db = %cfg.db_path.display(), "web UI listening");

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!(error = %e, "web server error");
    }

    tracing::info!("shutting down...");
    shutdown.store(true, Ordering::Relaxed);
    if let Some(h) = capture_handle {
        let _ = h.join();
    }
    let _ = writer_handle.join();
}

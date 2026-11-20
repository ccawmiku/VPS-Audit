use crate::collector::{BUCKET_SECONDS, CollectorStatus, unix_now};
use crate::geo::CountryDb;
use crate::storage::sqlite::{
    SourcesResponse, TimelinePoint, db_size_bytes, query_domain_details, query_domain_timeline,
    query_overview, query_recent, query_sources,
};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

#[derive(RustEmbed)]
#[folder = "src/web/static/"]
struct StaticAssets;

#[derive(Clone)]
pub struct AppState {
    pub db_path: PathBuf,
    pub status: Arc<RwLock<CollectorStatus>>,
    pub country_db: Option<Arc<CountryDb>>,
}

#[derive(Deserialize)]
pub struct RangeQuery {
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub step: Option<i64>,
}

#[derive(Deserialize)]
pub struct RecentQuery {
    pub limit: Option<usize>,
}

#[derive(Deserialize)]
struct SourcesQuery {
    from: Option<i64>,
    to: Option<i64>,
    ip: Option<Ipv4Addr>,
}

#[derive(Serialize)]
struct StatusResponse {
    #[serde(flatten)]
    collector: CollectorStatus,
    db_size_bytes: u64,
    cf_access_user: Option<String>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/dashboard.css", get(serve_stylesheet))
        .route("/dashboard.js", get(serve_script))
        .route("/world-map.json", get(serve_world_map))
        .route("/healthz", get(healthz))
        .route("/api/overview", get(api_overview))
        .route("/api/domain/{root}/details", get(api_domain_details))
        .route("/api/domain/{root}/timeline", get(api_domain_timeline))
        .route("/api/recent", get(api_recent))
        .route("/api/sources", get(api_sources))
        .route("/api/status", get(api_status))
        .layer(axum::middleware::map_response(
            |mut response: Response| async {
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    header::HeaderValue::from_static("no-store"),
                );
                response
            },
        ))
        .with_state(state)
}

async fn healthz(State(state): State<AppState>) -> (StatusCode, &'static str) {
    if state.status.read().is_ok_and(|s| s.running || s.web_only) {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "collector unavailable")
    }
}

async fn serve_index() -> Response {
    serve_asset("index.html", "text/html; charset=utf-8")
}

async fn serve_stylesheet() -> Response {
    serve_asset("dashboard.css", "text/css; charset=utf-8")
}

async fn serve_script() -> Response {
    serve_asset("dashboard.js", "text/javascript; charset=utf-8")
}

async fn serve_world_map() -> Response {
    serve_asset("world-map.json", "application/json")
}

fn serve_asset(path: &str, content_type: &'static str) -> Response {
    match StaticAssets::get(path) {
        Some(file) => ([(header::CONTENT_TYPE, content_type)], file.data).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn normalize_range(q: &RangeQuery) -> (i64, i64, i64) {
    let now = unix_now();
    let to = q.to.unwrap_or(now).clamp(0, now);
    let from = q.from.unwrap_or(to - 24 * 3600).clamp(0, to);
    let default_step = if to - from > 36 * 3600 {
        3600
    } else {
        BUCKET_SECONDS
    };
    let step = q.step.unwrap_or(default_step).clamp(BUCKET_SECONDS, 86_400);
    let step = step - step % BUCKET_SECONDS;
    (from, to, step)
}

async fn api_overview(
    State(state): State<AppState>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<crate::storage::sqlite::OverviewResponse>, (StatusCode, String)> {
    let (from, to, step) = normalize_range(&q);
    let db = state.db_path.clone();
    let res = tokio::task::spawn_blocking(move || query_overview(&db, from, to, step))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(res))
}

async fn api_domain_details(
    State(state): State<AppState>,
    Path(root): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Vec<crate::storage::sqlite::SubdomainDetailRow>>, (StatusCode, String)> {
    let (from, to, _) = normalize_range(&q);
    let db = state.db_path.clone();
    let res = tokio::task::spawn_blocking(move || query_domain_details(&db, &root, from, to))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(res))
}

async fn api_recent(
    State(state): State<AppState>,
    Query(q): Query<RecentQuery>,
) -> Result<Json<Vec<crate::storage::sqlite::RecentDomainRow>>, (StatusCode, String)> {
    let limit = q.limit.unwrap_or(100);
    let db = state.db_path.clone();
    let res = tokio::task::spawn_blocking(move || query_recent(&db, limit))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(res))
}

async fn api_sources(
    State(state): State<AppState>,
    Query(q): Query<SourcesQuery>,
) -> Result<Json<SourcesResponse>, (StatusCode, String)> {
    let (from, to, _) = normalize_range(&RangeQuery {
        from: q.from,
        to: q.to,
        step: None,
    });
    let res = tokio::task::spawn_blocking(move || {
        query_sources(&state.db_path, from, to, q.ip, state.country_db.as_deref())
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(res))
}

async fn api_domain_timeline(
    State(state): State<AppState>,
    Path(root): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Vec<TimelinePoint>>, (StatusCode, String)> {
    let (from, to, step) = normalize_range(&q);
    tokio::task::spawn_blocking(move || {
        query_domain_timeline(&state.db_path, &root, from, to, step)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map(Json)
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn api_status(State(state): State<AppState>, headers: HeaderMap) -> Json<StatusResponse> {
    let collector = state
        .status
        .read()
        .map(|s| s.clone())
        .unwrap_or_else(|_| CollectorStatus {
            instance_name: None,
            running: false,
            web_only: true,
            iface: String::new(),
            local_ip: String::new(),
            inbound_port: None,
            inbound_ports: Vec::new(),
            source_limit_drops: 0,
            started_at: 0,
            uptime_sec: 0,
            socket_packets_total: 0,
            socket_drops_total: 0,
            parsed_packets_total: 0,
            syn_flows_total: 0,
            resolved_flows_total: 0,
            unidentified_flows_total: 0,
            active_flows: 0,
            pending_flows: 0,
            pending_prefix_bytes: 0,
            preexisting_gap_packets: 0,
            preexisting_gap_bytes: 0,
            flow_limit_drops: 0,
            pending_budget_drops: 0,
            last_flush_at: None,
            coverage_note: String::new(),
        });

    let cf_access_user = headers
        .get("Cf-Access-Authenticated-User-Email")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let db = state.db_path.clone();
    let db_bytes = tokio::task::spawn_blocking(move || db_size_bytes(&db))
        .await
        .unwrap_or(0);

    Json(StatusResponse {
        collector,
        db_size_bytes: db_bytes,
        cf_access_user,
    })
}

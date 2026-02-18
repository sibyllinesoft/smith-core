//! Metrics and HTTP server for the policy sync service

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use lazy_static::lazy_static;
use prometheus::{
    register_gauge_vec, register_int_counter_vec, Encoder, GaugeVec, IntCounterVec, TextEncoder,
};
use std::convert::Infallible;
use std::net::SocketAddr;
use tracing::{error, info};

lazy_static! {
    static ref SYNC_TOTAL: IntCounterVec = register_int_counter_vec!(
        "smith_policy_sync_total",
        "Total policy sync operations",
        &["status"]
    )
    .unwrap();
    static ref POLICIES_LOADED: GaugeVec = register_gauge_vec!(
        "smith_policy_sync_policies_loaded",
        "Active policies synced to OPA",
        &[]
    )
    .unwrap();
}

pub fn record_sync(status: &str) {
    SYNC_TOTAL.with_label_values(&[status]).inc();
}

pub fn set_policies_loaded(n: usize) {
    POLICIES_LOADED
        .with_label_values(&[] as &[&str])
        .set(n as f64);
}

/// HTTP metrics and health check server
pub struct MetricsServer {
    addr: SocketAddr,
}

impl MetricsServer {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub async fn start(&self) -> anyhow::Result<tokio::task::JoinHandle<()>> {
        let addr = self.addr;

        let make_svc =
            make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(metrics_handler)) });

        let server = Server::bind(&addr).serve(make_svc);

        info!("Metrics server starting on http://{}/metrics", addr);

        let handle = tokio::spawn(async move {
            if let Err(e) = server.await {
                error!("Metrics server error: {}", e);
            }
        });

        Ok(handle)
    }
}

async fn metrics_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    if req.method() != Method::GET {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body("Method not allowed".into())
            .unwrap());
    }

    match req.uri().path() {
        "/metrics" => {
            let encoder = TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut buffer = Vec::new();

            if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
                error!("Failed to encode metrics: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Failed to encode metrics".into())
                    .unwrap());
            }

            Ok(Response::builder()
                .header("content-type", "text/plain; version=0.0.4")
                .body(buffer.into())
                .unwrap())
        }
        "/health" => Ok(Response::builder().body("OK".into()).unwrap()),
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body("Not found".into())
            .unwrap()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_initialization() {
        let _ = &*SYNC_TOTAL;
        let _ = &*POLICIES_LOADED;
    }

    #[test]
    fn test_metric_functions() {
        record_sync("success");
        record_sync("error");
        set_policies_loaded(5);
    }
}

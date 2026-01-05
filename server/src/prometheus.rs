use anyhow::Result;
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server, StatusCode,
};
use prometheus::{Counter, Gauge, HistogramOpts, HistogramVec, Opts};
use prometheus::{Encoder, Registry, TextEncoder};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};

#[derive(Clone)]
pub struct PrometheusMetrics {
    registry: Arc<Registry>,
    pub connections_total: Counter,
    pub connections_active: Gauge,
    pub bytes_sent_total: Counter,
    pub bytes_received_total: Counter,
    pub packets_sent_total: Counter,
    pub packets_received_total: Counter,
    pub compression_saved_bytes: Counter,
    pub request_duration: HistogramVec,
}

impl PrometheusMetrics {
    pub fn new() -> Result<Self> {
        let registry = Arc::new(Registry::new());

        let connections_total = Counter::with_opts(
            Opts::new("relay_connections_total", "Total number of connections")
                .namespace("oxidize"),
        )?;
        registry.register(Box::new(connections_total.clone()))?;

        let connections_active = Gauge::with_opts(
            Opts::new("relay_connections_active", "Currently active connections")
                .namespace("oxidize"),
        )?;
        registry.register(Box::new(connections_active.clone()))?;

        let bytes_sent_total = Counter::with_opts(
            Opts::new("oxidize_relay_bytes_sent_total", "Total bytes sent").namespace("oxidize"),
        )?;
        registry.register(Box::new(bytes_sent_total.clone()))?;

        let bytes_received_total = Counter::with_opts(
            Opts::new("oxidize_relay_bytes_received_total", "Total bytes received")
                .namespace("oxidize"),
        )?;
        registry.register(Box::new(bytes_received_total.clone()))?;

        let packets_sent_total = Counter::with_opts(
            Opts::new("oxidize_relay_packets_sent_total", "Total packets sent")
                .namespace("oxidize"),
        )?;
        registry.register(Box::new(packets_sent_total.clone()))?;

        let packets_received_total = Counter::with_opts(
            Opts::new("relay_packets_received_total", "Total packets received")
                .namespace("oxidize"),
        )?;
        registry.register(Box::new(packets_received_total.clone()))?;

        let compression_saved_bytes = Counter::with_opts(
            Opts::new(
                "relay_compression_saved_bytes",
                "Bytes saved through compression",
            )
            .namespace("oxidize"),
        )?;
        registry.register(Box::new(compression_saved_bytes.clone()))?;

        let request_duration = HistogramVec::new(
            HistogramOpts::new(
                "relay_request_duration_seconds",
                "Request duration in seconds",
            )
            .namespace("oxidize")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
            &["operation"],
        )?;
        registry.register(Box::new(request_duration.clone()))?;

        Ok(Self {
            registry,
            connections_total,
            connections_active,
            bytes_sent_total,
            bytes_received_total,
            packets_sent_total,
            packets_received_total,
            compression_saved_bytes,
            request_duration,
        })
    }

    pub fn update_from_relay_metrics(&self, stats: &oxidize_common::Stats) {
        self.connections_total
            .inc_by(stats.connections_total as f64);
        self.connections_active.set(stats.connections_active as f64);
        self.bytes_sent_total.inc_by(stats.bytes_sent as f64);
        self.bytes_received_total
            .inc_by(stats.bytes_received as f64);
        self.packets_sent_total.inc_by(stats.packets_sent as f64);
        self.packets_received_total
            .inc_by(stats.packets_received as f64);
        self.compression_saved_bytes
            .inc_by(stats.compression_saved as f64);
    }

    async fn serve_metrics(self, _req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();

        let mut buffer = Vec::new();
        if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
            error!("Failed to encode metrics: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to encode metrics"))
                .unwrap());
        }

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", encoder.format_type())
            .body(Body::from(buffer))
            .unwrap())
    }

    pub async fn start_server(self, addr: SocketAddr) -> Result<()> {
        info!("Starting Prometheus metrics server on {}", addr);

        let make_svc = make_service_fn(move |_conn| {
            let metrics = self.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    let metrics = metrics.clone();
                    async move { metrics.serve_metrics(req).await }
                }))
            }
        });

        let server = Server::bind(&addr).serve(make_svc);

        if let Err(e) = server.await {
            error!("Prometheus server error: {}", e);
        }

        Ok(())
    }
}

impl Default for PrometheusMetrics {
    fn default() -> Self {
        Self::new().expect("Failed to create Prometheus metrics")
    }
}

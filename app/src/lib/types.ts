export interface ConnectionStatus {
    connected: boolean;
    server: string | null;
    ip: string | null;
    original_ip: string | null;
    uptime_secs: number;
    bytes_sent: number;
    bytes_received: number;
    packets_sent: number;
    packets_received: number;
    compression_saved: number;
    latency_ms: number | null;
    // ML metrics from backend
    fec_recovered: number;
    fec_sent: number;
    loss_predictions: number;
    congestion_adjustments: number;
    path_switches: number;
}

export interface Server {
    id: string;
    name: string;
    location: string;
    country_code: string;
    load: number;
    latency_ms: number | null;
}

export interface AppConfig {
    auto_connect: boolean;
}

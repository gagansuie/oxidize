export interface ConnectionStatus {
    connected: boolean;
    server: string | null;
    ip: string | null;
    uptime_secs: number;
    bytes_sent: number;
    bytes_received: number;
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

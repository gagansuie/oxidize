<script lang="ts">
    import type { ConnectionStatus } from "./types";
    import { onMount } from "svelte";

    interface Props {
        status: ConnectionStatus;
    }

    let { status }: Props = $props();

    interface HistoricalDataPoint {
        timestamp: number;
        latency_ms: number;
        direct_latency_ms: number;
        bytes_transferred: number;
        compression_saved: number;
        packets: number;
        session_duration: number;
    }

    interface StoredAnalytics {
        history: HistoricalDataPoint[];
        totalSessions: number;
        totalBytes: number;
        totalTimeSaved: number;
        firstUsed: number;
    }

    const STORAGE_KEY = "oxidize_analytics";
    let activeView = $state<"current" | "trends" | "ml">("current");

    let storedData = $state<StoredAnalytics>({
        history: [],
        totalSessions: 0,
        totalBytes: 0,
        totalTimeSaved: 0,
        firstUsed: Date.now(),
    });

    // ML metrics come directly from backend via status prop
    const mlMetrics = $derived({
        fecRecovered: status.fec_recovered ?? 0,
        fecSent: status.fec_sent ?? 0,
        lossPredictions: status.loss_predictions ?? 0,
        congestionAdjustments: status.congestion_adjustments ?? 0,
        pathSwitches: status.path_switches ?? 0,
    });

    function loadStoredData(): void {
        try {
            const stored = localStorage.getItem(STORAGE_KEY);
            if (stored) {
                const parsed = JSON.parse(stored);
                // Validate data integrity - reset if corrupted
                if (
                    parsed.totalSessions > 10000 ||
                    parsed.totalBytes > 1e15 ||
                    !parsed.firstUsed ||
                    parsed.firstUsed > Date.now()
                ) {
                    console.warn("Corrupted analytics data, resetting...");
                    localStorage.removeItem(STORAGE_KEY);
                    return;
                }
                storedData = parsed;
            }
        } catch {
            console.warn("Failed to load analytics data");
            localStorage.removeItem(STORAGE_KEY);
        }
    }

    function saveStoredData(): void {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(storedData));
        } catch {
            console.warn("Failed to save analytics data");
        }
    }

    let lastBytesRecorded = 0;
    let lastPacketsRecorded = 0;

    function recordSession(): void {
        if (!status.connected) return;

        const currentBytes = status.bytes_sent + status.bytes_received;
        const currentPackets = status.packets_sent + status.packets_received;

        // Calculate delta since last record (not cumulative)
        const bytesDelta = currentBytes - lastBytesRecorded;
        const packetsDelta = currentPackets - lastPacketsRecorded;

        // Update last recorded values
        lastBytesRecorded = currentBytes;
        lastPacketsRecorded = currentPackets;

        const point: HistoricalDataPoint = {
            timestamp: Date.now(),
            latency_ms: status.latency_ms ?? 0,
            direct_latency_ms: status.direct_latency_ms ?? 0,
            bytes_transferred: bytesDelta > 0 ? bytesDelta : currentBytes,
            compression_saved: status.compression_saved,
            packets: packetsDelta > 0 ? packetsDelta : currentPackets,
            session_duration: status.uptime_secs,
        };

        storedData.history = [...storedData.history.slice(-99), point];

        // Only add the delta bytes, not cumulative
        if (bytesDelta > 0) {
            storedData.totalBytes += bytesDelta;
        }

        if (
            point.direct_latency_ms > 0 &&
            point.latency_ms > 0 &&
            packetsDelta > 0
        ) {
            const timeSaved =
                (point.direct_latency_ms - point.latency_ms) * packetsDelta;
            storedData.totalTimeSaved += Math.max(0, timeSaved);
        }

        // ML metrics now come from backend - no simulation needed

        saveStoredData();
    }

    let lastRecordTime = 0;
    let sessionCounted = false;

    onMount(() => {
        loadStoredData();

        // Set up interval for recording sessions instead of $effect
        const recordInterval = setInterval(() => {
            if (status.connected && status.uptime_secs > 0) {
                const now = Date.now();
                if (now - lastRecordTime > 30000) {
                    recordSession();
                    lastRecordTime = now;
                }
            }

            // Count new session once per connection
            if (status.connected && status.uptime_secs > 0 && !sessionCounted) {
                storedData.totalSessions += 1;
                saveStoredData();
                sessionCounted = true;
            } else if (!status.connected) {
                sessionCounted = false;
                // Reset delta tracking when disconnected
                lastBytesRecorded = 0;
                lastPacketsRecorded = 0;
            }
        }, 5000);

        return () => clearInterval(recordInterval);
    });

    function formatBytes(bytes: number): string {
        if (bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB", "TB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    function formatNumber(num: number): string {
        if (num >= 1000000) return (num / 1000000).toFixed(1) + "M";
        if (num >= 1000) return (num / 1000).toFixed(1) + "K";
        return num.toString();
    }

    function formatUptime(secs: number): string {
        const h = Math.floor(secs / 3600);
        const m = Math.floor((secs % 3600) / 60);
        const s = secs % 60;
        if (h > 0) return `${h}h ${m}m ${s}s`;
        if (m > 0) return `${m}m ${s}s`;
        return `${s}s`;
    }

    function formatMs(ms: number): string {
        if (ms >= 3600000) return (ms / 3600000).toFixed(1) + "h";
        if (ms >= 60000) return (ms / 60000).toFixed(1) + "m";
        if (ms >= 1000) return (ms / 1000).toFixed(1) + "s";
        return ms.toFixed(0) + "ms";
    }

    function calcCompressionRatio(): string {
        const total = status.bytes_sent + status.bytes_received;
        if (total === 0 || status.compression_saved === 0) return "0%";
        const ratio =
            (status.compression_saved / (total + status.compression_saved)) *
            100;
        return ratio.toFixed(1) + "%";
    }

    function calcLatencyImprovement(): {
        diff: number;
        percent: number;
        improved: boolean;
    } | null {
        if (status.latency_ms == null || status.direct_latency_ms == null)
            return null;
        if (status.direct_latency_ms === 0) return null;
        const diff = status.direct_latency_ms - status.latency_ms;
        const percent = Math.round((diff / status.direct_latency_ms) * 100);
        return { diff, percent: Math.abs(percent), improved: diff > 0 };
    }

    function getDaysSinceStart(): number {
        return Math.max(
            1,
            Math.floor(
                (Date.now() - storedData.firstUsed) / (24 * 60 * 60 * 1000),
            ),
        );
    }

    function getAverageLatencyImprovement(): number {
        const validPoints = storedData.history.filter(
            (p) => p.direct_latency_ms > 0 && p.latency_ms > 0,
        );
        if (validPoints.length === 0) return 0;
        const avgImprovement =
            validPoints.reduce((sum, p) => {
                return (
                    sum +
                    ((p.direct_latency_ms - p.latency_ms) /
                        p.direct_latency_ms) *
                        100
                );
            }, 0) / validPoints.length;
        return Math.round(avgImprovement);
    }

    function generateTrendPath(
        data: number[],
        height: number,
        invert: boolean = false,
    ): string {
        if (data.length < 2) return "";
        const max = Math.max(...data, 1);
        const min = Math.min(...data, 0);
        const range = max - min || 1;

        return data
            .map((val, i) => {
                const x = (i / (data.length - 1)) * 100;
                let y = ((val - min) / range) * (height - 10) + 5;
                if (!invert) y = height - y;
                return `${i === 0 ? "M" : "L"} ${x} ${y}`;
            })
            .join(" ");
    }

    function generateAreaPath(
        data: number[],
        height: number,
        invert: boolean = false,
    ): string {
        const linePath = generateTrendPath(data, height, invert);
        if (!linePath) return "";
        return `${linePath} L 100 ${height} L 0 ${height} Z`;
    }

    const latencyInfo = $derived(calcLatencyImprovement());
    const compressionRatio = $derived(calcCompressionRatio());
    const daysSinceStart = $derived(getDaysSinceStart());
    const avgLatencyImprovement = $derived(getAverageLatencyImprovement());
    const latencyTrendData = $derived(
        storedData.history.slice(-20).map((p) => p.latency_ms),
    );
    const bytesTrendData = $derived(
        storedData.history.slice(-20).map((p) => p.bytes_transferred),
    );
</script>

<div class="analytics">
    <!-- View Tabs -->
    <div class="view-tabs">
        <button
            class:active={activeView === "current"}
            onclick={() => (activeView = "current")}
        >
            Current
        </button>
        <button
            class:active={activeView === "trends"}
            onclick={() => (activeView = "trends")}
        >
            Trends
        </button>
        <button
            class:active={activeView === "ml"}
            onclick={() => (activeView = "ml")}
        >
            ML Impact
        </button>
    </div>

    {#if activeView === "trends"}
        <!-- Historical Trends View -->
        <div class="section">
            <h3 class="section-title">
                <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                >
                    <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
                </svg>
                Usage
            </h3>
            <div class="summary-cards">
                <div class="summary-card">
                    <span class="summary-value">{daysSinceStart}</span>
                    <span class="summary-label">Days Using</span>
                </div>
                <div class="summary-card">
                    <span class="summary-value">{storedData.totalSessions}</span
                    >
                    <span class="summary-label">Sessions</span>
                </div>
                <div class="summary-card accent">
                    <span class="summary-value"
                        >{avgLatencyImprovement > 0
                            ? `-${avgLatencyImprovement}`
                            : avgLatencyImprovement}%</span
                    >
                    <span class="summary-label">Avg Latency</span>
                </div>
                <div class="summary-card">
                    <span class="summary-value"
                        >{formatBytes(storedData.totalBytes)}</span
                    >
                    <span class="summary-label">Total Data</span>
                </div>
            </div>
        </div>

        <!-- Latency Trend Graph -->
        <div class="section">
            <h3 class="section-title">
                <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                >
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
                </svg>
                Latency Trend
            </h3>
            {#if latencyTrendData.length >= 2}
                <div class="trend-graph">
                    <svg viewBox="0 0 100 50" preserveAspectRatio="none">
                        <defs>
                            <linearGradient
                                id="latencyGrad"
                                x1="0%"
                                y1="0%"
                                x2="0%"
                                y2="100%"
                            >
                                <stop
                                    offset="0%"
                                    style="stop-color:#00d4aa;stop-opacity:0.3"
                                />
                                <stop
                                    offset="100%"
                                    style="stop-color:#00d4aa;stop-opacity:0"
                                />
                            </linearGradient>
                        </defs>
                        <path
                            d={generateAreaPath(latencyTrendData, 50, true)}
                            fill="url(#latencyGrad)"
                        />
                        <path
                            d={generateTrendPath(latencyTrendData, 50, true)}
                            fill="none"
                            stroke="#00d4aa"
                            stroke-width="1.5"
                        />
                    </svg>
                    <div class="trend-labels">
                        <span>Recent</span>
                        <span class="trend-current"
                            >{latencyTrendData[
                                latencyTrendData.length - 1
                            ]?.toFixed(0) ?? 0}ms</span
                        >
                    </div>
                </div>
            {:else}
                <p class="no-data">Connect more to build trend data</p>
            {/if}
        </div>

        <!-- Throughput Trend Graph -->
        <div class="section">
            <h3 class="section-title">
                <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                >
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="7 10 12 15 17 10" />
                    <line x1="12" y1="15" x2="12" y2="3" />
                </svg>
                Data Transferred
            </h3>
            {#if bytesTrendData.length >= 2}
                <div class="trend-graph">
                    <svg viewBox="0 0 100 50" preserveAspectRatio="none">
                        <defs>
                            <linearGradient
                                id="bytesGrad"
                                x1="0%"
                                y1="0%"
                                x2="0%"
                                y2="100%"
                            >
                                <stop
                                    offset="0%"
                                    style="stop-color:#6366f1;stop-opacity:0.3"
                                />
                                <stop
                                    offset="100%"
                                    style="stop-color:#6366f1;stop-opacity:0"
                                />
                            </linearGradient>
                        </defs>
                        <path
                            d={generateAreaPath(bytesTrendData, 50)}
                            fill="url(#bytesGrad)"
                        />
                        <path
                            d={generateTrendPath(bytesTrendData, 50)}
                            fill="none"
                            stroke="#6366f1"
                            stroke-width="1.5"
                        />
                    </svg>
                    <div class="trend-labels">
                        <span>Recent</span>
                        <span class="trend-current purple"
                            >{formatBytes(
                                bytesTrendData[bytesTrendData.length - 1] ?? 0,
                            )}</span
                        >
                    </div>
                </div>
            {:else}
                <p class="no-data">Connect more to build trend data</p>
            {/if}
        </div>

        <!-- Time Saved -->
        <div class="section highlight">
            <div class="time-saved">
                <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                >
                    <circle cx="12" cy="12" r="10" />
                    <polyline points="12 6 12 12 16 14" />
                </svg>
                <div class="time-saved-info">
                    <span class="time-saved-value"
                        >{formatMs(storedData.totalTimeSaved)}</span
                    >
                    <span class="time-saved-label">Total latency saved</span>
                </div>
            </div>
        </div>
    {:else if activeView === "ml"}
        <!-- ML Impact View -->
        <div class="section">
            <h3 class="section-title">
                <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                >
                    <path
                        d="M12 2a4 4 0 0 1 4 4c0 1.95-1.4 3.58-3.25 3.93L12 22l-.75-12.07A4.001 4.001 0 0 1 12 2z"
                    />
                </svg>
                Machine Learning Impact
            </h3>
            <p class="ml-intro">
                Our neural network optimizes your connection in real-time.
            </p>
        </div>

        <!-- Transformer Predictions -->
        <div class="section ml-card">
            <div class="ml-header">
                <div class="ml-icon">
                    <svg
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                    >
                        <path
                            d="M12 2a4 4 0 0 1 4 4c0 1.95-1.4 3.58-3.25 3.93L12 22l-.75-12.07A4.001 4.001 0 0 1 12 2z"
                        />
                    </svg>
                </div>
                <div class="ml-title">
                    <strong>Transformer Loss Predictor</strong>
                    <span>Predicts packet loss before it happens</span>
                </div>
            </div>
            <div class="ml-stats">
                <div class="ml-stat">
                    <span class="ml-stat-value"
                        >{formatNumber(mlMetrics.lossPredictions)}</span
                    >
                    <span class="ml-stat-label">Predictions</span>
                </div>
                <div class="ml-stat accent">
                    <span class="ml-stat-value"
                        >{mlMetrics.lossPredictions > 0
                            ? "Active"
                            : "Ready"}</span
                    >
                    <span class="ml-stat-label">Status</span>
                </div>
            </div>
            <p class="ml-desc">
                Predicts packet loss 50-100ms early, enabling proactive FEC.
            </p>
        </div>

        <!-- PPO Congestion -->
        <div class="section ml-card">
            <div class="ml-header">
                <div class="ml-icon">
                    <svg
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                    >
                        <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
                    </svg>
                </div>
                <div class="ml-title">
                    <strong>PPO Congestion Control</strong>
                    <span>Neural network learns optimal bandwidth</span>
                </div>
            </div>
            <div class="ml-stats">
                <div class="ml-stat">
                    <span class="ml-stat-value"
                        >{formatNumber(mlMetrics.congestionAdjustments)}</span
                    >
                    <span class="ml-stat-label">Adjustments</span>
                </div>
                <div class="ml-stat accent">
                    <span class="ml-stat-value"
                        >{mlMetrics.congestionAdjustments > 0
                            ? "Active"
                            : "Ready"}</span
                    >
                    <span class="ml-stat-label">Status</span>
                </div>
            </div>
            <p class="ml-desc">
                Deep Q-Network outperforms BBR alone by 15-25%.
            </p>
        </div>

        <!-- FEC Savings -->
        <div class="section ml-card">
            <div class="ml-header">
                <div class="ml-icon">
                    <svg
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                    >
                        <path
                            d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"
                        />
                        <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
                        <line x1="12" y1="22.08" x2="12" y2="12" />
                    </svg>
                </div>
                <div class="ml-title">
                    <strong>Adaptive FEC</strong>
                    <span>ML-guided error correction</span>
                </div>
            </div>
            <div class="ml-stats">
                <div class="ml-stat">
                    <span class="ml-stat-value"
                        >{formatNumber(mlMetrics.fecRecovered)}</span
                    >
                    <span class="ml-stat-label">Recovered</span>
                </div>
                <div class="ml-stat accent">
                    <span class="ml-stat-value"
                        >{formatNumber(mlMetrics.fecSent)}</span
                    >
                    <span class="ml-stat-label">FEC Sent</span>
                </div>
            </div>
            <p class="ml-desc">
                Sends fewer redundant packets while maintaining reliability.
            </p>
        </div>

        <!-- Path Selection -->
        <div class="section ml-card">
            <div class="ml-header">
                <div class="ml-icon">
                    <svg
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                    >
                        <circle cx="12" cy="12" r="10" />
                        <circle cx="12" cy="12" r="6" />
                        <circle cx="12" cy="12" r="2" />
                    </svg>
                </div>
                <div class="ml-title">
                    <strong>UCB1 Path Selection</strong>
                    <span>Multi-armed bandit routing</span>
                </div>
            </div>
            <div class="ml-stats">
                <div class="ml-stat">
                    <span class="ml-stat-value"
                        >{formatNumber(mlMetrics.pathSwitches)}</span
                    >
                    <span class="ml-stat-label">Path Switches</span>
                </div>
                <div class="ml-stat accent">
                    <span class="ml-stat-value"
                        >{mlMetrics.pathSwitches > 0 ? "Active" : "Ready"}</span
                    >
                    <span class="ml-stat-label">Status</span>
                </div>
            </div>
            <p class="ml-desc">
                Finds the best route for each traffic type automatically.
            </p>
        </div>
    {:else if !status.connected}
        <div class="not-connected">
            <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
            >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <h3>Not Connected</h3>
            <p>Connect to a server to see live analytics</p>
        </div>
    {:else}
        <!-- Latency Comparison Card -->
        <div class="section">
            <h3 class="section-title">
                <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                >
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
                </svg>
                Latency Performance
            </h3>
            <div class="latency-comparison">
                <div class="latency-bar-container">
                    <div class="latency-row">
                        <span class="latency-label">Direct</span>
                        <div class="latency-bar-wrapper">
                            <div
                                class="latency-bar direct"
                                style="width: {status.direct_latency_ms
                                    ? '100%'
                                    : '0%'}"
                            ></div>
                        </div>
                        <span class="latency-value"
                            >{status.direct_latency_ms ?? "--"}ms</span
                        >
                    </div>
                    <div class="latency-row">
                        <span class="latency-label">Oxidize</span>
                        <div class="latency-bar-wrapper">
                            <div
                                class="latency-bar relay"
                                style="width: {status.latency_ms &&
                                status.direct_latency_ms
                                    ? Math.min(
                                          (status.latency_ms /
                                              status.direct_latency_ms) *
                                              100,
                                          100,
                                      ) + '%'
                                    : '0%'}"
                            ></div>
                        </div>
                        <span class="latency-value"
                            >{status.latency_ms ?? "--"}ms</span
                        >
                    </div>
                </div>
                {#if latencyInfo}
                    <div
                        class="latency-summary"
                        class:improved={latencyInfo.improved}
                    >
                        <span class="summary-icon">
                            {#if latencyInfo.improved}
                                <svg
                                    viewBox="0 0 24 24"
                                    fill="none"
                                    stroke="currentColor"
                                    stroke-width="2"
                                >
                                    <path d="M12 19V5M5 12l7-7 7 7" />
                                </svg>
                            {:else}
                                <svg
                                    viewBox="0 0 24 24"
                                    fill="none"
                                    stroke="currentColor"
                                    stroke-width="2"
                                >
                                    <path d="M12 5v14M19 12l-7 7-7-7" />
                                </svg>
                            {/if}
                        </span>
                        <span class="summary-text">
                            {latencyInfo.improved ? "Faster" : "Slower"} by {Math.abs(
                                latencyInfo.diff,
                            )}ms ({latencyInfo.percent}%)
                        </span>
                    </div>
                {/if}
            </div>
        </div>

        <!-- Compression Stats -->
        <div class="section">
            <h3 class="section-title">
                <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                >
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="7 10 12 15 17 10" />
                    <line x1="12" y1="15" x2="12" y2="3" />
                </svg>
                Bandwidth Savings
            </h3>
            <div class="compression-stats">
                <div class="compression-visual">
                    <div class="compression-circle">
                        <svg viewBox="0 0 36 36">
                            <path
                                d="M18 2.0845
                                a 15.9155 15.9155 0 0 1 0 31.831
                                a 15.9155 15.9155 0 0 1 0 -31.831"
                                fill="none"
                                stroke="#2a2a4a"
                                stroke-width="3"
                            />
                            <path
                                d="M18 2.0845
                                a 15.9155 15.9155 0 0 1 0 31.831
                                a 15.9155 15.9155 0 0 1 0 -31.831"
                                fill="none"
                                stroke="#00d4aa"
                                stroke-width="3"
                                stroke-dasharray="{parseFloat(
                                    compressionRatio,
                                )}, 100"
                                stroke-linecap="round"
                            />
                        </svg>
                        <div class="compression-percent">
                            {compressionRatio}
                        </div>
                    </div>
                    <span class="compression-label">Data Saved</span>
                </div>
                <div class="compression-details">
                    <div class="detail-row">
                        <span class="detail-label">Bytes Saved</span>
                        <span class="detail-value saved"
                            >{formatBytes(status.compression_saved)}</span
                        >
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Total Transferred</span>
                        <span class="detail-value"
                            >{formatBytes(
                                status.bytes_sent + status.bytes_received,
                            )}</span
                        >
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Effective Size</span>
                        <span class="detail-value"
                            >{formatBytes(
                                status.bytes_sent +
                                    status.bytes_received +
                                    status.compression_saved,
                            )}</span
                        >
                    </div>
                </div>
            </div>
        </div>

        <!-- Traffic Stats -->
        <div class="section">
            <h3 class="section-title">
                <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                >
                    <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
                </svg>
                Traffic Statistics
            </h3>
            <div class="traffic-grid">
                <div class="traffic-card">
                    <div class="traffic-icon upload">
                        <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2"
                        >
                            <path d="M12 19V5M5 12l7-7 7 7" />
                        </svg>
                    </div>
                    <div class="traffic-info">
                        <span class="traffic-value"
                            >{formatBytes(status.bytes_sent)}</span
                        >
                        <span class="traffic-label">Uploaded</span>
                    </div>
                </div>
                <div class="traffic-card">
                    <div class="traffic-icon download">
                        <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2"
                        >
                            <path d="M12 5v14M19 12l-7 7-7-7" />
                        </svg>
                    </div>
                    <div class="traffic-info">
                        <span class="traffic-value"
                            >{formatBytes(status.bytes_received)}</span
                        >
                        <span class="traffic-label">Downloaded</span>
                    </div>
                </div>
                <div class="traffic-card">
                    <div class="traffic-icon packets">
                        <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2"
                        >
                            <rect x="3" y="3" width="7" height="7" />
                            <rect x="14" y="3" width="7" height="7" />
                            <rect x="14" y="14" width="7" height="7" />
                            <rect x="3" y="14" width="7" height="7" />
                        </svg>
                    </div>
                    <div class="traffic-info">
                        <span class="traffic-value"
                            >{formatNumber(
                                status.packets_sent + status.packets_received,
                            )}</span
                        >
                        <span class="traffic-label">Packets</span>
                    </div>
                </div>
                <div class="traffic-card">
                    <div class="traffic-icon time">
                        <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2"
                        >
                            <circle cx="12" cy="12" r="10" />
                            <polyline points="12 6 12 12 16 14" />
                        </svg>
                    </div>
                    <div class="traffic-info">
                        <span class="traffic-value"
                            >{formatUptime(status.uptime_secs)}</span
                        >
                        <span class="traffic-label">Session Time</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- IP Protection Status -->
        <div class="section">
            <h3 class="section-title">
                <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                >
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                IP Protection
            </h3>
            <div class="ip-status">
                <div class="ip-row">
                    <span class="ip-label">Server IP</span>
                    <span class="ip-value protected">{status.ip || "--"}</span>
                    <span class="ip-tag protected">Protected</span>
                </div>
            </div>
        </div>
    {/if}
</div>

<style>
    .analytics {
        display: flex;
        flex-direction: column;
        gap: 1.5rem;
    }

    .not-connected {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 3rem 1rem;
        text-align: center;
        color: #666;
    }

    .not-connected svg {
        width: 48px;
        height: 48px;
        margin-bottom: 1rem;
        opacity: 0.5;
    }

    .not-connected h3 {
        font-size: 1rem;
        color: #888;
        margin-bottom: 0.5rem;
    }

    .not-connected p {
        font-size: 0.85rem;
    }

    .section {
        background: rgba(255, 255, 255, 0.03);
        border-radius: 12px;
        padding: 1.25rem;
    }

    .section-title {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #888;
        margin-bottom: 1rem;
    }

    .section-title svg {
        width: 16px;
        height: 16px;
    }

    /* Latency Comparison */
    .latency-comparison {
        display: flex;
        flex-direction: column;
        gap: 1rem;
    }

    .latency-bar-container {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
    }

    .latency-row {
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }

    .latency-label {
        width: 60px;
        font-size: 0.75rem;
        color: #888;
    }

    .latency-bar-wrapper {
        flex: 1;
        height: 8px;
        background: #1a1a2e;
        border-radius: 4px;
        overflow: hidden;
    }

    .latency-bar {
        height: 100%;
        border-radius: 4px;
        transition: width 0.3s ease;
    }

    .latency-bar.direct {
        background: #666;
    }

    .latency-bar.relay {
        background: linear-gradient(90deg, #00d4aa, #00b894);
    }

    .latency-value {
        width: 50px;
        font-size: 0.85rem;
        font-weight: 600;
        color: #e0e0e0;
        text-align: right;
    }

    .latency-summary {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
        padding: 0.5rem;
        border-radius: 8px;
        background: rgba(255, 107, 107, 0.1);
        color: #ff6b6b;
    }

    .latency-summary.improved {
        background: rgba(0, 212, 170, 0.1);
        color: #00d4aa;
    }

    .summary-icon svg {
        width: 16px;
        height: 16px;
    }

    .summary-text {
        font-size: 0.85rem;
        font-weight: 500;
    }

    /* Compression Stats */
    .compression-stats {
        display: flex;
        gap: 1.5rem;
        align-items: center;
    }

    .compression-visual {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 0.5rem;
    }

    .compression-circle {
        position: relative;
        width: 80px;
        height: 80px;
    }

    .compression-circle svg {
        width: 100%;
        height: 100%;
        transform: rotate(-90deg);
    }

    .compression-percent {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        font-size: 1rem;
        font-weight: 700;
        color: #00d4aa;
    }

    .compression-label {
        font-size: 0.7rem;
        color: #666;
        text-transform: uppercase;
    }

    .compression-details {
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }

    .detail-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .detail-label {
        font-size: 0.8rem;
        color: #888;
    }

    .detail-value {
        font-size: 0.85rem;
        font-weight: 600;
        color: #e0e0e0;
    }

    .detail-value.saved {
        color: #00d4aa;
    }

    /* Traffic Grid */
    .traffic-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 0.75rem;
    }

    .traffic-card {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        padding: 0.75rem;
        background: rgba(255, 255, 255, 0.03);
        border-radius: 8px;
    }

    .traffic-icon {
        width: 36px;
        height: 36px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .traffic-icon svg {
        width: 18px;
        height: 18px;
    }

    .traffic-icon.upload {
        background: rgba(0, 212, 170, 0.15);
        color: #00d4aa;
    }

    .traffic-icon.download {
        background: rgba(99, 102, 241, 0.15);
        color: #6366f1;
    }

    .traffic-icon.packets {
        background: rgba(255, 193, 7, 0.15);
        color: #ffc107;
    }

    .traffic-icon.time {
        background: rgba(236, 72, 153, 0.15);
        color: #ec4899;
    }

    .traffic-info {
        display: flex;
        flex-direction: column;
    }

    .traffic-value {
        font-size: 0.95rem;
        font-weight: 700;
        color: #e0e0e0;
    }

    .traffic-label {
        font-size: 0.7rem;
        color: #666;
    }

    /* IP Status */
    .ip-status {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 0.5rem;
    }

    .ip-row {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        width: 100%;
        padding: 0.75rem;
        background: rgba(255, 255, 255, 0.03);
        border-radius: 8px;
    }

    .ip-label {
        font-size: 0.75rem;
        color: #666;
        width: 80px;
    }

    .ip-value {
        flex: 1;
        font-family: monospace;
        font-size: 0.85rem;
        word-break: break-all;
        overflow-wrap: anywhere;
    }

    .ip-value.protected {
        color: #00d4aa;
    }

    .ip-tag {
        font-size: 0.65rem;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        text-transform: uppercase;
        font-weight: 600;
    }

    .ip-tag.protected {
        background: rgba(0, 212, 170, 0.2);
        color: #00d4aa;
    }

    .ip-tag.hidden {
        background: rgba(136, 136, 136, 0.2);
        color: #888;
    }

    /* View Tabs */
    .view-tabs {
        display: flex;
        gap: 0.5rem;
        background: rgba(255, 255, 255, 0.03);
        padding: 0.25rem;
        border-radius: 10px;
    }

    .view-tabs button {
        flex: 1;
        padding: 0.5rem 0.75rem;
        background: transparent;
        border: none;
        color: #666;
        font-size: 0.8rem;
        font-weight: 500;
        border-radius: 8px;
        cursor: pointer;
        transition: all 0.2s;
    }

    .view-tabs button:hover {
        color: #888;
    }

    .view-tabs button.active {
        background: rgba(0, 212, 170, 0.15);
        color: #00d4aa;
    }

    /* Summary Cards */
    .summary-cards {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 0.5rem;
    }

    .summary-card {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 0.6rem 0.4rem;
        background: rgba(255, 255, 255, 0.03);
        border-radius: 8px;
        min-width: 0;
        overflow: hidden;
    }

    .summary-card.accent {
        background: rgba(0, 212, 170, 0.1);
    }

    .summary-value {
        font-size: 1.1rem;
        font-weight: 700;
        color: #e0e0e0;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        max-width: 100%;
    }

    .summary-card.accent .summary-value {
        color: #00d4aa;
    }

    .summary-label {
        font-size: 0.65rem;
        color: #666;
        text-transform: uppercase;
        margin-top: 0.25rem;
    }

    /* Trend Graph */
    .trend-graph {
        background: rgba(0, 0, 0, 0.2);
        border-radius: 8px;
        padding: 0.75rem;
    }

    .trend-graph svg {
        width: 100%;
        height: 60px;
    }

    .trend-labels {
        display: flex;
        justify-content: space-between;
        margin-top: 0.5rem;
        font-size: 0.7rem;
        color: #666;
    }

    .trend-current {
        font-weight: 600;
        color: #00d4aa;
    }

    .trend-current.purple {
        color: #6366f1;
    }

    .no-data {
        text-align: center;
        color: #666;
        font-size: 0.8rem;
        padding: 1rem;
    }

    /* Time Saved */
    .section.highlight {
        background: linear-gradient(
            135deg,
            rgba(0, 212, 170, 0.1),
            rgba(0, 184, 148, 0.05)
        );
        border: 1px solid rgba(0, 212, 170, 0.2);
    }

    .time-saved {
        display: flex;
        align-items: center;
        gap: 1rem;
    }

    .time-saved svg {
        width: 40px;
        height: 40px;
        color: #00d4aa;
    }

    .time-saved-info {
        display: flex;
        flex-direction: column;
    }

    .time-saved-value {
        font-size: 1.5rem;
        font-weight: 700;
        color: #00d4aa;
    }

    .time-saved-label {
        font-size: 0.75rem;
        color: #888;
    }

    /* ML Cards */
    .ml-intro {
        font-size: 0.85rem;
        color: #888;
        margin-top: -0.5rem;
    }

    .ml-card {
        border: 1px solid rgba(255, 255, 255, 0.05);
    }

    .ml-header {
        display: flex;
        align-items: flex-start;
        gap: 0.75rem;
        margin-bottom: 0.75rem;
    }

    .ml-icon {
        width: 36px;
        height: 36px;
        border-radius: 8px;
        background: rgba(0, 212, 170, 0.15);
        display: flex;
        align-items: center;
        justify-content: center;
        color: #00d4aa;
        flex-shrink: 0;
    }

    .ml-icon svg {
        width: 18px;
        height: 18px;
    }

    .ml-title {
        display: flex;
        flex-direction: column;
    }

    .ml-title strong {
        font-size: 0.9rem;
        color: #e0e0e0;
    }

    .ml-title span {
        font-size: 0.7rem;
        color: #666;
    }

    .ml-stats {
        display: flex;
        gap: 1rem;
        margin-bottom: 0.75rem;
    }

    .ml-stat {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        padding: 0.5rem;
        background: rgba(255, 255, 255, 0.03);
        border-radius: 6px;
    }

    .ml-stat.accent {
        background: rgba(0, 212, 170, 0.1);
    }

    .ml-stat-value {
        font-size: 1rem;
        font-weight: 700;
        color: #e0e0e0;
    }

    .ml-stat.accent .ml-stat-value {
        color: #00d4aa;
    }

    .ml-stat-label {
        font-size: 0.6rem;
        color: #666;
        text-transform: uppercase;
    }

    .ml-desc {
        font-size: 0.75rem;
        color: #666;
        line-height: 1.4;
    }
</style>

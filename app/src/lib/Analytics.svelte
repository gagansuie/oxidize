<script lang="ts">
    import type { ConnectionStatus } from "./types";

    interface Props {
        status: ConnectionStatus;
    }

    let { status }: Props = $props();

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

    const latencyInfo = $derived(calcLatencyImprovement());
    const compressionRatio = $derived(calcCompressionRatio());
</script>

<div class="analytics">
    {#if !status.connected}
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
            <p>Connect to a server to see detailed analytics</p>
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
        {#if status.original_ip && status.ip}
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
                        <span class="ip-label">Your Real IP</span>
                        <span class="ip-value original"
                            >{status.original_ip}</span
                        >
                        <span class="ip-tag hidden">Hidden</span>
                    </div>
                    <div class="ip-arrow">
                        <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2"
                        >
                            <path d="M12 5v14M19 12l-7 7-7-7" />
                        </svg>
                    </div>
                    <div class="ip-row">
                        <span class="ip-label">Visible IP</span>
                        <span class="ip-value protected">{status.ip}</span>
                        <span class="ip-tag protected">Protected</span>
                    </div>
                </div>
            </div>
        {/if}
    {/if}
</div>

<style>
    .analytics {
        display: flex;
        flex-direction: column;
        gap: 1rem;
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
        padding: 1rem;
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
    }

    .ip-value.original {
        color: #666;
        text-decoration: line-through;
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

    .ip-tag.hidden {
        background: rgba(255, 107, 107, 0.2);
        color: #ff6b6b;
    }

    .ip-tag.protected {
        background: rgba(0, 212, 170, 0.2);
        color: #00d4aa;
    }

    .ip-arrow {
        color: #00d4aa;
    }

    .ip-arrow svg {
        width: 20px;
        height: 20px;
    }
</style>

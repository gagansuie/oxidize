<script lang="ts">
    import type { ConnectionStatus } from "./types";

    interface Props {
        status: ConnectionStatus;
    }

    let { status }: Props = $props();

    function formatBytes(bytes: number): string {
        if (bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
    }

    function formatUptime(secs: number): string {
        const h = Math.floor(secs / 3600);
        const m = Math.floor((secs % 3600) / 60);
        const s = secs % 60;
        if (h > 0) return `${h}h ${m}m`;
        if (m > 0) return `${m}m ${s}s`;
        return `${s}s`;
    }

    function maskIp(ip: string | null): string {
        if (!ip) return "---";
        const parts = ip.split(".");
        if (parts.length === 4) {
            return `${parts[0]}.${parts[1]}.*.*`;
        }
        return ip.substring(0, 8) + "...";
    }

    function calcLatencyImprovement(): {
        percent: number;
        improved: boolean;
    } | null {
        if (status.latency_ms == null || status.direct_latency_ms == null)
            return null;
        if (status.direct_latency_ms === 0) return null;
        const diff = status.direct_latency_ms - status.latency_ms;
        const percent = Math.round((diff / status.direct_latency_ms) * 100);
        return { percent: Math.abs(percent), improved: diff > 0 };
    }

    const latencyInfo = $derived(calcLatencyImprovement());
</script>

<!-- IP Protection Banner -->
{#if status.original_ip && status.ip && status.original_ip !== status.ip}
    <div class="ip-protection">
        <div class="ip-badge">
            <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
            >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="M9 12l2 2 4-4" />
            </svg>
            <span class="badge-text">IP Protected</span>
        </div>
        <div class="ip-change">
            <span class="ip-old">{maskIp(status.original_ip)}</span>
            <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                class="arrow"
            >
                <path d="M5 12h14M12 5l7 7-7 7" />
            </svg>
            <span class="ip-new">{maskIp(status.ip)}</span>
        </div>
    </div>
{/if}

<!-- Key Value Metrics -->
<div class="value-stats">
    <!-- Latency Improvement -->
    <div class="value-card">
        <div class="value-icon latency">
            <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
            >
                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
            </svg>
        </div>
        <div class="value-content">
            {#if status.latency_ms != null}
                <span class="value-number">{status.latency_ms}ms</span>
                {#if latencyInfo}
                    <span
                        class="value-delta"
                        class:positive={latencyInfo.improved}
                        class:negative={!latencyInfo.improved}
                    >
                        {latencyInfo.improved ? "-" : "+"}{latencyInfo.percent}%
                    </span>
                {/if}
            {:else}
                <span class="value-number">--</span>
            {/if}
            <span class="value-label">Latency</span>
        </div>
    </div>

    <!-- Data Saved -->
    <div class="value-card">
        <div class="value-icon saved">
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
        </div>
        <div class="value-content">
            <span class="value-number"
                >{formatBytes(status.compression_saved)}</span
            >
            <span class="value-label">Saved</span>
        </div>
    </div>

    <!-- Uptime -->
    <div class="value-card">
        <div class="value-icon uptime">
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
        <div class="value-content">
            <span class="value-number">{formatUptime(status.uptime_secs)}</span>
            <span class="value-label">Uptime</span>
        </div>
    </div>
</div>

<!-- Transfer Stats -->
<div class="transfer-stats">
    <div class="transfer-item">
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
        >
            <path d="M12 19V5M5 12l7-7 7 7" />
        </svg>
        <span class="transfer-value">{formatBytes(status.bytes_sent)}</span>
        <span class="transfer-label">Sent</span>
    </div>
    <div class="transfer-divider"></div>
    <div class="transfer-item">
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
        >
            <path d="M12 5v14M19 12l-7 7-7-7" />
        </svg>
        <span class="transfer-value">{formatBytes(status.bytes_received)}</span>
        <span class="transfer-label">Received</span>
    </div>
</div>

<style>
    /* IP Protection Banner */
    .ip-protection {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0.75rem 1rem;
        background: linear-gradient(
            135deg,
            rgba(0, 212, 170, 0.15) 0%,
            rgba(0, 184, 148, 0.1) 100%
        );
        border: 1px solid rgba(0, 212, 170, 0.3);
        border-radius: 12px;
        margin-bottom: 0.75rem;
    }

    .ip-badge {
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .ip-badge svg {
        width: 20px;
        height: 20px;
        color: #00d4aa;
    }

    .badge-text {
        font-size: 0.85rem;
        font-weight: 600;
        color: #00d4aa;
    }

    .ip-change {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.75rem;
    }

    .ip-old {
        color: #666;
        text-decoration: line-through;
    }

    .ip-change .arrow {
        width: 14px;
        height: 14px;
        color: #00d4aa;
    }

    .ip-new {
        color: #00d4aa;
        font-weight: 500;
    }

    /* Value Stats Grid */
    .value-stats {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 0.75rem;
        margin-bottom: 0.75rem;
    }

    .value-card {
        display: flex;
        flex-direction: column;
        align-items: center;
        padding: 0.75rem 0.5rem;
        background: rgba(255, 255, 255, 0.03);
        border-radius: 12px;
        gap: 0.5rem;
    }

    .value-icon {
        width: 32px;
        height: 32px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .value-icon svg {
        width: 18px;
        height: 18px;
    }

    .value-icon.latency {
        background: rgba(255, 193, 7, 0.15);
        color: #ffc107;
    }

    .value-icon.saved {
        background: rgba(0, 212, 170, 0.15);
        color: #00d4aa;
    }

    .value-icon.uptime {
        background: rgba(99, 102, 241, 0.15);
        color: #6366f1;
    }

    .value-content {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 0.125rem;
    }

    .value-number {
        font-size: 1rem;
        font-weight: 700;
        color: #e0e0e0;
    }

    .value-delta {
        font-size: 0.7rem;
        font-weight: 600;
        padding: 0.125rem 0.375rem;
        border-radius: 4px;
    }

    .value-delta.positive {
        background: rgba(0, 212, 170, 0.2);
        color: #00d4aa;
    }

    .value-delta.negative {
        background: rgba(255, 107, 107, 0.2);
        color: #ff6b6b;
    }

    .value-label {
        font-size: 0.65rem;
        color: #666;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    /* Transfer Stats */
    .transfer-stats {
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 0.75rem 1rem;
        background: rgba(255, 255, 255, 0.03);
        border-radius: 12px;
        gap: 1.5rem;
    }

    .transfer-item {
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .transfer-item svg {
        width: 14px;
        height: 14px;
        color: #00d4aa;
    }

    .transfer-value {
        font-size: 0.85rem;
        font-weight: 600;
        color: #e0e0e0;
    }

    .transfer-label {
        font-size: 0.7rem;
        color: #666;
        text-transform: uppercase;
    }

    .transfer-divider {
        width: 1px;
        height: 24px;
        background: #2a2a4a;
    }
</style>

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
</script>

<div
    class="stats"
    style="display: flex; flex-direction: row; flex-wrap: nowrap;"
>
    <div class="stat-item">
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
        >
            <path d="M12 2v20M2 12h20" />
        </svg>
        <div class="stat-info">
            <span class="stat-value">{formatUptime(status.uptime_secs)}</span>
            <span class="stat-label">Uptime</span>
        </div>
    </div>

    <div class="stat-item">
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
        >
            <path d="M12 19V5M5 12l7-7 7 7" />
        </svg>
        <div class="stat-info">
            <span class="stat-value">{formatBytes(status.bytes_sent)}</span>
            <span class="stat-label">Sent</span>
        </div>
    </div>

    <div class="stat-item">
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
        >
            <path d="M12 5v14M19 12l-7 7-7-7" />
        </svg>
        <div class="stat-info">
            <span class="stat-value">{formatBytes(status.bytes_received)}</span>
            <span class="stat-label">Received</span>
        </div>
    </div>
</div>

<style>
    .stats {
        display: flex;
        flex-direction: row !important;
        flex-wrap: nowrap;
        justify-content: space-around;
        align-items: center;
        gap: 1.5rem;
        padding: 1rem;
        background: rgba(0, 212, 170, 0.05);
        border-radius: 12px;
        margin-bottom: 0.5rem;
    }

    .stat-item {
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .stat-item svg {
        width: 16px;
        height: 16px;
        color: #00d4aa;
    }

    .stat-info {
        display: flex;
        flex-direction: column;
    }

    .stat-value {
        font-size: 0.9rem;
        font-weight: 600;
        color: #e0e0e0;
    }

    .stat-label {
        font-size: 0.65rem;
        color: #666;
        text-transform: uppercase;
    }
</style>

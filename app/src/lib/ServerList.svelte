<script lang="ts">
    import { invoke } from "@tauri-apps/api/core";

    interface Server {
        id: string;
        name: string;
        location: string;
        country_code: string;
        load: number;
        latency_ms: number | null;
    }

    interface Props {
        selected?: string | null;
        onselect?: (serverId: string) => void;
    }

    let { selected = null, onselect }: Props = $props();

    let servers = $state<Server[]>([]);
    let searchQuery = $state("");
    let liveLatency = $state<number | null>(null);
    let loading = $state(true);

    let filteredServers = $derived(
        servers.filter(
            (s) =>
                s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                s.location.toLowerCase().includes(searchQuery.toLowerCase()),
        ),
    );

    $effect(() => {
        let interval: ReturnType<typeof setInterval> | undefined;

        (async () => {
            loading = true;
            servers = await invoke("get_servers");
            loading = false;

            // Measure live latency immediately and then every 5 seconds
            const measureLatency = async () => {
                try {
                    liveLatency = await invoke("ping_relay");
                } catch (e) {
                    console.error("Failed to ping relay:", e);
                }
            };

            measureLatency();
            interval = setInterval(measureLatency, 5000);
        })();

        return () => {
            if (interval) clearInterval(interval);
        };
    });

    function selectServer(id: string) {
        onselect?.(id);
    }

    function getLoadColor(load: number): string {
        if (load < 40) return "#00d4aa";
        if (load < 70) return "#ffd93d";
        return "#ff6b6b";
    }

    function getLatencyColor(latency: number): string {
        if (latency < 80) return "#00d4aa";
        if (latency < 150) return "#ffd93d";
        return "#ff6b6b";
    }

    function getFlagEmoji(countryCode: string): string {
        const codePoints = countryCode
            .toUpperCase()
            .split("")
            .map((char) => 127397 + char.charCodeAt(0));
        return String.fromCodePoint(...codePoints);
    }
</script>

<div
    class="server-list"
    style="display: flex; flex-direction: column; gap: 1.5rem;"
>
    <div class="search-box" style="margin-bottom: 0.5rem;">
        <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
        >
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.35-4.35" />
        </svg>
        <input
            type="text"
            placeholder="Search servers..."
            bind:value={searchQuery}
        />
    </div>

    <div class="servers">
        {#if loading}
            {#each [1, 2, 3, 4, 5] as _}
                <div class="server-item skeleton-item">
                    <div class="skeleton skeleton-flag"></div>
                    <div class="server-info">
                        <div class="skeleton skeleton-name"></div>
                        <div class="skeleton skeleton-location"></div>
                    </div>
                    <div class="server-stats">
                        <div class="skeleton skeleton-latency"></div>
                        <div class="skeleton skeleton-bar"></div>
                    </div>
                </div>
            {/each}
        {:else if filteredServers.length === 0}
            <div class="empty-state">No servers found</div>
        {:else}
            {#each filteredServers as server}
            <button
                class="server-item"
                class:selected={selected === server.id}
                onclick={() => selectServer(server.id)}
            >
                <span class="flag">{getFlagEmoji(server.country_code)}</span>
                <div class="server-info">
                    <span class="name">{server.name}</span>
                    <span class="location">{server.location}</span>
                </div>
                <div class="server-stats">
                    {#if liveLatency !== null}
                        <span
                            class="latency"
                            style="color: {getLatencyColor(liveLatency)}"
                            >{liveLatency}ms</span
                        >
                    {/if}
                    <div class="load-bar">
                        <div
                            class="load-fill"
                            style="width: {liveLatency !== null
                                ? Math.min((liveLatency / 200) * 100, 100)
                                : server.load}%; background: {liveLatency !==
                            null
                                ? getLatencyColor(liveLatency)
                                : getLoadColor(server.load)}"
                        ></div>
                    </div>
                </div>
            </button>
            {/each}
        {/if}
    </div>
</div>

<style>
    .skeleton {
        background: linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.05) 25%,
            rgba(255, 255, 255, 0.1) 50%,
            rgba(255, 255, 255, 0.05) 75%
        );
        background-size: 200% 100%;
        animation: shimmer 1.5s infinite;
        border-radius: 4px;
    }

    @keyframes shimmer {
        0% { background-position: 200% 0; }
        100% { background-position: -200% 0; }
    }

    .skeleton-item {
        pointer-events: none;
    }

    .skeleton-flag {
        width: 32px;
        height: 24px;
        border-radius: 4px;
    }

    .skeleton-name {
        width: 100px;
        height: 14px;
        margin-bottom: 4px;
    }

    .skeleton-location {
        width: 70px;
        height: 10px;
    }

    .skeleton-latency {
        width: 35px;
        height: 10px;
    }

    .skeleton-bar {
        width: 50px;
        height: 4px;
    }

    .empty-state {
        text-align: center;
        color: #666;
        padding: 2rem;
        font-size: 0.9rem;
    }

    .server-list {
        display: flex;
        flex-direction: column;
        gap: 1.5rem;
    }

    .search-box {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        padding: 0.75rem 1rem;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        border: 1px solid #2a2a4a;
    }

    .search-box svg {
        width: 18px;
        height: 18px;
        color: #666;
    }

    .search-box input {
        flex: 1;
        background: transparent;
        border: none;
        color: #e0e0e0;
        font-size: 0.9rem;
        outline: none;
    }

    .search-box input::placeholder {
        color: #555;
    }

    .servers {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }

    .server-item {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        padding: 0.875rem 1rem;
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid transparent;
        border-radius: 12px;
        cursor: pointer;
        transition: all 0.2s;
        text-align: left;
        width: 100%;
    }

    .server-item:hover {
        background: rgba(255, 255, 255, 0.06);
        border-color: #2a2a4a;
    }

    .server-item.selected {
        background: rgba(0, 212, 170, 0.1);
        border-color: #00d4aa;
    }

    .flag {
        font-size: 1.5rem;
    }

    .server-info {
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 0.125rem;
    }

    .name {
        font-weight: 500;
        color: #e0e0e0;
        font-size: 0.9rem;
    }

    .location {
        font-size: 0.75rem;
        color: #666;
    }

    .server-stats {
        display: flex;
        flex-direction: column;
        align-items: flex-end;
        gap: 0.375rem;
    }

    .latency {
        font-size: 0.75rem;
        color: #888;
    }

    .load-bar {
        width: 50px;
        height: 4px;
        background: #2a2a4a;
        border-radius: 2px;
        overflow: hidden;
    }

    .load-fill {
        height: 100%;
        border-radius: 2px;
        transition: width 0.3s;
    }
</style>

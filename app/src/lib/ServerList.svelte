<script lang="ts">
    import { invoke } from "@tauri-apps/api/core";

    interface Region {
        id: string; // Region code (e.g., 'ord')
        name: string; // Region group (e.g., 'North America')
        location: string; // City (e.g., 'Chicago, Illinois')
        country_code: string; // ISO country code for flag
        status: string;
        latency_ms: number | null;
        load: number;
        server_count: number;
        server_ids: string[]; // Best server first
    }

    interface Props {
        selected?: string | null;
        onselect?: (
            regionId: string,
            serverId: string,
            regionLocation: string,
        ) => void;
    }

    let { selected = null, onselect }: Props = $props();

    let regions = $state<Region[]>([]);
    let searchQuery = $state("");
    let loading = $state(true);
    let loadError = $state<string | null>(null);

    let filteredRegions = $derived(
        regions.filter(
            (r) =>
                r.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                r.location.toLowerCase().includes(searchQuery.toLowerCase()),
        ),
    );

    $effect(() => {
        let interval: ReturnType<typeof setInterval> | undefined;
        let retryTimeout: ReturnType<typeof setTimeout> | undefined;
        let cancelled = false;

        async function loadRegions(retryCount = 0) {
            if (cancelled) return;

            try {
                loading = true;
                loadError = null;
                regions = await invoke("get_regions");
                loading = false;

                // Region latencies are already measured during get_regions call
            } catch (e) {
                console.error(
                    `Failed to load regions (attempt ${retryCount + 1}):`,
                    e,
                );

                if (cancelled) return;

                // Retry with exponential backoff (max 5 seconds)
                const delay = Math.min(1000 * Math.pow(1.5, retryCount), 5000);
                loadError = `Failed to load regions. Retrying...`;
                loading = false;

                retryTimeout = setTimeout(
                    () => loadRegions(retryCount + 1),
                    delay,
                );
            }
        }

        loadRegions();

        return () => {
            cancelled = true;
            if (interval) clearInterval(interval);
            if (retryTimeout) clearTimeout(retryTimeout);
        };
    });

    async function selectRegion(region: Region) {
        // Use round-robin to select next server in region
        try {
            const serverId: string = await invoke(
                "get_next_server_for_region",
                {
                    regionId: region.id,
                },
            );
            onselect?.(region.id, serverId, region.location);
        } catch (e) {
            console.error("Failed to get server for region:", e);
            // Fallback to first server
            onselect?.(region.id, region.server_ids[0], region.location);
        }
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
            placeholder="Search regions..."
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
        {:else if loadError}
            <div class="error-state">
                <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                >
                    <circle cx="12" cy="12" r="10" />
                    <path d="M12 8v4M12 16h.01" />
                </svg>
                <p>{loadError}</p>
            </div>
        {:else if filteredRegions.length === 0}
            <div class="empty-state">No regions found</div>
        {:else}
            {#each filteredRegions as region}
                <button
                    class="server-item"
                    class:selected={selected === region.id}
                    onclick={() => selectRegion(region)}
                >
                    <span class="flag">{getFlagEmoji(region.country_code)}</span
                    >
                    <div class="server-info">
                        <span class="name">{region.location}</span>
                        <span class="location"
                            >{region.name}{#if region.server_count > 1}
                                · {region.server_count} servers{/if}</span
                        >
                    </div>
                    <div class="server-stats">
                        {#if region.latency_ms !== null}
                            {@const displayLatency = region.latency_ms}
                            <span
                                class="latency"
                                style="color: {getLatencyColor(displayLatency)}"
                                >{displayLatency}ms</span
                            >
                            <div class="load-bar">
                                <div
                                    class="load-fill"
                                    style="width: {Math.min(
                                        (displayLatency / 200) * 100,
                                        100,
                                    )}%; background: {getLatencyColor(
                                        displayLatency,
                                    )}"
                                ></div>
                                <span class="load-value">{displayLatency}</span>
                            </div>
                        {:else}
                            <span class="latency" style="color: #666">--ms</span
                            >
                            <div class="load-bar">
                                <div
                                    class="load-fill"
                                    style="width: {region.load}%; background: {getLoadColor(
                                        region.load,
                                    )}"
                                ></div>
                            </div>
                        {/if}
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
        0% {
            background-position: 200% 0;
        }
        100% {
            background-position: -200% 0;
        }
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

    .error-state {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 0.75rem;
        text-align: center;
        color: #888;
        padding: 2rem;
    }

    .error-state svg {
        width: 32px;
        height: 32px;
        color: #ffd93d;
    }

    .error-state p {
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

    .load-bar {
        position: relative;
    }

    .load-value {
        display: none;
    }
</style>
